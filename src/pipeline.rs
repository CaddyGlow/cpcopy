//! Bounded read/write overlap for large, dense Windows files.
use std::{
    io::{self, Read, Write},
    sync::mpsc::sync_channel,
};

#[derive(Debug)]
pub(crate) enum Failure {
    Read(io::Error),
    Write(io::Error),
    Worker(io::Error),
}

/// Keep at most two buffers in flight; the caller owns both file handles until
/// the reader has joined. Errors retain their phase for path-specific reporting.
pub(crate) fn copy<R: Read + Send, W: Write>(
    input: &mut R,
    output: &mut W,
    buffer_size: usize,
) -> Result<u64, Failure> {
    std::thread::scope(|scope| {
        let (free_tx, free_rx) = sync_channel::<Vec<u8>>(2);
        let (ready_tx, ready_rx) = sync_channel::<io::Result<(Vec<u8>, usize)>>(2);
        for _ in 0..2 {
            free_tx
                .send(vec![0; buffer_size])
                .map_err(|_| Failure::Worker(io::Error::other("buffer channel closed")))?;
        }
        let reader = std::thread::Builder::new()
            .name("cpcopy-reader".into())
            .spawn_scoped(scope, move || {
                while let Ok(mut buffer) = free_rx.recv() {
                    let count = loop {
                        match input.read(&mut buffer) {
                            Ok(count) => break count,
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                            Err(error) => {
                                let _ = ready_tx.send(Err(error));
                                return;
                            }
                        }
                    };
                    if ready_tx.send(Ok((buffer, count))).is_err() || count == 0 {
                        return;
                    }
                }
            })
            .map_err(Failure::Worker)?;
        let result = (|| {
            let mut bytes = 0;
            loop {
                let (buffer, count) = ready_rx
                    .recv()
                    .map_err(|_| Failure::Worker(io::Error::other("reader stopped before EOF")))?
                    .map_err(Failure::Read)?;
                if count == 0 {
                    return Ok(bytes);
                }
                output.write_all(&buffer[..count]).map_err(Failure::Write)?;
                bytes += count as u64;
                // EOF may already be queued, with the reader no longer receiving.
                let _ = free_tx.send(buffer);
            }
        })();
        // A failed writer must release a reader blocked on either channel before
        // joining. Its original write error takes precedence over a worker error.
        drop(ready_rx);
        drop(free_tx);
        if reader.join().is_err() && result.is_ok() {
            return Err(Failure::Worker(io::Error::other("copy reader panicked")));
        }
        result
    })
}

#[cfg(test)]
mod tests {
    use super::{Failure, copy};
    use std::io::{self, Cursor, Read, Write};

    #[test]
    fn interrupted_and_short_reads_and_writes_preserve_the_odd_tail() {
        struct ShortReader {
            input: Cursor<Vec<u8>>,
            interrupted: bool,
        }
        impl Read for ShortReader {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                let length = buffer.len().min(17);
                self.input.read(&mut buffer[..length])
            }
        }
        struct ShortWriter(Vec<u8>);
        impl Write for ShortWriter {
            fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
                let length = buffer.len().min(7);
                self.0.extend_from_slice(&buffer[..length]);
                Ok(length)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let expected: Vec<u8> = (0..12345).map(|i| (i % 251) as u8).collect();
        let mut input = ShortReader {
            input: Cursor::new(expected.clone()),
            interrupted: false,
        };
        let mut output = ShortWriter(Vec::new());
        assert_eq!(
            copy(&mut input, &mut output, 4096).unwrap(),
            expected.len() as u64
        );
        assert_eq!(output.0, expected);
    }

    struct FailingReader(Cursor<Vec<u8>>);
    impl Read for FailingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.0.position() == self.0.get_ref().len() as u64 {
                Err(io::Error::from_raw_os_error(5))
            } else {
                self.0.read(buffer)
            }
        }
    }

    #[test]
    fn reader_failure_retains_the_written_prefix_and_native_error() {
        let prefix = vec![3; 4099];
        let mut output = Vec::new();
        let error = copy(
            &mut FailingReader(Cursor::new(prefix.clone())),
            &mut output,
            4096,
        )
        .unwrap_err();
        assert!(matches!(error, Failure::Read(error) if error.raw_os_error() == Some(5)));
        assert_eq!(output, prefix);
    }

    struct FailingWriter;
    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from_raw_os_error(112))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn writer_failure_unblocks_a_reader_with_more_than_two_buffers() {
        let error = copy(
            &mut Cursor::new(vec![1; 1024 * 1024]),
            &mut FailingWriter,
            4096,
        )
        .unwrap_err();
        assert!(matches!(error, Failure::Write(error) if error.raw_os_error() == Some(112)));
    }

    #[test]
    fn writer_failure_takes_precedence_over_a_queued_reader_failure() {
        let error = copy(
            &mut FailingReader(Cursor::new(vec![1; 4096])),
            &mut FailingWriter,
            4096,
        )
        .unwrap_err();
        assert!(matches!(error, Failure::Write(error) if error.raw_os_error() == Some(112)));
    }

    #[test]
    fn zero_byte_write_is_an_error() {
        struct ZeroWriter;
        impl Write for ZeroWriter {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Ok(0)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let error = copy(&mut Cursor::new([1]), &mut ZeroWriter, 4096);
        assert!(
            matches!(error, Err(Failure::Write(error)) if error.kind() == io::ErrorKind::WriteZero)
        );
    }

    #[test]
    fn empty_input_does_not_write() {
        assert_eq!(
            copy(&mut Cursor::new([]), &mut FailingWriter, 4096).unwrap(),
            0
        );
    }

    #[test]
    fn reader_panic_is_reported_without_panicking_the_caller() {
        struct PanickingReader;
        impl Read for PanickingReader {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                panic!("injected reader panic");
            }
        }
        let error = copy(&mut PanickingReader, &mut Vec::new(), 4096).unwrap_err();
        assert!(matches!(error, Failure::Worker(error) if error.kind() == io::ErrorKind::Other));
    }
}
