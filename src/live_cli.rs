//! Low-frequency terminal rendering, outside transfer workers.
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle, TermLike};
use std::{
    io::{IsTerminal, Write},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub(super) struct Reporter {
    stop: mpsc::Sender<bool>,
    thread: JoinHandle<()>,
    finished: mpsc::Receiver<()>,
}

impl Reporter {
    pub(super) fn start(
        progress: crate::LiveProgress,
        total: Option<u64>,
    ) -> std::io::Result<Self> {
        // A private handle avoids holding Rust's shared stderr lock during a
        // blocked write, which would otherwise stall copy diagnostics too.
        let mut output = progress_output()?;
        let terminal = std::io::stderr().is_terminal();
        let failed_output = Arc::new(AtomicBool::new(false));
        let bar = if terminal {
            let target = ProgressDrawTarget::term_like_with_hz(
                Box::new(ProgressTerminal {
                    output: Mutex::new(output.try_clone()?),
                    failed: Arc::clone(&failed_output),
                }),
                5,
            );
            Some(
                ProgressBar::with_draw_target(total, target)
                    .with_style(progress_style(total.is_some())?),
            )
        } else {
            None
        };
        let (stop, receiver) = mpsc::channel();
        let (finished_sender, finished) = mpsc::channel();
        let started = Instant::now();
        let unknown_style = progress_style(false)?;
        let thread = thread::Builder::new()
            .name("cpcopy-progress".into())
            .spawn(move || {
                loop {
                    let status = match receiver.recv_timeout(Duration::from_millis(200)) {
                        Ok(failed) => Some(if failed { "failed" } else { "finished" }),
                        Err(mpsc::RecvTimeoutError::Timeout) => None,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    };
                    let snapshot = progress.snapshot();
                    let elapsed = started.elapsed();
                    if let Some(bar) = &bar {
                        if bar.length().is_some_and(|length| snapshot.bytes > length) {
                            bar.unset_length();
                            // Templates were validated before the reporter started.
                            bar.set_style(unknown_style.clone());
                        }
                        bar.set_prefix(status.unwrap_or("copying"));
                        bar.set_message(format_details(snapshot, total, elapsed));
                        bar.set_position(snapshot.bytes);
                        if status.is_some() {
                            // Abandon preserves partial progress on failure or shrinkage.
                            bar.abandon();
                        }
                        if failed_output.load(Ordering::Relaxed) || status.is_some() {
                            break;
                        }
                    } else {
                        let line = format_progress(snapshot, total, elapsed, status);
                        if writeln!(output, "{line}")
                            .and_then(|()| output.flush())
                            .is_err()
                            || status.is_some()
                        {
                            break;
                        }
                    }
                }
                let _ = finished_sender.send(());
            })?;
        Ok(Self {
            stop,
            thread,
            finished,
        })
    }

    pub(super) fn finish(self, failed: bool) {
        let _ = self.stop.send(failed);
        // Give normal output time to render the final snapshot. A stalled
        // consumer must not keep the CLI alive: dropping JoinHandle detaches
        // that reporter, which owns only its output handle and counters.
        if self
            .finished
            .recv_timeout(Duration::from_millis(100))
            .is_ok()
        {
            let _ = self.thread.join();
        }
    }
}

#[cfg(unix)]
fn progress_output() -> std::io::Result<std::fs::File> {
    use std::os::fd::BorrowedFd;
    // SAFETY: Borrow only the process stderr descriptor, then duplicate it;
    // the reporter never owns or closes the original descriptor.
    let stderr = unsafe { BorrowedFd::borrow_raw(libc::STDERR_FILENO) };
    stderr.try_clone_to_owned().map(std::fs::File::from)
}

#[cfg(windows)]
fn progress_output() -> std::io::Result<std::fs::File> {
    use std::os::windows::io::BorrowedHandle;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetStdHandle(kind: u32) -> *mut std::ffi::c_void;
    }
    // SAFETY: STD_ERROR_HANDLE requests the process-owned stderr handle.
    let handle = unsafe { GetStdHandle(-12_i32 as u32) };
    if handle.is_null() || handle as isize == -1 {
        return Err(std::io::Error::other("stderr handle unavailable"));
    }
    // SAFETY: Borrow a valid process-owned handle only while duplicating it.
    let stderr = unsafe { BorrowedHandle::borrow_raw(handle) };
    stderr.try_clone_to_owned().map(std::fs::File::from)
}

#[cfg(not(any(unix, windows)))]
fn progress_output() -> std::io::Result<std::fs::File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "live progress output is unsupported on this platform",
    ))
}

pub(super) fn single_file_total(
    copies: &[(PathBuf, PathBuf)],
    options: &crate::CopyOptions,
) -> Option<u64> {
    if copies.len() != 1 || options.hard_link || options.symbolic_link || options.attributes_only {
        return None;
    }
    let source = &copies[0].0;
    let metadata = if options.dereference == crate::Dereference::Never {
        std::fs::symlink_metadata(source)
    } else {
        std::fs::metadata(source)
    }
    .ok()?;
    metadata.is_file().then_some(metadata.len())
}

fn progress_style(known: bool) -> std::io::Result<ProgressStyle> {
    ProgressStyle::with_template(if known {
        "{prefix}: [{bar:20}] {percent:>3}% {msg}"
    } else {
        "{prefix}: {spinner} {msg}"
    })
    .map(|style| style.progress_chars("=> "))
    .map_err(std::io::Error::other)
}

fn format_details(
    snapshot: crate::LiveProgressSnapshot,
    total: Option<u64>,
    elapsed: Duration,
) -> String {
    let rate = if elapsed.is_zero() {
        0.0
    } else {
        snapshot.bytes as f64 / elapsed.as_secs_f64()
    };
    let eta = match total.filter(|total| snapshot.bytes <= *total) {
        Some(total) if total == snapshot.bytes => "0s".into(),
        Some(total) if rate > 0.0 => {
            format!("{:.0}s", ((total - snapshot.bytes) as f64 / rate).ceil())
        }
        _ => "unknown".into(),
    };
    format!(
        "ETA {eta} | {:.1} MiB | {:.1} MiB/s | {:.1}s | {} entries",
        snapshot.bytes as f64 / 1048576.0,
        rate / 1048576.0,
        elapsed.as_secs_f64(),
        snapshot.completed,
    )
}

// Plain output deliberately avoids terminal controls when stderr is redirected.
fn format_progress(
    snapshot: crate::LiveProgressSnapshot,
    total: Option<u64>,
    elapsed: Duration,
    status: Option<&str>,
) -> String {
    let percentage = match total.filter(|total| snapshot.bytes <= *total) {
        Some(total) => format!(
            "{:.1}% ",
            if total == 0 {
                100.0
            } else {
                snapshot.bytes as f64 / total as f64 * 100.0
            }
        ),
        None => String::new(),
    };
    format!(
        "{}: {percentage}{}",
        status.unwrap_or("copying"),
        format_details(snapshot, total, elapsed)
    )
}

/// Adapt the private output handle to indicatif without its default stderr lock.
#[derive(Debug)]
struct ProgressTerminal {
    output: Mutex<std::fs::File>,
    failed: Arc<AtomicBool>,
}
impl ProgressTerminal {
    fn write(&self, text: std::fmt::Arguments<'_>) -> std::io::Result<()> {
        let result = self
            .output
            .lock()
            .map_err(|_| std::io::Error::other("progress output lock poisoned"))
            .and_then(|mut output| output.write_fmt(text));
        if result.is_err() {
            self.failed.store(true, Ordering::Relaxed);
        }
        result
    }
}
impl TermLike for ProgressTerminal {
    fn width(&self) -> u16 {
        console::Term::stderr().size().1
    }
    fn height(&self) -> u16 {
        console::Term::stderr().size().0
    }
    fn move_cursor_up(&self, n: usize) -> std::io::Result<()> {
        if n == 0 {
            return Ok(());
        }
        self.write(format_args!("\x1b[{n}A"))
    }
    fn move_cursor_down(&self, n: usize) -> std::io::Result<()> {
        if n == 0 {
            return Ok(());
        }
        self.write(format_args!("\x1b[{n}B"))
    }
    fn move_cursor_right(&self, n: usize) -> std::io::Result<()> {
        if n == 0 {
            return Ok(());
        }
        self.write(format_args!("\x1b[{n}C"))
    }
    fn move_cursor_left(&self, n: usize) -> std::io::Result<()> {
        if n == 0 {
            return Ok(());
        }
        self.write(format_args!("\x1b[{n}D"))
    }
    fn write_line(&self, s: &str) -> std::io::Result<()> {
        self.write(format_args!("{s}\n"))
    }
    fn write_str(&self, s: &str) -> std::io::Result<()> {
        self.write(format_args!("{s}"))
    }
    fn clear_line(&self) -> std::io::Result<()> {
        self.write(format_args!("\r\x1b[2K"))
    }
    // File is unbuffered; every write has already reached the OS.
    fn flush(&self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indicatif_failure_preserves_partial_bar_and_private_output() {
        let output = tempfile::NamedTempFile::new().unwrap();
        let failed = Arc::new(AtomicBool::new(false));
        let target = ProgressDrawTarget::term_like_with_hz(
            Box::new(ProgressTerminal {
                output: Mutex::new(output.reopen().unwrap()),
                failed: Arc::clone(&failed),
            }),
            5,
        );
        let bar = ProgressBar::with_draw_target(Some(100), target)
            .with_style(progress_style(true).unwrap());
        bar.set_prefix("failed");
        bar.set_message("ETA unknown");
        bar.set_position(25);
        bar.abandon();
        let rendered = std::fs::read_to_string(output.path()).unwrap();
        assert!(
            rendered.contains("failed:") && rendered.contains("25%"),
            "{rendered:?}"
        );
        assert!(!rendered.contains("100%"), "{rendered:?}");
        assert!(!failed.load(Ordering::Relaxed));
    }

    #[test]
    fn total_is_known_only_for_one_regular_data_copy() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        std::fs::write(&source, b"payload").unwrap();
        let copies = vec![(source, directory.path().join("destination"))];
        let mut options = crate::CopyOptions::default();
        assert_eq!(single_file_total(&copies, &options), Some(7));
        options.attributes_only = true;
        assert_eq!(single_file_total(&copies, &options), None);
        assert_eq!(
            single_file_total(
                &[copies[0].clone(), copies[0].clone()],
                &crate::CopyOptions::default()
            ),
            None
        );
        assert_eq!(
            single_file_total(
                &[(directory.path().to_owned(), directory.path().join("tree"))],
                &crate::CopyOptions::default()
            ),
            None
        );
    }

    #[test]
    fn redirected_partial_file_has_percentage_and_estimated_remaining_time() {
        let rendered = format_progress(
            crate::LiveProgressSnapshot {
                bytes: 1048576,
                completed: 0,
            },
            Some(4194304),
            Duration::from_secs(2),
            None,
        );
        assert!(rendered.contains("25.0% ETA 6s"), "{rendered}");
        assert!(rendered.contains("0.5 MiB/s"), "{rendered}");
    }

    #[test]
    fn unknown_total_and_zero_rate_do_not_invent_eta() {
        let snapshot = crate::LiveProgressSnapshot {
            bytes: 0,
            completed: 0,
        };
        assert!(format_progress(snapshot, None, Duration::ZERO, None).contains("ETA unknown"));
        assert!(format_progress(snapshot, Some(100), Duration::ZERO, None).contains("ETA unknown"));
    }

    #[test]
    fn source_growth_discards_stale_percentage_and_eta() {
        let snapshot = crate::LiveProgressSnapshot {
            bytes: 101,
            completed: 1,
        };
        let rendered = format_progress(
            snapshot,
            Some(100),
            Duration::from_secs(1),
            Some("finished"),
        );
        assert!(rendered.contains("ETA unknown") && !rendered.contains('%'));
    }
}
