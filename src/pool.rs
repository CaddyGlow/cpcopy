//! Bounded scoped workers with ordered results and caller-thread consumption.
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::sync_channel,
    },
};

#[derive(Debug)]
pub(crate) enum PoolError<E> {
    InvalidWorkers,
    Spawn(std::io::Error),
    WorkerPanic,
    Disconnected,
    Cancelled,
    Consumer(E),
}

impl<E: std::fmt::Display> std::fmt::Display for PoolError<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidWorkers => formatter.write_str("worker count must be between 1 and 64"),
            Self::Spawn(error) => write!(formatter, "cannot start copy worker: {error}"),
            Self::WorkerPanic => formatter.write_str("copy worker panicked"),
            Self::Disconnected => formatter.write_str("copy worker disconnected"),
            Self::Cancelled => formatter.write_str("copy cancelled"),
            Self::Consumer(error) => error.fmt(formatter),
        }
    }
}
impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for PoolError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Self::Spawn(error) = self {
            Some(error)
        } else {
            None
        }
    }
}

/// Admit at most twice `workers` jobs, retaining input order for consumption.
/// Job failures are ordinary result values; the consumer chooses their policy.
/// On cancellation/error all channel ends are dropped before scoped workers join.
pub(crate) fn run<I, J, R, W, C, E>(
    jobs: I,
    workers: usize,
    cancellation: &AtomicBool,
    work: W,
    mut consume: C,
) -> Result<(), PoolError<E>>
where
    I: IntoIterator<Item = J>,
    J: Send,
    R: Send,
    W: Fn(J) -> R + Sync,
    C: FnMut(R) -> Result<(), E>,
{
    let capacity = workers
        .checked_mul(2)
        .filter(|value| *value > 0 && workers <= 64)
        .ok_or(PoolError::InvalidWorkers)?;
    if cancellation.load(Ordering::Acquire) {
        return Err(PoolError::Cancelled);
    }
    std::thread::scope(|scope| {
        let (job_tx, job_rx) = sync_channel::<(usize, J)>(capacity);
        let (result_tx, result_rx) = sync_channel::<(usize, Result<R, ()>)>(capacity);
        let job_rx = Arc::new(Mutex::new(job_rx));
        let mut spawn_error = None;
        for _ in 0..workers {
            let job_rx = Arc::clone(&job_rx);
            let result_tx = result_tx.clone();
            let work = &work;
            if let Err(error) = std::thread::Builder::new().spawn_scoped(scope, move || {
                loop {
                    if cancellation.load(Ordering::Acquire) {
                        break;
                    }
                    let job = match job_rx.lock() {
                        Ok(receiver) => receiver.recv(),
                        Err(_) => break,
                    };
                    let Ok((index, job)) = job else {
                        break;
                    };
                    if cancellation.load(Ordering::Acquire) {
                        break;
                    }
                    let result =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(job)))
                            .map_err(|_| ());
                    if result_tx.send((index, result)).is_err() {
                        break;
                    }
                }
            }) {
                spawn_error = Some(error);
                break;
            }
        }
        drop(result_tx);
        let result = if let Some(error) = spawn_error {
            Err(PoolError::Spawn(error))
        } else {
            let mut jobs = jobs.into_iter();
            let mut dispatched = 0_usize;
            let mut delivered = 0_usize;
            let mut exhausted = false;
            let mut pending = BTreeMap::new();
            (|| {
                loop {
                    if cancellation.load(Ordering::Acquire) {
                        return Err(PoolError::Cancelled);
                    }
                    while !exhausted && dispatched - delivered < capacity {
                        if cancellation.load(Ordering::Acquire) {
                            return Err(PoolError::Cancelled);
                        }
                        let Some(job) = jobs.next() else {
                            exhausted = true;
                            break;
                        };
                        job_tx
                            .send((dispatched, job))
                            .map_err(|_| PoolError::Disconnected)?;
                        dispatched += 1;
                    }
                    if delivered == dispatched {
                        return Ok(());
                    }
                    let (index, result) = result_rx.recv().map_err(|_| {
                        if cancellation.load(Ordering::Acquire) {
                            PoolError::Cancelled
                        } else {
                            PoolError::Disconnected
                        }
                    })?;
                    pending.insert(index, result);
                    while let Some(result) = pending.remove(&delivered) {
                        if cancellation.load(Ordering::Acquire) {
                            return Err(PoolError::Cancelled);
                        }
                        let value = result.map_err(|_| PoolError::WorkerPanic)?;
                        consume(value).map_err(PoolError::Consumer)?;
                        delivered += 1;
                    }
                }
            })()
        };
        if result.is_err() {
            cancellation.store(true, Ordering::Release);
        }
        // Workers blocked on either channel must be released before scope joins.
        drop(job_tx);
        drop(result_rx);
        result
    })
}

#[cfg(test)]
mod tests {
    use super::{PoolError, run};
    use std::{
        cell::RefCell,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread,
    };

    #[test]
    fn callbacks_remain_on_caller_and_results_follow_input_order() {
        let caller = thread::current().id();
        let values = RefCell::new(Vec::new());
        run(
            0..100,
            4,
            &AtomicBool::new(false),
            |index| {
                if index % 3 == 0 {
                    thread::yield_now();
                }
                index
            },
            |value| {
                assert_eq!(thread::current().id(), caller);
                values.borrow_mut().push(value);
                Ok::<_, ()>(())
            },
        )
        .unwrap();
        assert_eq!(values.into_inner(), (0..100).collect::<Vec<_>>());
    }

    #[test]
    fn admission_and_active_work_stay_bounded_and_workers_are_reused() {
        let admitted = AtomicUsize::new(0);
        let consumed = AtomicUsize::new(0);
        let active = AtomicUsize::new(0);
        let threads = std::sync::Mutex::new(std::collections::HashSet::new());
        let jobs = (0..200).inspect(|_| {
            let count = admitted.fetch_add(1, Ordering::SeqCst) + 1;
            assert!(count - consumed.load(Ordering::SeqCst) <= 6);
        });
        run(
            jobs,
            3,
            &AtomicBool::new(false),
            |_| {
                assert!(active.fetch_add(1, Ordering::SeqCst) < 3);
                threads.lock().unwrap().insert(thread::current().id());
                thread::yield_now();
                active.fetch_sub(1, Ordering::SeqCst);
            },
            |_| {
                consumed.fetch_add(1, Ordering::SeqCst);
                Ok::<_, ()>(())
            },
        )
        .unwrap();
        assert!(threads.lock().unwrap().len() <= 3);
        assert_eq!(consumed.load(Ordering::SeqCst), 200);
    }

    #[test]
    fn consumer_failure_cancels_joins_and_stops_admission() {
        let admitted = AtomicUsize::new(0);
        let completed = Arc::new(AtomicUsize::new(0));
        let cancellation = AtomicBool::new(false);
        let result = run(
            (0..10_000).inspect(|_| {
                admitted.fetch_add(1, Ordering::SeqCst);
            }),
            4,
            &cancellation,
            |_| {
                completed.fetch_add(1, Ordering::SeqCst);
            },
            |_| Err("stop"),
        );
        assert!(matches!(result, Err(PoolError::Consumer("stop"))));
        assert!(cancellation.load(Ordering::Acquire));
        assert!(admitted.load(Ordering::SeqCst) <= 8);
        let final_count = completed.load(Ordering::SeqCst);
        thread::yield_now();
        assert_eq!(completed.load(Ordering::SeqCst), final_count);
    }

    #[test]
    fn worker_panic_cancels_without_waiting_for_a_missing_result() {
        let result = run(
            0..100,
            3,
            &AtomicBool::new(false),
            |index| {
                assert_ne!(index, 2, "injected worker panic");
                index
            },
            |_| Ok::<_, ()>(()),
        );
        assert!(matches!(result, Err(PoolError::WorkerPanic)));
    }

    #[test]
    fn job_errors_are_delivered_and_do_not_stop_other_jobs() {
        let mut results = Vec::new();
        run(
            0..4,
            2,
            &AtomicBool::new(false),
            |index| if index == 1 { Err(index) } else { Ok(index) },
            |result| {
                results.push(result);
                Ok::<_, ()>(())
            },
        )
        .unwrap();
        assert_eq!(results, [Ok(0), Err(1), Ok(2), Ok(3)]);
    }

    #[test]
    fn external_cancellation_stops_without_consuming_more_results() {
        let cancelled = AtomicBool::new(false);
        let mut callbacks = 0;
        let result = run(
            0..100,
            2,
            &cancelled,
            |index| {
                if index == 0 {
                    cancelled.store(true, Ordering::Release);
                }
                index
            },
            |_| {
                callbacks += 1;
                Ok::<_, ()>(())
            },
        );
        assert!(matches!(result, Err(PoolError::Cancelled)));
        assert_eq!(callbacks, 0);
    }

    #[test]
    fn all_workers_exiting_for_external_cancel_reports_cancellation() {
        for _ in 0..100 {
            let cancelled = AtomicBool::new(false);
            let jobs = (0..100).inspect(|index| {
                if *index == 1 {
                    cancelled.store(true, Ordering::Release);
                }
            });
            let result = run(jobs, 2, &cancelled, |value| value, |_| Ok::<_, ()>(()));
            assert!(matches!(result, Err(PoolError::Cancelled)));
        }
    }

    #[test]
    fn empty_iterator_succeeds_and_invalid_worker_count_is_rejected() {
        run(
            std::iter::empty::<()>(),
            2,
            &AtomicBool::new(false),
            |_| (),
            |_| Ok::<_, ()>(()),
        )
        .unwrap();
        let result = run(
            [()],
            0,
            &AtomicBool::new(false),
            |_| (),
            |_| Ok::<_, ()>(()),
        );
        assert!(matches!(result, Err(PoolError::InvalidWorkers)));
        let result = run(
            [()],
            65,
            &AtomicBool::new(false),
            |_| (),
            |_| Ok::<_, ()>(()),
        );
        assert!(matches!(result, Err(PoolError::InvalidWorkers)));
    }
}
