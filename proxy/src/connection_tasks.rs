//! Tasks belonging to one accepted transport, including adopted upgrades.
//! Only the accepted-client supervisor drains this set. Registration remains
//! possible during cancellation: late work is never invoked, and its captured
//! values remain in tracked tasks until joined. No mutex guard crosses an await.

use std::{
    future::{Future, poll_fn},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    sync::{oneshot, watch},
    task::{AbortHandle, JoinSet},
};

pub(crate) struct ConnectionTasks {
    inner: Mutex<Inner>,
    pub(crate) stop: watch::Receiver<bool>,
}
struct Inner {
    tasks: JoinSet<()>,
    closing: bool,
}

/// A concrete result/abort handle; the actual task stays in the connection set.
/// Dropping a body or relay owner requests cancellation without detaching work.
pub(crate) struct Task<T> {
    result: oneshot::Receiver<T>,
    abort: AbortHandle,
}
impl<T> Task<T> {
    pub(crate) fn abort(&self) {
        self.abort.abort();
    }
}
impl<T> Future for Task<T> {
    type Output = Result<T, oneshot::error::RecvError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.result).poll(cx)
    }
}
impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        self.abort();
    }
}

impl ConnectionTasks {
    pub(crate) fn new(stop: watch::Receiver<bool>) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                tasks: JoinSet::new(),
                closing: false,
            }),
            stop,
        })
    }
    pub(crate) fn spawn(&self, future: impl Future<Output = ()> + Send + 'static) -> AbortHandle {
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        let closing = inner.closing;
        let task = inner.tasks.spawn(async move {
            // A spawned task can run on another worker before abort(). Never
            // poll user work registered after closure, even in that interval.
            if !closing {
                future.await;
            }
        });
        if closing {
            task.abort();
        }
        task
    }
    pub(crate) fn spawn_upgrade(
        self: &Arc<Self>,
        future: impl Future<Output = Result<(), crate::Error>> + Send + 'static,
    ) {
        let mut cleanup = FailedUpgrade(Some(self.clone()));
        self.spawn(async move {
            if future.await.is_ok() {
                cleanup.disarm();
            }
        });
    }
    pub(crate) fn spawn_result<T: Send + 'static>(
        &self,
        future: impl Future<Output = T> + Send + 'static,
    ) -> Task<T> {
        let (send, result) = oneshot::channel();
        let abort = self.spawn(async move {
            let output = future.await;
            let _ = send.send(output);
        });
        Task { result, abort }
    }
    pub(crate) fn spawn_blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Task<T> {
        let (send, result) = oneshot::channel();
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        let closing = inner.closing;
        let abort = inner.tasks.spawn_blocking(move || {
            // Blocking jobs may start before abort(), and cannot then be
            // canceled. Check the registration state before calling the job.
            if !closing {
                let output = work();
                let _ = send.send(output);
            }
        });
        if closing {
            abort.abort();
        }
        Task { result, abort }
    }
    pub(crate) fn abort_all(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        inner.closing = true;
        inner.tasks.abort_all();
    }
    async fn join_next(&self) -> Option<Result<(), tokio::task::JoinError>> {
        poll_fn(|cx| {
            self.inner
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .tasks
                .poll_join_next(cx)
        })
        .await
    }
    /// The caller retains the client lifetime outside this supervisor. A main
    /// driver panic/error cancels descendants; an ordinary 101/CONNECT driver
    /// completion leaves adopted streams alive. Only this method joins tasks.
    pub(crate) async fn run(
        self: &Arc<Self>,
        main: impl Future<Output = Result<(), crate::Error>> + Send + 'static,
    ) {
        let mut main = self.spawn_result(main);
        let mut main_pending = true;
        let mut stop = self.stop.clone();
        let mut stopping = *stop.borrow();
        let deadline = tokio::time::sleep(Duration::from_secs(10));
        tokio::pin!(deadline);
        let mut forced = false;
        loop {
            tokio::select! {
                biased;
                result = &mut main, if main_pending => {
                    main_pending = false;
                    if !matches!(result, Ok(Ok(()))) { self.abort_all(); }
                },
                _ = stop.changed(), if !stopping => {
                    stopping = true;
                    deadline.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(10));
                },
                _ = &mut deadline, if stopping && !forced => {
                    forced = true;
                    self.abort_all();
                },
                task = self.join_next() => {
                    if task.is_none() && !main_pending { break; }
                }
            }
        }
        // Running blocking work cannot be aborted. The final join above waits
        // for its return, even when that exceeds the existing transport grace.
    }
}

// This guard belongs only to the CONNECT producer. Ordinary transfer of the
// socket disarms it; failure, panic, or cancellation stops its descendants.
struct FailedUpgrade(Option<Arc<ConnectionTasks>>);
impl FailedUpgrade {
    fn disarm(&mut self) {
        self.0 = None;
    }
}
impl Drop for FailedUpgrade {
    fn drop(&mut self) {
        if let Some(tasks) = &self.0 {
            tasks.abort_all();
        }
    }
}

/// Hyper's H2 service/body jobs use the same owner as explicit HTTP drivers.
#[derive(Clone)]
pub(crate) struct Executor(pub(crate) Arc<ConnectionTasks>);
impl<F> hyper::rt::Executor<F> for Executor
where
    F: Future + Send + 'static,
    F::Output: Send,
{
    fn execute(&self, future: F) {
        self.0.spawn(async move {
            let _ = future.await;
        });
    }
}

#[cfg(test)]
mod tests;
