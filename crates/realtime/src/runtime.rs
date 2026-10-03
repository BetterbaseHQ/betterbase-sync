use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;

pub struct RealtimeRuntime;

impl RealtimeRuntime {
    pub fn spawn_housekeeping(mut shutdown: watch::Receiver<bool>) -> JoinHandle<()> {
        tokio::spawn(async move {
            while !*shutdown.borrow_and_update() {
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {}
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn housekeeping_stops_on_shutdown_or_channel_close() {
        for explicit_shutdown in [false, true] {
            let (tx, rx) = watch::channel(false);
            let worker = RealtimeRuntime::spawn_housekeeping(rx);
            if explicit_shutdown {
                tx.send(true).expect("shutdown");
            }
            drop(tx);
            tokio::time::timeout(Duration::from_secs(1), worker)
                .await
                .expect("shutdown deadline")
                .expect("worker");
        }
    }
    #[tokio::test(start_paused = true)]
    async fn housekeeping_handles_timer_ticks_and_false_updates() {
        let (tx, rx) = watch::channel(false);
        let worker = RealtimeRuntime::spawn_housekeeping(rx);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(30)).await;
        tokio::task::yield_now().await;
        assert!(!worker.is_finished());
        tx.send(false).unwrap();
        tokio::task::yield_now().await;
        assert!(!worker.is_finished());
        tx.send(true).unwrap();
        worker.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn housekeeping_respects_an_already_requested_shutdown() {
        let (_tx, rx) = watch::channel(true);
        let worker = RealtimeRuntime::spawn_housekeeping(rx);
        tokio::task::yield_now().await;
        assert!(
            worker.is_finished(),
            "a shutdown that predates spawning must not be lost"
        );
        worker.await.unwrap();
    }
}
