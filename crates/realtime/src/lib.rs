#![forbid(unsafe_code)]

use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;

pub struct RealtimeRuntime;

impl RealtimeRuntime {
    pub fn spawn_housekeeping(mut shutdown: watch::Receiver<bool>) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
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
