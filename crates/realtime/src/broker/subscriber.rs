use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubscriberId(pub(crate) u64);

pub trait Subscriber: Send + Sync {
    fn send(&self, payload: Arc<[u8]>) -> bool;
    fn exclude_id(&self) -> &str;
    fn mailbox_id(&self) -> &str;
    fn is_closed(&self) -> bool;
}
