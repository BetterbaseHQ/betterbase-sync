#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum BrokerError {
    #[error("too many connections")]
    TooManyConnections,
    #[error("subscriber not found")]
    SubscriberNotFound,
}
