#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrokerConfig {
    pub max_connections_per_mailbox: usize,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            max_connections_per_mailbox: 3,
        }
    }
}
