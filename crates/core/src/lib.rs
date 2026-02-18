#![forbid(unsafe_code)]

use std::fmt::{Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpaceId(pub uuid::Uuid);

impl SpaceId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

impl Display for SpaceId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for SpaceId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(uuid::Uuid::parse_str(s)?))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("invalid identifier")]
    InvalidIdentifier,
}
