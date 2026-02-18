#![forbid(unsafe_code)]

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Permission {
    Read = 1,
    Write = 2,
    Admin = 3,
}

impl Permission {
    #[must_use]
    pub fn as_cmd(self) -> &'static str {
        match self {
            Self::Read => "/space/read",
            Self::Write => "/space/write",
            Self::Admin => "/space/admin",
        }
    }

    #[must_use]
    pub fn attenuates(self, child: Self) -> bool {
        self >= child
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_cmd())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParsePermissionError {
    #[error("unknown command {0:?}")]
    UnknownCommand(String),
    #[error("unknown permission value {0}")]
    UnknownValue(u8),
}

impl TryFrom<u8> for Permission {
    type Error = ParsePermissionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Read),
            2 => Ok(Self::Write),
            3 => Ok(Self::Admin),
            _ => Err(ParsePermissionError::UnknownValue(value)),
        }
    }
}

pub fn parse_permission(cmd: &str) -> Result<Permission, ParsePermissionError> {
    match cmd {
        "/space/read" => Ok(Permission::Read),
        "/space/write" => Ok(Permission::Write),
        "/space/admin" => Ok(Permission::Admin),
        _ => Err(ParsePermissionError::UnknownCommand(cmd.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_permission, Permission};

    #[test]
    fn parse_permission_known_commands() {
        assert_eq!(
            parse_permission("/space/read").expect("read"),
            Permission::Read
        );
        assert_eq!(
            parse_permission("/space/write").expect("write"),
            Permission::Write
        );
        assert_eq!(
            parse_permission("/space/admin").expect("admin"),
            Permission::Admin
        );
    }

    #[test]
    fn parse_permission_unknown_command() {
        assert!(parse_permission("/space/nope").is_err());
    }

    #[test]
    fn permission_attenuation() {
        assert!(Permission::Admin.attenuates(Permission::Write));
        assert!(Permission::Write.attenuates(Permission::Read));
        assert!(!Permission::Read.attenuates(Permission::Write));
    }
}
