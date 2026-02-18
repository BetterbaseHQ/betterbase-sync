use thiserror::Error;
use uuid::Uuid;

pub const DEFAULT_MAX_BLOB_SIZE: i64 = 5 * 1024 * 1024;
pub const DEFAULT_MAX_FILE_SIZE: i64 = 100 * 1024 * 1024;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    #[error("invalid record ID: must be valid UUID format")]
    InvalidRecordId,
    #[error("invalid file ID: must be valid UUID format")]
    InvalidFileId,
    #[error("blob exceeds {0} MB limit")]
    BlobTooLarge(i64),
    #[error("file exceeds {0} MB limit")]
    FileTooLarge(i64),
}

pub fn validate_record_id(id: &str) -> Result<(), ValidationError> {
    if is_hyphenated_uuid(id) {
        Ok(())
    } else {
        Err(ValidationError::InvalidRecordId)
    }
}

pub fn validate_file_id(id: &str) -> Result<(), ValidationError> {
    if is_hyphenated_uuid(id) {
        Ok(())
    } else {
        Err(ValidationError::InvalidFileId)
    }
}

pub fn blob_too_large(limit_bytes: i64) -> ValidationError {
    ValidationError::BlobTooLarge(limit_bytes / (1024 * 1024))
}

pub fn file_too_large(limit_bytes: i64) -> ValidationError {
    ValidationError::FileTooLarge(limit_bytes / (1024 * 1024))
}

fn is_hyphenated_uuid(id: &str) -> bool {
    if id.len() != 36 {
        return false;
    }
    for (idx, b) in id.as_bytes().iter().enumerate() {
        let ok = match idx {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_hexdigit(),
        };
        if !ok {
            return false;
        }
    }
    // Parsing confirms structural bits without allowing compact UUID forms.
    Uuid::parse_str(id).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_record_id_cases() {
        let valid = [
            "019400e8-7b5d-7000-8000-000000000001",
            "d205899b-b9fb-4d6e-8159-8578661a574c",
            "5a4bfc46-90cf-517c-9cd7-c5ca19f890d3",
            "D205899B-B9FB-4D6E-8159-8578661A574C",
        ];
        for id in valid {
            assert!(validate_record_id(id).is_ok(), "{id}");
        }

        let invalid = [
            "invalid-id",
            "",
            "019400e87b5d70008000000000000001",
            "019400e8-7b5d-7000-8000",
            "019400e8-7b5d-7000-8000-000000000001x",
        ];
        for id in invalid {
            assert!(validate_record_id(id).is_err(), "{id}");
        }
    }

    #[test]
    fn validate_file_id_cases() {
        let valid = [
            "019400e8-7b5d-7000-8000-000000000001",
            "00000000-0000-0000-0000-000000000000",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
        ];
        for id in valid {
            assert!(validate_file_id(id).is_ok(), "{id}");
        }

        let invalid = ["abc", "not-a-valid-uuid", ""];
        for id in invalid {
            assert!(validate_file_id(id).is_err(), "{id}");
        }
    }
}
