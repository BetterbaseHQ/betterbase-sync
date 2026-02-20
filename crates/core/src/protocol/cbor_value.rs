use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Dynamic CBOR value type, used by the federation client to hold
/// partially-decoded RPC results before re-encoding into concrete types.
#[derive(Debug, Clone, PartialEq)]
pub enum CborValue {
    Null,
    Bool(bool),
    Integer(i64),
    Float(f64),
    Text(String),
    Bytes(Vec<u8>),
    Array(Vec<CborValue>),
    Map(Vec<(CborValue, CborValue)>),
}

impl CborValue {
    /// Convert any `Serialize` value into a `CborValue` by round-tripping
    /// through CBOR bytes. Replaces `serde_cbor::value::to_value`.
    pub fn from_serializable<T: Serialize>(val: &T) -> Result<CborValue, String> {
        let bytes = minicbor_serde::to_vec(val).map_err(|e| e.to_string())?;
        minicbor_serde::from_slice(&bytes).map_err(|e| e.to_string())
    }
}

impl Serialize for CborValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            CborValue::Null => serializer.serialize_none(),
            CborValue::Bool(b) => serializer.serialize_bool(*b),
            CborValue::Integer(n) => serializer.serialize_i64(*n),
            CborValue::Float(f) => serializer.serialize_f64(*f),
            CborValue::Text(s) => serializer.serialize_str(s),
            CborValue::Bytes(b) => serializer.serialize_bytes(b),
            CborValue::Array(arr) => arr.serialize(serializer),
            CborValue::Map(entries) => {
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for (k, v) in entries {
                    map.serialize_entry(k, v)?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for CborValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(CborValueVisitor)
    }
}

struct CborValueVisitor;

impl<'de> Visitor<'de> for CborValueVisitor {
    type Value = CborValue;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("any CBOR value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<CborValue, E> {
        Ok(CborValue::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<CborValue, E> {
        Ok(CborValue::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<CborValue, D::Error> {
        Deserialize::deserialize(deserializer)
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<CborValue, E> {
        Ok(CborValue::Bool(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<CborValue, E> {
        Ok(CborValue::Integer(v))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<CborValue, E> {
        i64::try_from(v)
            .map(CborValue::Integer)
            .map_err(|_| E::custom(format!("u64 value {v} overflows i64")))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<CborValue, E> {
        Ok(CborValue::Float(v))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<CborValue, E> {
        Ok(CborValue::Text(v.to_owned()))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<CborValue, E> {
        Ok(CborValue::Text(v))
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<CborValue, E> {
        Ok(CborValue::Bytes(v.to_vec()))
    }

    fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<CborValue, E> {
        Ok(CborValue::Bytes(v))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<CborValue, A::Error> {
        let mut arr = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(elem) = seq.next_element()? {
            arr.push(elem);
        }
        Ok(CborValue::Array(arr))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<CborValue, A::Error> {
        let mut entries = Vec::with_capacity(map.size_hint().unwrap_or(0));
        while let Some((k, v)) = map.next_entry()? {
            entries.push((k, v));
        }
        Ok(CborValue::Map(entries))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_primitives() {
        let values = vec![
            CborValue::Null,
            CborValue::Bool(true),
            CborValue::Integer(42),
            CborValue::Float(1.234),
            CborValue::Text("hello".to_owned()),
            CborValue::Bytes(vec![1, 2, 3]),
        ];
        for val in values {
            let encoded = minicbor_serde::to_vec(&val).expect("encode");
            let decoded: CborValue = minicbor_serde::from_slice(&encoded).expect("decode");
            assert_eq!(decoded, val);
        }
    }

    #[test]
    fn roundtrip_nested() {
        let val = CborValue::Map(vec![
            (
                CborValue::Text("key".to_owned()),
                CborValue::Array(vec![CborValue::Integer(1), CborValue::Null]),
            ),
            (
                CborValue::Text("data".to_owned()),
                CborValue::Bytes(vec![0xAA, 0xBB]),
            ),
        ]);
        let encoded = minicbor_serde::to_vec(&val).expect("encode");
        let decoded: CborValue = minicbor_serde::from_slice(&encoded).expect("decode");
        assert_eq!(decoded, val);
    }

    #[test]
    fn from_serializable_struct() {
        #[derive(serde::Serialize)]
        struct Example {
            name: String,
            count: i32,
        }
        let val = CborValue::from_serializable(&Example {
            name: "test".to_owned(),
            count: 7,
        })
        .expect("from_serializable");
        match &val {
            CborValue::Map(entries) => {
                assert_eq!(entries.len(), 2);
            }
            other => panic!("expected Map, got {other:?}"),
        }
    }
}
