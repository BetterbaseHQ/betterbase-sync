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
    fn cbor_roundtrip_preserves_all_value_kinds_in_nested_frames() {
        let frame = CborValue::Map(vec![(
            CborValue::Text("params".into()),
            CborValue::Array(vec![
                CborValue::Null,
                CborValue::Bool(true),
                CborValue::Bool(false),
                CborValue::Integer(-8),
                CborValue::Float(1.25),
                CborValue::Text("héllo".into()),
                CborValue::Bytes(vec![0, 128, 255]),
                CborValue::Array(vec![]),
                CborValue::Map(vec![]),
            ]),
        )]);
        let bytes = minicbor_serde::to_vec(&frame).expect("CBOR frame");
        assert_eq!(
            minicbor_serde::from_slice::<CborValue>(&bytes).expect("decode frame"),
            frame
        );
        assert_eq!(
            CborValue::from_serializable(&frame).expect("dynamic frame"),
            frame
        );
    }

    #[test]
    fn integer_boundaries_and_unsigned_overflow() {
        for value in [i64::MIN, -1, 0, i64::MAX] {
            assert_eq!(
                CborValue::from_serializable(&value).expect("signed integer"),
                CborValue::Integer(value)
            );
        }
        assert_eq!(
            CborValue::from_serializable(&(i64::MAX as u64))
                .expect("largest supported unsigned integer"),
            CborValue::Integer(i64::MAX)
        );
        for value in [i64::MAX as u64 + 1, u64::MAX] {
            assert!(
                CborValue::from_serializable(&value).is_err(),
                "overflow {value}"
            );
        }
    }

    #[test]
    fn federation_reencoding_preserves_binary_fields() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct ResultPayload {
            #[serde(with = "serde_bytes")]
            blob: Vec<u8>,
            cursor: i64,
        }
        let original = ResultPayload {
            blob: vec![0, 0x80, 0xff],
            cursor: i64::MAX,
        };
        let dynamic = CborValue::from_serializable(&original).expect("dynamic payload");
        let CborValue::Map(entries) = &dynamic else {
            panic!("expected payload map");
        };
        assert!(entries.contains(&(
            CborValue::Text("blob".to_owned()),
            CborValue::Bytes(original.blob.clone()),
        )));
        let encoded = minicbor_serde::to_vec(dynamic).expect("reencode");
        let decoded: ResultPayload =
            minicbor_serde::from_slice(&encoded).expect("concrete payload");
        assert_eq!(decoded, original);
    }

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
    #[test]
    fn conversion_rejects_unsigned_integer_overflow() {
        let error = CborValue::from_serializable(&u64::MAX).expect_err("overflow must not wrap");
        assert!(error.contains("overflows i64"), "{error}");
        assert_eq!(
            CborValue::from_serializable(&(i64::MAX as u64)).unwrap(),
            CborValue::Integer(i64::MAX)
        );
    }

    #[test]
    fn conversion_propagates_serializer_failure() {
        struct Invalid;
        impl Serialize for Invalid {
            fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("source serialization failed"))
            }
        }
        assert!(CborValue::from_serializable(&Invalid)
            .unwrap_err()
            .contains("source serialization failed"));
    }

    #[test]
    fn dynamic_values_accept_owned_strings_and_reject_unsupported_integer_width() {
        use serde::de::value::{Error, StringDeserializer, U128Deserializer};
        let value =
            CborValue::deserialize(StringDeserializer::<Error>::new("owned text".to_owned()))
                .unwrap();
        assert_eq!(value, CborValue::Text("owned text".to_owned()));
        let error = CborValue::deserialize(U128Deserializer::<Error>::new(u128::MAX)).unwrap_err();
        assert!(error.to_string().contains("any CBOR value"));
    }
}
