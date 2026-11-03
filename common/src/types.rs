use crate::codec::{b58_decode, b58_encode};
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountId(String);

pub fn valid_account_id(id: &str) -> bool {
    if id.len() < 2 || id.len() > 64 {
        return false;
    }
    let mut last_separator = true;
    for b in id.bytes() {
        let separator = match b {
            b'a'..=b'z' | b'0'..=b'9' => false,
            b'-' | b'_' | b'.' => true,
            _ => return false,
        };
        if separator && last_separator {
            return false;
        }
        last_separator = separator;
    }
    !last_separator
}

impl AccountId {
    pub fn parse_str(id: &str) -> Option<Self> {
        valid_account_id(id).then(|| Self(String::from(id)))
    }
    pub fn from_trusted(id: String) -> Self {
        Self(id)
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn get_parent_account_id(&self) -> Option<&str> {
        self.0.split_once('.').map(|(_, parent)| parent)
    }
}

impl core::str::FromStr for AccountId {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        Self::parse_str(s).ok_or(())
    }
}

impl core::fmt::Display for AccountId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CurveType {
    ED25519 = 0,
    SECP256K1 = 1,
    MLDSA65 = 2,
}

impl CurveType {
    fn data_len(self) -> usize {
        match self {
            CurveType::ED25519 => 32,
            CurveType::SECP256K1 => 64,
            CurveType::MLDSA65 => 1952,
        }
    }
    fn prefix(self) -> &'static str {
        match self {
            CurveType::ED25519 => "ed25519:",
            CurveType::SECP256K1 => "secp256k1:",
            CurveType::MLDSA65 => "ml-dsa-65:",
        }
    }
    fn from_name(name: &str) -> Option<Self> {
        if name.eq_ignore_ascii_case("ed25519") {
            Some(CurveType::ED25519)
        } else if name.eq_ignore_ascii_case("secp256k1") {
            Some(CurveType::SECP256K1)
        } else if name.eq_ignore_ascii_case("ml-dsa-65") {
            Some(CurveType::MLDSA65)
        } else {
            None
        }
    }
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(CurveType::ED25519),
            1 => Some(CurveType::SECP256K1),
            2 => Some(CurveType::MLDSA65),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey {
    data: Vec<u8>,
}

impl PublicKey {
    pub fn from_parts(curve: CurveType, data: Vec<u8>) -> Result<Self, ()> {
        if data.len() != curve.data_len() {
            return Err(());
        }
        let mut bytes = Vec::with_capacity(1 + data.len());
        bytes.push(curve as u8);
        bytes.extend(data);
        Ok(Self { data: bytes })
    }
    pub fn ed25519(key: [u8; 32]) -> Self {
        let mut data = Vec::with_capacity(33);
        data.push(0);
        data.extend_from_slice(&key);
        Self { data }
    }
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let curve = CurveType::from_u8(*data.first()?)?;
        (data.len() == 1 + curve.data_len()).then(|| Self { data: data.to_vec() })
    }
    pub fn parse_str(value: &str) -> Option<Self> {
        let (curve, key) = match value.split_once(':') {
            Some((name, key)) => (CurveType::from_name(name)?, key),
            None => (CurveType::ED25519, value),
        };
        Self::from_parts(curve, b58_decode(key)?).ok()
    }
    pub fn curve_type(&self) -> CurveType {
        CurveType::from_u8(self.data[0]).unwrap_or(CurveType::ED25519)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
    pub fn to_string_repr(&self) -> String {
        let mut s = String::from(self.curve_type().prefix());
        s.push_str(&b58_encode(&self.data[1..]));
        s
    }
}

impl core::str::FromStr for PublicKey {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        Self::parse_str(s).ok_or(())
    }
}

impl core::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_string_repr())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct U128(pub u128);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct U64(pub u64);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Base64VecU8(pub Vec<u8>);

impl From<u128> for U128 {
    fn from(v: u128) -> Self {
        Self(v)
    }
}

impl From<u64> for U64 {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

impl From<Vec<u8>> for Base64VecU8 {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_ids_follow_near_rules() {
        for ok in ["ab", "alice.near", "a-b_c.d", "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1", "u-7k3x9q2m4p.obiba.near"] {
            assert!(valid_account_id(ok), "{ok}");
        }
        for bad in ["a", "", "Alice.near", ".a", "a.", "a..b", "a-.b", "a b", "ab@c", &"a".repeat(65)] {
            assert!(!valid_account_id(bad), "{bad}");
        }
        let id: AccountId = "u-test.obiba.near".parse().unwrap();
        assert_eq!(id.get_parent_account_id(), Some("obiba.near"));
        assert_eq!("near".parse::<AccountId>().unwrap().get_parent_account_id(), None);
    }

    #[test]
    fn public_keys_parse_like_near_sdk() {
        let pk = PublicKey::parse_str("ed25519:GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB").unwrap();
        assert_eq!(pk.curve_type(), CurveType::ED25519);
        assert_eq!(pk.to_string_repr(), "ed25519:GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB");
        assert_eq!(PublicKey::parse_str("ED25519:GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB"), Some(pk.clone()));
        assert_eq!(PublicKey::parse_str("GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB"), Some(pk));
        assert!(PublicKey::parse_str("ed25519:abc").is_none());
        assert!(PublicKey::parse_str("rsa:GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB").is_none());
    }
}
