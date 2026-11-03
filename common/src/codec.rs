use alloc::string::String;
use alloc::vec::Vec;

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const HEX: &[u8; 16] = b"0123456789abcdef";

pub fn b58_encode(input: &[u8]) -> String {
    let zeros = input.iter().take_while(|b| **b == 0).count();
    let mut digits: Vec<u8> = Vec::with_capacity(input.len() * 138 / 100 + 1);
    for &byte in &input[zeros..] {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for d in digits.iter().rev() {
        out.push(B58[*d as usize] as char);
    }
    out
}

pub fn b58_decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    let zeros = bytes.iter().take_while(|b| **b == b'1').count();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    for &c in &bytes[zeros..] {
        let mut carry = B58.iter().position(|x| *x == c)? as u32;
        for o in out.iter_mut() {
            carry += (*o as u32) * 58;
            *o = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            out.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut result = alloc::vec![0u8; zeros];
    result.extend(out.iter().rev());
    Some(result)
}

pub fn b64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

fn b64_value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a' + 26) as u32),
        b'0'..=b'9' => Some((c - b'0' + 52) as u32),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

pub fn b64_decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let last = bytes.len() / 4;
    for (i, chunk) in bytes.chunks(4).enumerate() {
        let pad = chunk.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 || (pad > 0 && i + 1 != last) {
            return None;
        }
        let mut n = 0u32;
        for &c in &chunk[..4 - pad] {
            n = n << 6 | b64_value(c)?;
        }
        n <<= 6 * pad as u32;
        let decoded = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        if decoded[3 - pad..].iter().any(|b| *b != 0) {
            return None;
        }
        out.extend_from_slice(&decoded[..3 - pad]);
    }
    Some(out)
}

pub fn hex_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len() * 2);
    for b in input {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 15) as usize] as char);
    }
    out
}

pub fn hex_decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let nibble = |c: u8| HEX.iter().position(|h| *h == c).map(|p| p as u8);
    bytes.chunks(2).map(|p| Some(nibble(p[0])? << 4 | nibble(p[1])?)).collect()
}

pub fn push_decimal(out: &mut String, mut value: u128) {
    let mut buf = [0u8; 39];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for b in &buf[i..] {
        out.push(*b as char);
    }
}

pub fn decimal(value: u128) -> String {
    let mut s = String::new();
    push_decimal(&mut s, value);
    s
}

pub fn parse_decimal(input: &str) -> Option<u128> {
    let digits = input.strip_prefix('+').unwrap_or(input);
    if digits.is_empty() {
        return None;
    }
    let mut value: u128 = 0;
    for b in digits.bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((b - b'0') as u128)?;
    }
    Some(value)
}

pub struct BorshWriter(pub Vec<u8>);

impl BorshWriter {
    pub fn new() -> Self {
        Self(Vec::new())
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u128(&mut self, v: u128) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.u32(v.len() as u32);
        self.0.extend_from_slice(v);
        self
    }
    pub fn str(&mut self, v: &str) -> &mut Self {
        self.bytes(v.as_bytes())
    }
    pub fn opt_str(&mut self, v: Option<&str>) -> &mut Self {
        match v {
            Some(s) => self.u8(1).str(s),
            None => self.u8(0),
        }
    }
    pub fn raw(&mut self, v: &[u8]) -> &mut Self {
        self.0.extend_from_slice(v);
        self
    }
    pub fn var(&mut self, mut v: u128) -> &mut Self {
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                self.0.push(byte);
                return self;
            }
            self.0.push(byte | 0x80);
        }
    }
    pub fn short(&mut self, v: &str) -> &mut Self {
        self.u8(v.len() as u8);
        self.0.extend_from_slice(v.as_bytes());
        self
    }
}

impl Default for BorshWriter {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ByteReader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> ByteReader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }
    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.i.checked_add(n)?;
        let s = self.b.get(self.i..end)?;
        self.i = end;
        Some(s)
    }
    pub fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    pub fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    pub fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    pub fn u128(&mut self) -> Option<u128> {
        Some(u128::from_le_bytes(self.take(16)?.try_into().ok()?))
    }
    pub fn bool(&mut self) -> Option<bool> {
        match self.u8()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }
    pub fn var(&mut self) -> Option<u128> {
        let mut v: u128 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            if shift > 126 {
                return None;
            }
            v |= ((byte & 0x7f) as u128) << shift;
            if byte & 0x80 == 0 {
                return Some(v);
            }
            shift += 7;
        }
    }
    pub fn var64(&mut self) -> Option<u64> {
        u64::try_from(self.var()?).ok()
    }
    pub fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    pub fn string(&mut self) -> Option<String> {
        Some(String::from(core::str::from_utf8(self.bytes()?).ok()?))
    }
    pub fn short(&mut self) -> Option<String> {
        let n = self.u8()? as usize;
        Some(String::from(core::str::from_utf8(self.take(n)?).ok()?))
    }
    pub fn arr32(&mut self) -> Option<[u8; 32]> {
        self.take(32)?.try_into().ok()
    }
    pub fn done(&self) -> bool {
        self.i == self.b.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58_round_trips_and_matches_reference() {
        let key = [0u8, 0, 1, 2, 255, 7];
        assert_eq!(b58_decode(&b58_encode(&key)).unwrap(), key);
        assert_eq!(b58_encode(&[0x61]), "2g");
        assert_eq!(b58_encode(b"hello world"), "StV1DL6CwTryKyV");
        assert!(b58_decode("0OIl").is_none());
        assert_eq!(b58_decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn base64_is_strict_standard_with_padding() {
        assert_eq!(b64_encode(b"ab"), "YWI=");
        assert_eq!(b64_encode(b"abc"), "YWJj");
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_decode("YWI=").unwrap(), b"ab");
        assert_eq!(b64_decode("YQ==").unwrap(), b"a");
        assert!(b64_decode("YWI").is_none());
        assert!(b64_decode("YR==").is_none());
        assert!(b64_decode("Y===").is_none());
        assert!(b64_decode("YQ==YWJj").is_none());
        assert!(b64_decode("YW-j").is_none());
    }

    #[test]
    fn decimal_parse_matches_rust_unsigned_parsing() {
        for s in ["0", "007", "+5", "340282366920938463463374607431768211455"] {
            assert_eq!(parse_decimal(s), s.parse::<u128>().ok());
        }
        for s in ["", "+", "-1", "1.0", " 1", "340282366920938463463374607431768211456", "1e3"] {
            assert_eq!(parse_decimal(s), None);
            assert!(s.parse::<u128>().is_err());
        }
        assert_eq!(decimal(0), "0");
        assert_eq!(decimal(u128::MAX), "340282366920938463463374607431768211455");
    }

    #[test]
    fn varint_round_trips() {
        for v in [0u128, 1, 127, 128, 300, u64::MAX as u128, u128::MAX] {
            let mut w = BorshWriter::new();
            w.var(v);
            let mut r = ByteReader::new(&w.0);
            assert_eq!(r.var(), Some(v));
            assert!(r.done());
        }
    }
}
