use crate::codec::{b64_decode, b64_encode, parse_decimal, push_decimal};
use crate::types::{AccountId, Base64VecU8, PublicKey, U128, U64};
use alloc::string::String;
use alloc::vec::Vec;

pub type R<T> = Result<T, ()>;

pub struct Reader<'a> {
    b: &'a [u8],
    i: usize,
    depth: u32,
}

const MAX_DEPTH: u32 = 64;

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0, depth: 0 }
    }

    fn ws(&mut self) {
        while let Some(c) = self.b.get(self.i) {
            if matches!(c, b' ' | b'\t' | b'\n' | b'\r') {
                self.i += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.ws();
        self.b.get(self.i).copied()
    }

    fn eat(&mut self, c: u8) -> R<()> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(())
        }
    }

    fn literal(&mut self, word: &[u8]) -> R<()> {
        self.ws();
        if self.b.get(self.i..self.i + word.len()) == Some(word) {
            self.i += word.len();
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn end(&mut self) -> R<()> {
        self.ws();
        if self.i == self.b.len() {
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn null(&mut self) -> bool {
        if self.peek() == Some(b'n') && self.literal(b"null").is_ok() {
            return true;
        }
        false
    }

    pub fn bool(&mut self) -> R<bool> {
        match self.peek() {
            Some(b't') => self.literal(b"true").map(|_| true),
            Some(b'f') => self.literal(b"false").map(|_| false),
            _ => Err(()),
        }
    }

    fn hex4(&mut self) -> R<u32> {
        let mut v = 0u32;
        for _ in 0..4 {
            let c = *self.b.get(self.i).ok_or(())?;
            self.i += 1;
            v = v << 4
                | match c {
                    b'0'..=b'9' => (c - b'0') as u32,
                    b'a'..=b'f' => (c - b'a' + 10) as u32,
                    b'A'..=b'F' => (c - b'A' + 10) as u32,
                    _ => return Err(()),
                };
        }
        Ok(v)
    }

    pub fn string(&mut self) -> R<String> {
        self.eat(b'"')?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = *self.b.get(self.i).ok_or(())?;
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = *self.b.get(self.i).ok_or(())?;
                    self.i += 1;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let mut cp = self.hex4()?;
                            if (0xDC00..0xE000).contains(&cp) {
                                return Err(());
                            }
                            if (0xD800..0xDC00).contains(&cp) {
                                if self.b.get(self.i..self.i + 2) != Some(b"\\u") {
                                    return Err(());
                                }
                                self.i += 2;
                                let low = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&low) {
                                    return Err(());
                                }
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                            }
                            let ch = char::from_u32(cp).ok_or(())?;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err(()),
                    }
                }
                0..=0x1f => return Err(()),
                _ => out.push(c),
            }
        }
        String::from_utf8(out).map_err(|_| ())
    }

    pub fn uint(&mut self, max: u128) -> R<u128> {
        self.ws();
        let start = self.i;
        while self.b.get(self.i).is_some_and(|c| c.is_ascii_digit()) {
            self.i += 1;
        }
        let digits = &self.b[start..self.i];
        if digits.is_empty() || (digits.len() > 1 && digits[0] == b'0') {
            return Err(());
        }
        if matches!(self.b.get(self.i), Some(b'.' | b'e' | b'E')) {
            return Err(());
        }
        let v = parse_decimal(core::str::from_utf8(digits).map_err(|_| ())?).ok_or(())?;
        if v > max {
            return Err(());
        }
        Ok(v)
    }

    pub fn object(&mut self, mut field: impl FnMut(&mut Self, &str) -> R<bool>) -> R<()> {
        self.object_dyn(&mut field)
    }

    #[inline(never)]
    fn object_dyn(&mut self, field: &mut dyn FnMut(&mut Self, &str) -> R<bool>) -> R<()> {
        self.enter()?;
        self.eat(b'{')?;
        if self.peek() == Some(b'}') {
            self.i += 1;
            return self.leave();
        }
        loop {
            let key = self.string()?;
            self.eat(b':')?;
            if !field(self, &key)? {
                self.skip()?;
            }
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return self.leave();
                }
                _ => return Err(()),
            }
        }
    }

    pub fn array(&mut self, mut item: impl FnMut(&mut Self) -> R<()>) -> R<()> {
        self.array_dyn(&mut item)
    }

    #[inline(never)]
    fn array_dyn(&mut self, item: &mut dyn FnMut(&mut Self) -> R<()>) -> R<()> {
        self.enter()?;
        self.eat(b'[')?;
        if self.peek() == Some(b']') {
            self.i += 1;
            return self.leave();
        }
        loop {
            item(self)?;
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return self.leave();
                }
                _ => return Err(()),
            }
        }
    }

    fn enter(&mut self) -> R<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(());
        }
        Ok(())
    }

    fn leave(&mut self) -> R<()> {
        self.depth -= 1;
        Ok(())
    }

    fn number(&mut self) -> R<()> {
        self.ws();
        if self.b.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        let int_start = self.i;
        while self.b.get(self.i).is_some_and(|c| c.is_ascii_digit()) {
            self.i += 1;
        }
        let int = &self.b[int_start..self.i];
        if int.is_empty() || (int.len() > 1 && int[0] == b'0') {
            return Err(());
        }
        if self.b.get(self.i) == Some(&b'.') {
            self.i += 1;
            let s = self.i;
            while self.b.get(self.i).is_some_and(|c| c.is_ascii_digit()) {
                self.i += 1;
            }
            if self.i == s {
                return Err(());
            }
        }
        if matches!(self.b.get(self.i), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.b.get(self.i), Some(b'+' | b'-')) {
                self.i += 1;
            }
            let s = self.i;
            while self.b.get(self.i).is_some_and(|c| c.is_ascii_digit()) {
                self.i += 1;
            }
            if self.i == s {
                return Err(());
            }
        }
        Ok(())
    }

    pub fn skip(&mut self) -> R<()> {
        match self.peek().ok_or(())? {
            b'{' => self.object(|_, _| Ok(false)),
            b'[' => self.array(|r| r.skip()),
            b'"' => self.string().map(|_| ()),
            b't' | b'f' => self.bool().map(|_| ()),
            b'n' => self.literal(b"null"),
            _ => self.number(),
        }
    }

    pub fn account(&mut self) -> R<AccountId> {
        AccountId::parse_str(&self.string()?).ok_or(())
    }

    pub fn public_key(&mut self) -> R<PublicKey> {
        PublicKey::parse_str(&self.string()?).ok_or(())
    }

    pub fn u128_str(&mut self) -> R<U128> {
        parse_decimal(&self.string()?).map(U128).ok_or(())
    }

    pub fn u64_str(&mut self) -> R<U64> {
        let v = parse_decimal(&self.string()?).ok_or(())?;
        u64::try_from(v).map(U64).map_err(|_| ())
    }

    pub fn base64(&mut self) -> R<Base64VecU8> {
        b64_decode(&self.string()?).map(Base64VecU8).ok_or(())
    }

    pub fn opt<T>(&mut self, f: impl FnOnce(&mut Self) -> R<T>) -> R<Option<T>> {
        if self.null() {
            Ok(None)
        } else {
            f(self).map(Some)
        }
    }
}

pub fn set<T>(slot: &mut Option<T>, value: R<T>) -> R<bool> {
    if slot.is_some() {
        return Err(());
    }
    *slot = Some(value?);
    Ok(true)
}

pub fn set_opt<T>(slot: &mut Option<Option<T>>, value: R<Option<T>>) -> R<bool> {
    set(slot, value)
}

pub struct Writer(pub String);

impl Writer {
    pub fn new() -> Self {
        Self(String::new())
    }

    pub fn raw(&mut self, s: &str) -> &mut Self {
        self.0.push_str(s);
        self
    }

    pub fn str(&mut self, s: &str) -> &mut Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        self.0.push('"');
        for ch in s.chars() {
            match ch {
                '"' => self.0.push_str("\\\""),
                '\\' => self.0.push_str("\\\\"),
                '\u{8}' => self.0.push_str("\\b"),
                '\u{c}' => self.0.push_str("\\f"),
                '\n' => self.0.push_str("\\n"),
                '\r' => self.0.push_str("\\r"),
                '\t' => self.0.push_str("\\t"),
                c if (c as u32) < 0x20 => {
                    self.0.push_str("\\u00");
                    self.0.push(HEX[(c as u32 >> 4) as usize] as char);
                    self.0.push(HEX[(c as u32 & 15) as usize] as char);
                }
                c => self.0.push(c),
            }
        }
        self.0.push('"');
        self
    }

    pub fn uint(&mut self, v: u128) -> &mut Self {
        push_decimal(&mut self.0, v);
        self
    }

    pub fn quoted(&mut self, v: u128) -> &mut Self {
        self.0.push('"');
        push_decimal(&mut self.0, v);
        self.0.push('"');
        self
    }

    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.0.push_str(if v { "true" } else { "false" });
        self
    }

    pub fn null(&mut self) -> &mut Self {
        self.0.push_str("null");
        self
    }

    pub fn key(&mut self, k: &str) -> &mut Self {
        let last = self.0.as_bytes().last().copied();
        if !matches!(last, Some(b'{') | Some(b'[') | None) {
            self.0.push(',');
        }
        self.str(k);
        self.0.push(':');
        self
    }

    pub fn item(&mut self) -> &mut Self {
        let last = self.0.as_bytes().last().copied();
        if !matches!(last, Some(b'[') | None) {
            self.0.push(',');
        }
        self
    }

    pub fn account(&mut self, k: &str, v: &AccountId) -> &mut Self {
        self.key(k).str(v.as_str())
    }

    pub fn pk(&mut self, k: &str, v: &PublicKey) -> &mut Self {
        let s = v.to_string_repr();
        self.key(k).str(&s)
    }

    pub fn u128(&mut self, k: &str, v: u128) -> &mut Self {
        self.key(k).quoted(v)
    }

    pub fn base64(&mut self, k: &str, v: &[u8]) -> &mut Self {
        let s = b64_encode(v);
        self.key(k).str(&s)
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn parse_string(s: &str) -> R<String> {
        let mut r = Reader::new(s.as_bytes());
        let v = r.string()?;
        r.end()?;
        Ok(v)
    }

    #[test]
    fn strings_match_serde_json() {
        for s in [r#""plain""#, r#""a\"b\\c\/d""#, r#""\b\f\n\r\t""#, r#""é€""#, r#""😀""#, "\"caf\u{e9}\"", r#""\u0000""#] {
            let ours = parse_string(s).unwrap();
            let theirs: String = serde_json::from_str(s).unwrap();
            assert_eq!(ours, theirs, "{s}");
        }
        for s in [r#""\ud83d""#, r#""\ude00""#, r#""\x""#, "\"a\u{1}b\"", r#""abc"#, r#""\u12g4""#] {
            assert!(parse_string(s).is_err(), "{s}");
            assert!(serde_json::from_str::<String>(s).is_err(), "{s}");
        }
    }

    #[test]
    fn writer_escapes_like_serde_json() {
        let samples = ["plain", "q\"uote", "back\\slash", "tab\tnew\nline", "\u{1}\u{1f}\u{7f}", "caf\u{e9} \u{1f600}", "</script>"];
        for s in samples {
            let mut w = Writer::new();
            w.str(s);
            assert_eq!(w.0, serde_json::to_string(s).unwrap(), "{s:?}");
        }
    }

    #[test]
    fn integers_follow_json_grammar() {
        let ok = |s: &str| Reader::new(s.as_bytes()).uint(u16::MAX as u128);
        assert_eq!(ok("0"), Ok(0));
        assert_eq!(ok(" 50 "), Ok(50));
        for bad in ["01", "-1", "1.0", "1e2", "", "65536", "\"5\""] {
            assert!(ok(bad).is_err() || Reader::new(bad.as_bytes()).end().is_err(), "{bad}");
            assert!(serde_json::from_str::<u16>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn skip_accepts_any_valid_json_and_rejects_invalid() {
        for s in [r#"{"a":[1,-2.5e+3,true,false,null,{"b":"c"}],"d":{}}"#, "[]", "-0", "1E9", "\"x\""] {
            let mut r = Reader::new(s.as_bytes());
            r.skip().unwrap();
            r.end().unwrap();
            serde_json::from_str::<Value>(s).unwrap();
        }
        for s in ["{", "[1,]", "{\"a\" 1}", "01", "1.", "-", "tru", "{\"a\":1,}", "nul"] {
            let mut r = Reader::new(s.as_bytes());
            assert!(r.skip().and_then(|_| r.end()).is_err(), "{s}");
            assert!(serde_json::from_str::<Value>(s).is_err(), "{s}");
        }
    }

    #[test]
    fn nesting_is_bounded() {
        let deep = "[".repeat(100) + &"]".repeat(100);
        assert!(Reader::new(deep.as_bytes()).skip().is_err());
    }

    #[test]
    fn duplicate_fields_are_rejected() {
        let mut a: Option<u128> = None;
        let mut r = Reader::new(br#"{"a":1,"a":2}"#);
        let res = r.object(|r, k| match k {
            "a" => set(&mut a, r.uint(u128::MAX)),
            _ => Ok(false),
        });
        assert!(res.is_err());
    }
}
