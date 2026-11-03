#![cfg_attr(target_arch = "wasm32", no_std)]
extern crate alloc;
#[cfg(test)]
extern crate near_sdk as _;

pub mod codec;
pub mod json;
pub mod rt;
mod types;

pub use types::*;

use alloc::string::String;
use alloc::vec::Vec;
use codec::BorshWriter;
use json::{set, set_opt, Reader, Writer, R};

pub const ACCOUNT_TAG: &str = "obiba-account/v1";
pub const INVOICE_TAG: &str = "obiba-invoice/v1";
pub const ID_HEX_LEN: usize = 32;
pub const MAX_MEMO_LEN: usize = 64;
pub const HOUR_NS: u64 = 3_600_000_000_000;
pub const WINDOW_HOURS: usize = 24;
pub const USD_DECIMALS: u8 = 6;
pub const MAX_TOKEN_DECIMALS: u8 = 24;
pub const MAX_TOKENS: usize = 16;

pub trait Borsh {
    fn encode(&self, w: &mut BorshWriter);
}

pub fn borsh_bytes<T: Borsh>(value: &T) -> Vec<u8> {
    let mut w = BorshWriter::new();
    value.encode(&mut w);
    w.0
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpKind {
    Transfer,
    PayInvoice,
}

impl OpKind {
    pub fn name(self) -> &'static str {
        match self {
            OpKind::Transfer => "Transfer",
            OpKind::PayInvoice => "PayInvoice",
        }
    }
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(OpKind::Transfer),
            1 => Some(OpKind::PayInvoice),
            _ => None,
        }
    }
    pub fn read(r: &mut Reader) -> R<Self> {
        match r.string()?.as_str() {
            "Transfer" => Ok(OpKind::Transfer),
            "PayInvoice" => Ok(OpKind::PayInvoice),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Op {
    pub op_id: String,
    pub kind: OpKind,
    pub token: AccountId,
    pub receiver: AccountId,
    pub amount: U128,
    pub expires_at_ns: U64,
    pub memo: Option<String>,
}

impl Op {
    pub fn read(r: &mut Reader) -> R<Self> {
        let (mut op_id, mut kind, mut token, mut receiver, mut amount, mut expires, mut memo) = (None, None, None, None, None, None, None);
        r.object(|r, k| match k {
            "op_id" => set(&mut op_id, r.string()),
            "kind" => set(&mut kind, OpKind::read(r)),
            "token" => set(&mut token, r.account()),
            "receiver" => set(&mut receiver, r.account()),
            "amount" => set(&mut amount, r.u128_str()),
            "expires_at_ns" => set(&mut expires, r.u64_str()),
            "memo" => set_opt(&mut memo, r.opt(|r| r.string())),
            _ => Ok(false),
        })?;
        Ok(Op {
            op_id: op_id.ok_or(())?,
            kind: kind.ok_or(())?,
            token: token.ok_or(())?,
            receiver: receiver.ok_or(())?,
            amount: amount.ok_or(())?,
            expires_at_ns: expires.ok_or(())?,
            memo: memo.flatten(),
        })
    }

    pub fn write(&self, w: &mut Writer) {
        w.raw("{").key("op_id").str(&self.op_id);
        w.key("kind").str(self.kind.name());
        w.account("token", &self.token).account("receiver", &self.receiver);
        w.u128("amount", self.amount.0).u128("expires_at_ns", self.expires_at_ns.0 as u128);
        w.key("memo");
        match &self.memo {
            Some(m) => w.str(m),
            None => w.null(),
        };
        w.raw("}");
    }
}

impl Borsh for Op {
    fn encode(&self, w: &mut BorshWriter) {
        w.str(&self.op_id).u8(self.kind as u8).str(self.token.as_str()).str(self.receiver.as_str());
        w.u128(self.amount.0).u64(self.expires_at_ns.0).opt_str(self.memo.as_deref());
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    ExecuteOp,
    RaiseLimit,
    AddDevice,
    RemoveDevice,
    BeginRecovery,
    Freeze,
    Unfreeze,
    RotateGuardian,
    VetoGuardianChange,
    AddToken,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LimitPayload {
    pub new_limit: U128,
    pub guardian_nonce: U64,
}

impl Borsh for LimitPayload {
    fn encode(&self, w: &mut BorshWriter) {
        w.u128(self.new_limit.0).u64(self.guardian_nonce.0);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPayload {
    pub public_key: PublicKey,
    pub guardian_nonce: U64,
}

impl Borsh for KeyPayload {
    fn encode(&self, w: &mut BorshWriter) {
        w.bytes(self.public_key.as_bytes()).u64(self.guardian_nonce.0);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FreezePayload {
    pub until_ns: U64,
    pub guardian_nonce: U64,
}

impl Borsh for FreezePayload {
    fn encode(&self, w: &mut BorshWriter) {
        w.u64(self.until_ns.0).u64(self.guardian_nonce.0);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenPayload {
    pub token: AccountId,
    pub decimals: u8,
    pub guardian_nonce: U64,
}

impl Borsh for TokenPayload {
    fn encode(&self, w: &mut BorshWriter) {
        w.str(self.token.as_str()).u8(self.decimals).u64(self.guardian_nonce.0);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoncePayload {
    pub guardian_nonce: U64,
}

impl Borsh for NoncePayload {
    fn encode(&self, w: &mut BorshWriter) {
        w.u64(self.guardian_nonce.0);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenConfig {
    pub decimals: u8,
    pub enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invoice {
    pub invoice_id: String,
    pub merchant: AccountId,
    pub token: AccountId,
    pub amount: U128,
    pub fee_bps: u16,
    pub expires_at_ns: U64,
    pub reference: Option<String>,
}

impl Invoice {
    pub fn read(r: &mut Reader) -> R<Self> {
        let (mut id, mut merchant, mut token, mut amount, mut fee, mut expires, mut reference) = (None, None, None, None, None, None, None);
        r.object(|r, k| match k {
            "invoice_id" => set(&mut id, r.string()),
            "merchant" => set(&mut merchant, r.account()),
            "token" => set(&mut token, r.account()),
            "amount" => set(&mut amount, r.u128_str()),
            "fee_bps" => set(&mut fee, r.uint(u16::MAX as u128).map(|v| v as u16)),
            "expires_at_ns" => set(&mut expires, r.u64_str()),
            "reference" => set_opt(&mut reference, r.opt(|r| r.string())),
            _ => Ok(false),
        })?;
        Ok(Invoice {
            invoice_id: id.ok_or(())?,
            merchant: merchant.ok_or(())?,
            token: token.ok_or(())?,
            amount: amount.ok_or(())?,
            fee_bps: fee.ok_or(())?,
            expires_at_ns: expires.ok_or(())?,
            reference: reference.flatten(),
        })
    }

    pub fn write(&self, w: &mut Writer) {
        w.raw("{").key("invoice_id").str(&self.invoice_id);
        w.account("merchant", &self.merchant).account("token", &self.token);
        w.u128("amount", self.amount.0).key("fee_bps").uint(self.fee_bps as u128);
        w.u128("expires_at_ns", self.expires_at_ns.0 as u128).key("reference");
        match &self.reference {
            Some(s) => w.str(s),
            None => w.null(),
        };
        w.raw("}");
    }
}

impl Borsh for Invoice {
    fn encode(&self, w: &mut BorshWriter) {
        w.str(&self.invoice_id).str(self.merchant.as_str()).str(self.token.as_str());
        w.u128(self.amount.0).u16(self.fee_bps).u64(self.expires_at_ns.0).opt_str(self.reference.as_deref());
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedInvoice {
    pub invoice: Invoice,
    pub signature: Base64VecU8,
}

impl SignedInvoice {
    pub fn read(r: &mut Reader) -> R<Self> {
        let (mut invoice, mut signature) = (None, None);
        r.object(|r, k| match k {
            "invoice" => set(&mut invoice, Invoice::read(r)),
            "signature" => set(&mut signature, r.base64()),
            _ => Ok(false),
        })?;
        Ok(SignedInvoice { invoice: invoice.ok_or(())?, signature: signature.ok_or(())? })
    }

    pub fn parse(bytes: &[u8]) -> R<Self> {
        let mut r = Reader::new(bytes);
        let v = Self::read(&mut r)?;
        r.end()?;
        Ok(v)
    }

    pub fn write(&self, w: &mut Writer) {
        w.raw("{").key("invoice");
        self.invoice.write(w);
        w.base64("signature", &self.signature.0).raw("}");
    }

    pub fn to_json(&self) -> String {
        let mut w = Writer::new();
        self.write(&mut w);
        w.into_string()
    }
}

pub fn guardian_preimage<T: Borsh>(network_id: &str, account: &AccountId, purpose: Purpose, payload: &T) -> Vec<u8> {
    let mut w = BorshWriter::new();
    w.str(ACCOUNT_TAG).str(network_id).str(account.as_str()).u8(purpose as u8).bytes(&borsh_bytes(payload));
    w.0
}

pub fn invoice_preimage(network_id: &str, pay_contract: &AccountId, invoice: &Invoice) -> Vec<u8> {
    let mut w = BorshWriter::new();
    w.str(INVOICE_TAG).str(network_id).str(pay_contract.as_str());
    invoice.encode(&mut w);
    w.0
}

pub fn is_hex_id(value: &str) -> bool {
    value.len() == ID_HEX_LEN && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn ed25519_key(key: &PublicKey) -> Option<[u8; 32]> {
    if key.curve_type() != CurveType::ED25519 {
        return None;
    }
    let bytes = key.as_bytes();
    let raw = if bytes.len() == 33 { &bytes[1..] } else { bytes };
    raw.try_into().ok()
}

pub fn usd_units(amount: u128, decimals: u8) -> Option<u128> {
    if decimals > MAX_TOKEN_DECIMALS {
        return None;
    }
    if decimals <= USD_DECIMALS {
        return amount.checked_mul(10u128.pow(u32::from(USD_DECIMALS - decimals)));
    }
    let divisor = 10u128.pow(u32::from(decimals - USD_DECIMALS));
    Some(amount / divisor + u128::from(amount % divisor != 0))
}

pub fn signature_bytes(signature: &Base64VecU8) -> Option<[u8; 64]> {
    signature.0.as_slice().try_into().ok()
}

pub fn emit(event: &str, data: &str) {
    let mut w = Writer::new();
    w.raw("EVENT_JSON:{\"standard\":\"obiba\",\"version\":\"1.0.0\",\"event\":").str(event);
    w.raw(",\"data\":[").raw(data).raw("]}");
    rt::log(&w.0);
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpendWindow {
    pub entries: Vec<(u64, u128)>,
    pub hour: U64,
}

impl SpendWindow {
    pub fn hour_of(now_ns: u64) -> u64 {
        now_ns / HOUR_NS
    }

    pub fn roll(&mut self, now_hour: u64) {
        if now_hour <= self.hour.0 {
            return;
        }
        self.entries.retain(|(h, _)| now_hour - h < WINDOW_HOURS as u64);
        self.hour = U64(now_hour);
    }

    pub fn spent(&self) -> u128 {
        self.entries.iter().fold(0u128, |acc, (_, a)| acc.saturating_add(*a))
    }

    pub fn add(&mut self, amount: u128) {
        if amount == 0 {
            return;
        }
        let hour = self.hour.0;
        match self.entries.iter_mut().find(|(h, _)| *h == hour) {
            Some((_, a)) => *a = a.checked_add(amount).unwrap_or_else(|| rt::panic_str("spend overflow")),
            None => self.entries.push((hour, amount)),
        }
    }

    pub fn release(&mut self, amount: u128, spent_hour: u64) {
        if spent_hour > self.hour.0 || self.hour.0 - spent_hour >= WINDOW_HOURS as u64 {
            return;
        }
        if let Some((_, a)) = self.entries.iter_mut().find(|(h, _)| *h == spent_hour) {
            *a = a.saturating_sub(amount);
        }
        self.entries.retain(|(_, a)| *a > 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn hex_ids() {
        assert!(is_hex_id("0123456789abcdef0123456789abcdef"));
        assert!(!is_hex_id("0123456789ABCDEF0123456789abcdef"));
        assert!(!is_hex_id("0123456789abcdef0123456789abcde"));
        assert!(!is_hex_id("0123456789abcdef0123456789abcdeg"));
    }

    #[test]
    fn usd_units_normalize_and_round_up() {
        assert_eq!(usd_units(1_000_000, 6), Some(1_000_000));
        assert_eq!(usd_units(1, 18), Some(1));
        assert_eq!(usd_units(1_000_000_000_000, 18), Some(1));
        assert_eq!(usd_units(1_000_000_000_001, 18), Some(2));
        assert_eq!(usd_units(5, 2), Some(50_000));
        assert_eq!(usd_units(1, 25), None);
        assert_eq!(usd_units(u128::MAX, 0), None);
    }

    #[test]
    fn window_rolls_off_after_24_hours() {
        let mut w = SpendWindow::default();
        w.roll(100);
        w.add(10);
        w.roll(112);
        w.add(5);
        w.roll(123);
        assert_eq!(w.spent(), 15);
        w.roll(124);
        assert_eq!(w.spent(), 5);
        w.roll(136);
        assert_eq!(w.spent(), 0);
        assert!(w.entries.is_empty());
    }

    #[test]
    fn release_only_inside_window() {
        let mut w = SpendWindow::default();
        w.roll(10);
        w.add(50);
        w.roll(20);
        w.release(20, 10);
        assert_eq!(w.spent(), 30);
        w.roll(40);
        w.release(30, 10);
        assert_eq!(w.spent(), 0);
        w.add(7);
        w.release(7, 41);
        assert_eq!(w.spent(), 7);
    }

    #[test]
    fn roll_backwards_is_ignored() {
        let mut w = SpendWindow::default();
        w.roll(50);
        w.add(9);
        w.roll(49);
        assert_eq!(w.spent(), 9);
        assert_eq!(w.hour.0, 50);
    }

    #[derive(Clone)]
    struct Buckets {
        buckets: [u128; WINDOW_HOURS],
        hour: u64,
    }

    impl Buckets {
        fn roll(&mut self, now_hour: u64) {
            let last = self.hour;
            if now_hour <= last {
                return;
            }
            if now_hour - last >= WINDOW_HOURS as u64 {
                self.buckets = [0; WINDOW_HOURS];
            } else {
                for h in (last + 1)..=now_hour {
                    self.buckets[(h % WINDOW_HOURS as u64) as usize] = 0;
                }
            }
            self.hour = now_hour;
        }
        fn spent(&self) -> u128 {
            self.buckets.iter().fold(0u128, |acc, b| acc.saturating_add(*b))
        }
        fn add(&mut self, amount: u128) {
            let i = (self.hour % WINDOW_HOURS as u64) as usize;
            self.buckets[i] += amount;
        }
        fn release(&mut self, amount: u128, spent_hour: u64) {
            if spent_hour > self.hour || self.hour - spent_hour >= WINDOW_HOURS as u64 {
                return;
            }
            let i = (spent_hour % WINDOW_HOURS as u64) as usize;
            self.buckets[i] = self.buckets[i].saturating_sub(amount);
        }
    }

    proptest! {
        #[test]
        fn spent_equals_sum_of_last_24_hours(events in proptest::collection::vec((0u64..6, 0u128..1_000_000), 1..200)) {
            let mut w = SpendWindow::default();
            let mut hour = 1_000u64;
            let mut log: Vec<(u64, u128)> = vec![];
            for (step, amount) in events {
                hour += step;
                w.roll(hour);
                w.add(amount);
                log.push((hour, amount));
                let expected: u128 = log.iter().filter(|(h, _)| hour - h < 24).map(|(_, a)| a).sum();
                prop_assert_eq!(w.spent(), expected);
                prop_assert!(w.entries.len() <= WINDOW_HOURS);
            }
        }

        #[test]
        fn sparse_window_matches_the_bucket_window(events in proptest::collection::vec((0u64..30, 0u128..1_000_000, any::<bool>(), 0u64..30), 1..300)) {
            let mut sparse = SpendWindow::default();
            let mut dense = Buckets { buckets: [0; WINDOW_HOURS], hour: 0 };
            let mut hour = 500u64;
            for (step, amount, release, back) in events {
                hour += step;
                sparse.roll(hour);
                dense.roll(hour);
                if release {
                    let at = hour.saturating_sub(back);
                    sparse.release(amount, at);
                    dense.release(amount, at);
                } else {
                    sparse.add(amount);
                    dense.add(amount);
                }
                prop_assert_eq!(sparse.spent(), dense.spent());
            }
        }

        #[test]
        fn usd_units_never_undercount(amount in 0u128..u128::MAX / 1_000_000, decimals in 0u8..=24) {
            let usd = usd_units(amount, decimals).unwrap();
            if decimals >= 6 {
                let back = usd.saturating_mul(10u128.pow(u32::from(decimals - 6)));
                prop_assert!(back >= amount);
            } else {
                prop_assert_eq!(usd, amount * 10u128.pow(u32::from(6 - decimals)));
            }
        }

        #[test]
        fn release_never_underflows_or_touches_other_hours(a in 0u128..1_000, b in 0u128..1_000, r in 0u128..5_000) {
            let mut w = SpendWindow::default();
            w.roll(500);
            w.add(a);
            w.roll(501);
            w.add(b);
            w.release(r, 500);
            prop_assert_eq!(w.spent(), a.saturating_sub(r) + b);
        }
    }

    #[test]
    fn op_and_invoice_json_round_trip_through_serde_shapes() {
        let src = r#"{ "memo": null, "kind": "PayInvoice", "op_id": "0192f5c3a1b27c4d8e9f00112233aabb", "token": "usdc.near", "receiver": "pay.obiba.near", "amount": "5", "expires_at_ns": "7", "extra": [1, {"x": 2}] }"#;
        let mut r = Reader::new(src.as_bytes());
        let op = Op::read(&mut r).unwrap();
        r.end().unwrap();
        assert_eq!(op.kind, OpKind::PayInvoice);
        assert_eq!(op.memo, None);
        let mut w = Writer::new();
        op.write(&mut w);
        let ours: serde_json::Value = serde_json::from_str(&w.0).unwrap();
        let expected: serde_json::Value = serde_json::from_str(src).unwrap();
        for k in ["memo", "kind", "op_id", "token", "receiver", "amount", "expires_at_ns"] {
            assert_eq!(ours[k], expected[k], "{k}");
        }
        for bad in [
            r#"{"kind":"Transfer","op_id":"a","token":"usdc.near","receiver":"a.near","amount":"5"}"#,
            r#"{"kind":"Transfer","op_id":"a","token":"usdc.near","receiver":"a.near","amount":5,"expires_at_ns":"1"}"#,
            r#"{"kind":"Other","op_id":"a","token":"usdc.near","receiver":"a.near","amount":"5","expires_at_ns":"1"}"#,
            r#"{"kind":"Transfer","op_id":"a","token":"USDC","receiver":"a.near","amount":"5","expires_at_ns":"1"}"#,
            r#"{"kind":"Transfer","op_id":"a","op_id":"b","token":"usdc.near","receiver":"a.near","amount":"5","expires_at_ns":"1"}"#,
            r#"{"kind":"Transfer","op_id":"a","token":"usdc.near","receiver":"a.near","amount":"5","expires_at_ns":"18446744073709551616"}"#,
        ] {
            assert!(Op::read(&mut Reader::new(bad.as_bytes())).is_err(), "{bad}");
        }
    }

    #[test]
    fn signed_invoice_serializes_exactly_like_serde() {
        let inv = SignedInvoice {
            invoice: Invoice {
                invoice_id: "aa11bb22cc33dd44ee55ff6600778899".into(),
                merchant: "cafe.obiba.near".parse().unwrap(),
                token: "usdc.near".parse().unwrap(),
                amount: U128(12_345_678),
                fee_bps: 50,
                expires_at_ns: U64(1_800_003_600_000_000_000),
                reference: Some("table \"4\"".into()),
            },
            signature: Base64VecU8(vec![1, 2, 3, 250]),
        };
        let expected = serde_json::json!({
            "invoice": {
                "invoice_id": "aa11bb22cc33dd44ee55ff6600778899",
                "merchant": "cafe.obiba.near",
                "token": "usdc.near",
                "amount": "12345678",
                "fee_bps": 50,
                "expires_at_ns": "1800003600000000000",
                "reference": "table \"4\""
            },
            "signature": "AQID+g=="
        });
        assert_eq!(inv.to_json(), serde_json::to_string(&expected).unwrap());
        assert_eq!(SignedInvoice::parse(inv.to_json().as_bytes()).unwrap(), inv);
        let mut none = inv.clone();
        none.invoice.reference = None;
        assert!(none.to_json().contains("\"reference\":null"));
        assert_eq!(SignedInvoice::parse(none.to_json().as_bytes()).unwrap(), none);
    }
}

#[cfg(test)]
mod vectors {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};

    const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors/vectors.json");

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn pk() -> PublicKey {
        PublicKey::from_parts(CurveType::ED25519, key().verifying_key().to_bytes().to_vec()).unwrap()
    }

    fn entry(name: &str, input: Value, preimage: Vec<u8>) -> Value {
        let digest = Sha256::digest(&preimage);
        json!({
            "name": name,
            "input": input,
            "preimage_hex": hex::encode(&preimage),
            "digest_hex": hex::encode(digest),
            "signature_hex": hex::encode(key().sign(&digest).to_bytes()),
        })
    }

    fn parse(s: String) -> Value {
        serde_json::from_str(&s).unwrap()
    }

    fn op_json(op: &Op) -> Value {
        let mut w = Writer::new();
        op.write(&mut w);
        parse(w.0)
    }

    fn obj(f: impl FnOnce(&mut Writer)) -> Value {
        let mut w = Writer::new();
        w.raw("{");
        f(&mut w);
        w.raw("}");
        parse(w.0)
    }

    fn build() -> Value {
        let account: AccountId = "u-7k3x9q2m4p.obiba.near".parse().unwrap();
        let pay: AccountId = "pay.obiba.near".parse().unwrap();
        let op = Op {
            op_id: "0192f5c3a1b27c4d8e9f00112233aabb".into(),
            kind: OpKind::Transfer,
            token: "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1".parse().unwrap(),
            receiver: "alice.near".parse().unwrap(),
            amount: U128(12_345_678),
            expires_at_ns: U64(1_800_000_600_000_000_000),
            memo: None,
        };
        let mut pay_op = op.clone();
        pay_op.kind = OpKind::PayInvoice;
        pay_op.receiver = pay.clone();
        pay_op.memo = Some("aa11bb22cc33dd44ee55ff6600778899".into());
        let invoice = Invoice {
            invoice_id: "aa11bb22cc33dd44ee55ff6600778899".into(),
            merchant: "cafe.obiba.near".parse().unwrap(),
            token: "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1".parse().unwrap(),
            amount: U128(12_345_678),
            fee_bps: 50,
            expires_at_ns: U64(1_800_003_600_000_000_000),
            reference: Some("table-4".into()),
        };
        let key_payload = KeyPayload { public_key: pk(), guardian_nonce: U64(3) };
        let limit = LimitPayload { new_limit: U128(200_000_000), guardian_nonce: U64(1) };
        let freeze = FreezePayload { until_ns: U64(1_800_259_200_000_000_000), guardian_nonce: U64(2) };
        let nonce = NoncePayload { guardian_nonce: U64(4) };
        let token = TokenPayload { token: "usdt.tether-token.near".parse().unwrap(), decimals: 6, guardian_nonce: U64(5) };
        let key_json = obj(|w| {
            w.pk("public_key", &key_payload.public_key).u128("guardian_nonce", 3);
        });
        let invoice_json = {
            let mut w = Writer::new();
            invoice.write(&mut w);
            parse(w.0)
        };
        json!({
            "signer_public_key": pk().to_string_repr(),
            "network_id": "mainnet",
            "account": account.as_str(),
            "pay_contract": pay.as_str(),
            "vectors": [
                entry("op_borsh_transfer", op_json(&op), borsh_bytes(&op)),
                entry("guardian_execute_transfer", op_json(&op), guardian_preimage("mainnet", &account, Purpose::ExecuteOp, &op)),
                entry("guardian_execute_pay_invoice", op_json(&pay_op), guardian_preimage("mainnet", &account, Purpose::ExecuteOp, &pay_op)),
                entry("guardian_raise_limit", obj(|w| { w.u128("new_limit", 200_000_000).u128("guardian_nonce", 1); }), guardian_preimage("mainnet", &account, Purpose::RaiseLimit, &limit)),
                entry("guardian_add_device", key_json.clone(), guardian_preimage("mainnet", &account, Purpose::AddDevice, &key_payload)),
                entry("guardian_begin_recovery", key_json, guardian_preimage("mainnet", &account, Purpose::BeginRecovery, &key_payload)),
                entry("guardian_freeze", obj(|w| { w.u128("until_ns", 1_800_259_200_000_000_000).u128("guardian_nonce", 2); }), guardian_preimage("mainnet", &account, Purpose::Freeze, &freeze)),
                entry("guardian_unfreeze", obj(|w| { w.u128("guardian_nonce", 4); }), guardian_preimage("mainnet", &account, Purpose::Unfreeze, &nonce)),
                entry("guardian_add_token", obj(|w| { w.account("token", &token.token).key("decimals").uint(6).u128("guardian_nonce", 5); }), guardian_preimage("mainnet", &account, Purpose::AddToken, &token)),
                entry("invoice", invoice_json, invoice_preimage("mainnet", &pay, &invoice)),
            ]
        })
    }

    #[test]
    fn vectors_match_fixture() {
        let built = build();
        let fixture: Value = serde_json::from_str(&std::fs::read_to_string(FIXTURE).expect("fixture")).unwrap();
        assert_eq!(built, fixture, "signed-message encoding changed; the backend must change with it");
    }
}
