#![cfg_attr(target_arch = "wasm32", no_std)]
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use obiba_common::codec::{BorshWriter, ByteReader};
use obiba_common::json::{set, Reader, Writer, R};
use obiba_common::rt::{self, require, Promise};
use obiba_common::{
    ed25519_key, emit, invoice_preimage, is_hex_id, signature_bytes, AccountId, PublicKey, SignedInvoice, HOUR_NS,
    MAX_MEMO_LEN, MAX_TOKENS, U128, U64,
};

const TGAS: u64 = 1_000_000_000_000;
pub const MAX_FEE_BPS: u16 = 100;
pub const OWNER_DELAY_NS: u64 = 24 * HOUR_NS;
pub const PAID_RETENTION_NS: u64 = 24 * HOUR_NS;
pub const MAX_MSG_LEN: usize = 1024;
pub const GAS_FT_TRANSFER: u64 = 15 * TGAS;
pub const GAS_CALLBACK: u64 = 10 * TGAS;
const STATE_KEY: &[u8] = b"s";

pub enum PromiseOrValue<T> {
    Promise(Promise),
    Value(T),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaidRecord {
    pub payer: AccountId,
    pub merchant: AccountId,
    pub token: AccountId,
    pub amount: U128,
    pub fee: U128,
    pub paid_at_ns: U64,
}

impl PaidRecord {
    fn encode(&self) -> Vec<u8> {
        let mut w = BorshWriter::new();
        w.short(self.payer.as_str()).short(self.merchant.as_str()).short(self.token.as_str());
        w.var(self.amount.0).var(self.fee.0).var(self.paid_at_ns.0 as u128);
        w.0
    }

    fn decode(b: &[u8]) -> Option<Self> {
        let mut r = ByteReader::new(b);
        Some(PaidRecord {
            payer: AccountId::from_trusted(r.short()?),
            merchant: AccountId::from_trusted(r.short()?),
            token: AccountId::from_trusted(r.short()?),
            amount: U128(r.var()?),
            fee: U128(r.var()?),
            paid_at_ns: U64(r.var64()?),
        })
    }

    pub fn to_json(&self) -> String {
        let mut w = Writer::new();
        w.raw("{").account("payer", &self.payer).account("merchant", &self.merchant).account("token", &self.token);
        w.u128("amount", self.amount.0).u128("fee", self.fee.0).u128("paid_at_ns", self.paid_at_ns.0 as u128).raw("}");
        w.into_string()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending<T> {
    pub value: T,
    pub effective_at_ns: U64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigView {
    pub tokens: Vec<AccountId>,
    pub pending_token: Option<Pending<AccountId>>,
    pub network_id: String,
    pub owner: AccountId,
    pub pending_owner: Option<AccountId>,
    pub invoice_key: PublicKey,
    pub pending_invoice_key: Option<Pending<PublicKey>>,
    pub fee_bps: u16,
    pub pending_fee: Option<Pending<u16>>,
    pub treasury: AccountId,
    pub pending_treasury: Option<Pending<AccountId>>,
    pub paused: bool,
}

fn pending_json<T>(w: &mut Writer, key: &str, p: &Option<Pending<T>>, value: impl Fn(&mut Writer, &T)) {
    w.key(key);
    match p {
        Some(p) => {
            w.raw("{").key("value");
            value(w, &p.value);
            w.u128("effective_at_ns", p.effective_at_ns.0 as u128).raw("}");
        }
        None => {
            w.null();
        }
    }
}

impl ConfigView {
    pub fn to_json(&self) -> String {
        let mut w = Writer::new();
        w.raw("{").key("tokens").raw("[");
        for t in &self.tokens {
            w.item().str(t.as_str());
        }
        w.raw("]");
        pending_json(&mut w, "pending_token", &self.pending_token, |w, v| {
            w.str(v.as_str());
        });
        w.key("network_id").str(&self.network_id).account("owner", &self.owner).key("pending_owner");
        match &self.pending_owner {
            Some(o) => w.str(o.as_str()),
            None => w.null(),
        };
        w.pk("invoice_key", &self.invoice_key);
        pending_json(&mut w, "pending_invoice_key", &self.pending_invoice_key, |w, v| {
            let s = v.to_string_repr();
            w.str(&s);
        });
        w.key("fee_bps").uint(self.fee_bps as u128);
        pending_json(&mut w, "pending_fee", &self.pending_fee, |w, v| {
            w.uint(*v as u128);
        });
        w.account("treasury", &self.treasury);
        pending_json(&mut w, "pending_treasury", &self.pending_treasury, |w, v| {
            w.str(v.as_str());
        });
        w.key("paused").bool(self.paused).raw("}");
        w.into_string()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObibaPay {
    token_list: Vec<AccountId>,
    pending_token: Option<Pending<AccountId>>,
    network_id: String,
    owner: AccountId,
    pending_owner: Option<AccountId>,
    invoice_key: PublicKey,
    pending_invoice_key: Option<Pending<PublicKey>>,
    fee_bps: u16,
    pending_fee: Option<Pending<u16>>,
    treasury: AccountId,
    pending_treasury: Option<Pending<AccountId>>,
    paused: bool,
    q_head: u64,
    q_tail: u64,
}

fn now() -> u64 {
    rt::now()
}

fn key(prefix: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut k = alloc::vec![prefix];
    for p in parts {
        k.extend_from_slice(p);
    }
    k
}

fn token_key(token: &AccountId) -> Vec<u8> {
    key(b't', &[token.as_str().as_bytes()])
}

fn merchant_key(merchant: &AccountId) -> Vec<u8> {
    key(b'm', &[merchant.as_str().as_bytes()])
}

fn paid_key(invoice_id: &str) -> Vec<u8> {
    key(b'p', &[invoice_id.as_bytes()])
}

fn queue_key(index: u64) -> Vec<u8> {
    key(b'q', &[&index.to_le_bytes()])
}

fn owed_key(token: &AccountId, merchant: &AccountId) -> Vec<u8> {
    key(b'w', &[token.as_str().as_bytes(), b":", merchant.as_str().as_bytes()])
}

fn fee_key(token: &AccountId) -> Vec<u8> {
    key(b'f', &[token.as_str().as_bytes()])
}

fn read_u128(k: &[u8]) -> u128 {
    rt::read(k).and_then(|v| v.as_slice().try_into().ok()).map(u128::from_le_bytes).unwrap_or(0)
}

fn write_u128(k: &[u8], v: u128) {
    if v == 0 {
        rt::remove(k);
    } else {
        rt::write(k, &v.to_le_bytes());
    }
}

fn event_obj(f: impl FnOnce(&mut Writer)) -> String {
    let mut w = Writer::new();
    w.raw("{");
    f(&mut w);
    w.raw("}");
    w.into_string()
}

fn ft_transfer(token: &AccountId, receiver: &AccountId, amount: u128, memo: &str) -> Promise {
    let mut args = Writer::new();
    args.raw("{").account("receiver_id", receiver).u128("amount", amount).key("memo").str(memo).raw("}");
    Promise::new(token).call("ft_transfer", args.0.as_bytes(), 1, GAS_FT_TRANSFER)
}

fn forward_args(token: &AccountId, merchant: &AccountId, amount: u128, invoice_id: &str) -> Vec<u8> {
    let mut w = BorshWriter::new();
    w.str(token.as_str()).str(merchant.as_str()).u128(amount).str(invoice_id);
    w.0
}

impl ObibaPay {
    pub fn new(tokens: Vec<AccountId>, network_id: String, owner: AccountId, invoice_key: PublicKey, fee_bps: u16, treasury: AccountId) -> Self {
        let me = rt::current_account();
        require(fee_bps <= MAX_FEE_BPS, "ERR_FEE_TOO_HIGH");
        require(ed25519_key(&invoice_key).is_some(), "ERR_KEY_NOT_ED25519");
        require(!network_id.is_empty() && network_id.len() <= 16, "ERR_NETWORK_ID");
        require(owner != me, "ERR_SELF_OWNER");
        require(!tokens.is_empty() && tokens.len() <= MAX_TOKENS, "ERR_TOKEN_COUNT");
        let mut token_list: Vec<AccountId> = Vec::new();
        for t in tokens {
            require(t != me, "ERR_SELF_TOKEN");
            require(!token_list.contains(&t), "ERR_TOKEN_DUPLICATE");
            rt::write(&token_key(&t), b"");
            token_list.push(t);
        }
        Self {
            token_list,
            pending_token: None,
            network_id,
            owner,
            pending_owner: None,
            invoice_key,
            pending_invoice_key: None,
            fee_bps,
            pending_fee: None,
            treasury,
            pending_treasury: None,
            paused: false,
            q_head: 0,
            q_tail: 0,
        }
    }

    pub fn on_forward(&mut self, token: AccountId, merchant: AccountId, amount: U128, invoice_id: String) {
        require(rt::results_count() == 1, "ERR_NOT_A_CALLBACK");
        if rt::result_bounded(0, 0).is_err() {
            let k = owed_key(&token, &merchant);
            let owed = read_u128(&k);
            write_u128(&k, owed.checked_add(amount.0).unwrap_or_else(|| rt::panic_str("owed overflow")));
            emit("forward_failed", &event_obj(|w| {
                w.account("token", &token).account("merchant", &merchant).u128("amount", amount.0).key("invoice_id").str(&invoice_id);
            }));
        }
    }

    pub fn retry_owed(&mut self, merchant: AccountId, token: AccountId) -> Promise {
        let k = owed_key(&token, &merchant);
        let amount = read_u128(&k);
        rt::remove(&k);
        require(amount > 0, "ERR_NOTHING_OWED");
        emit("owed_retry", &event_obj(|w| {
            w.account("token", &token).account("merchant", &merchant).u128("amount", amount);
        }));
        self.forward(token, merchant, amount, "retry")
    }

    pub fn propose_token(&mut self, token: AccountId) {
        self.assert_owner();
        require(token != rt::current_account(), "ERR_SELF_TOKEN");
        require(!rt::has(&token_key(&token)), "ERR_TOKEN_EXISTS");
        require(self.token_list.len() < MAX_TOKENS || self.token_list.contains(&token), "ERR_TOKEN_COUNT");
        let at = now() + OWNER_DELAY_NS;
        self.pending_token = Some(Pending { value: token.clone(), effective_at_ns: U64(at) });
        emit("token_proposed", &event_obj(|w| {
            w.account("token", &token).u128("effective_at_ns", at as u128);
        }));
    }

    pub fn apply_token(&mut self) {
        let p = self.pending_token.clone().unwrap_or_else(|| rt::panic_str("ERR_NOTHING_PENDING"));
        require(now() >= p.effective_at_ns.0, "ERR_NOT_READY");
        rt::write(&token_key(&p.value), b"");
        if !self.token_list.contains(&p.value) {
            self.token_list.push(p.value.clone());
        }
        self.pending_token = None;
        emit("token_enabled", &event_obj(|w| {
            w.account("token", &p.value);
        }));
    }

    pub fn disable_token(&mut self, token: AccountId) {
        self.assert_owner();
        rt::remove(&token_key(&token));
        emit("token_disabled", &event_obj(|w| {
            w.account("token", &token);
        }));
    }

    pub fn pause(&mut self) {
        self.assert_owner();
        self.paused = true;
        emit("paused", "{}");
    }

    pub fn unpause(&mut self) {
        self.assert_owner();
        self.paused = false;
        emit("unpaused", "{}");
    }

    pub fn register_merchant(&mut self, merchant: AccountId) {
        self.assert_owner();
        require(merchant != rt::current_account(), "ERR_SELF_MERCHANT");
        rt::write(&merchant_key(&merchant), b"");
        emit("merchant_registered", &event_obj(|w| {
            w.account("merchant", &merchant);
        }));
    }

    pub fn unregister_merchant(&mut self, merchant: AccountId) {
        self.assert_owner();
        rt::remove(&merchant_key(&merchant));
        emit("merchant_unregistered", &event_obj(|w| {
            w.account("merchant", &merchant);
        }));
    }

    pub fn propose_fee(&mut self, fee_bps: u16) {
        self.assert_owner();
        require(fee_bps <= MAX_FEE_BPS, "ERR_FEE_TOO_HIGH");
        let at = now() + OWNER_DELAY_NS;
        self.pending_fee = Some(Pending { value: fee_bps, effective_at_ns: U64(at) });
        emit("fee_proposed", &event_obj(|w| {
            w.key("fee_bps").uint(fee_bps as u128).u128("effective_at_ns", at as u128);
        }));
    }

    pub fn apply_fee(&mut self) {
        let p = self.pending_fee.clone().unwrap_or_else(|| rt::panic_str("ERR_NOTHING_PENDING"));
        require(now() >= p.effective_at_ns.0, "ERR_NOT_READY");
        self.fee_bps = p.value;
        self.pending_fee = None;
        emit("fee_applied", &event_obj(|w| {
            w.key("fee_bps").uint(p.value as u128);
        }));
    }

    pub fn propose_invoice_key(&mut self, invoice_key: PublicKey) {
        self.assert_owner();
        require(ed25519_key(&invoice_key).is_some(), "ERR_KEY_NOT_ED25519");
        let at = now() + OWNER_DELAY_NS;
        self.pending_invoice_key = Some(Pending { value: invoice_key.clone(), effective_at_ns: U64(at) });
        emit("invoice_key_proposed", &event_obj(|w| {
            w.pk("invoice_key", &invoice_key).u128("effective_at_ns", at as u128);
        }));
    }

    pub fn apply_invoice_key(&mut self) {
        let p = self.pending_invoice_key.clone().unwrap_or_else(|| rt::panic_str("ERR_NOTHING_PENDING"));
        require(now() >= p.effective_at_ns.0, "ERR_NOT_READY");
        self.invoice_key = p.value.clone();
        self.pending_invoice_key = None;
        emit("invoice_key_applied", &event_obj(|w| {
            w.pk("invoice_key", &p.value);
        }));
    }

    pub fn propose_treasury(&mut self, treasury: AccountId) {
        self.assert_owner();
        let at = now() + OWNER_DELAY_NS;
        self.pending_treasury = Some(Pending { value: treasury.clone(), effective_at_ns: U64(at) });
        emit("treasury_proposed", &event_obj(|w| {
            w.account("treasury", &treasury).u128("effective_at_ns", at as u128);
        }));
    }

    pub fn apply_treasury(&mut self) {
        let p = self.pending_treasury.clone().unwrap_or_else(|| rt::panic_str("ERR_NOTHING_PENDING"));
        require(now() >= p.effective_at_ns.0, "ERR_NOT_READY");
        self.treasury = p.value.clone();
        self.pending_treasury = None;
        emit("treasury_applied", &event_obj(|w| {
            w.account("treasury", &p.value);
        }));
    }

    pub fn withdraw_fees(&mut self, token: AccountId, amount: U128) -> Promise {
        self.assert_owner();
        let k = fee_key(&token);
        let accrued = read_u128(&k);
        require(amount.0 > 0 && amount.0 <= accrued, "ERR_FEE_AMOUNT");
        write_u128(&k, accrued - amount.0);
        emit("fees_withdrawn", &event_obj(|w| {
            w.account("token", &token).u128("amount", amount.0).account("treasury", &self.treasury);
        }));
        let mut cb = BorshWriter::new();
        cb.str(token.as_str()).u128(amount.0);
        ft_transfer(&token, &self.treasury, amount.0, "obiba:fees")
            .then(&rt::current_account())
            .call("on_fee_withdraw", &cb.0, 0, GAS_CALLBACK)
    }

    pub fn on_fee_withdraw(&mut self, token: AccountId, amount: U128) {
        require(rt::results_count() == 1, "ERR_NOT_A_CALLBACK");
        if rt::result_bounded(0, 0).is_err() {
            let k = fee_key(&token);
            let accrued = read_u128(&k);
            write_u128(&k, accrued.checked_add(amount.0).unwrap_or_else(|| rt::panic_str("fee overflow")));
            emit("fee_withdraw_failed", &event_obj(|w| {
                w.account("token", &token).u128("amount", amount.0);
            }));
        }
    }

    pub fn propose_owner(&mut self, new_owner: AccountId) {
        self.assert_owner();
        self.pending_owner = Some(new_owner.clone());
        emit("owner_proposed", &event_obj(|w| {
            w.account("new_owner", &new_owner);
        }));
    }

    pub fn accept_owner(&mut self) {
        rt::assert_one_yocto();
        let pending = self.pending_owner.clone().unwrap_or_else(|| rt::panic_str("ERR_NOTHING_PENDING"));
        require(rt::predecessor() == pending, "ERR_NOT_PENDING_OWNER");
        self.owner = pending.clone();
        self.pending_owner = None;
        emit("owner_accepted", &event_obj(|w| {
            w.account("owner", &pending);
        }));
    }

    pub fn prune(&mut self, max: u32) -> u32 {
        let t = now();
        let mut removed = 0;
        for _ in 0..max.min(100) {
            if self.q_head >= self.q_tail {
                break;
            }
            let qk = queue_key(self.q_head);
            let Some(entry) = rt::read(&qk) else {
                self.q_head += 1;
                continue;
            };
            let mut r = ByteReader::new(&entry);
            let (Some(after), Some(id)) = (r.u64(), r.string()) else {
                self.q_head += 1;
                continue;
            };
            if after > t {
                break;
            }
            rt::remove(&qk);
            rt::remove(&paid_key(&id));
            self.q_head += 1;
            removed += 1;
        }
        removed
    }

    pub fn get_config(&self) -> ConfigView {
        ConfigView {
            tokens: self.token_list.iter().filter(|t| rt::has(&token_key(t))).cloned().collect(),
            pending_token: self.pending_token.clone(),
            network_id: self.network_id.clone(),
            owner: self.owner.clone(),
            pending_owner: self.pending_owner.clone(),
            invoice_key: self.invoice_key.clone(),
            pending_invoice_key: self.pending_invoice_key.clone(),
            fee_bps: self.fee_bps,
            pending_fee: self.pending_fee.clone(),
            treasury: self.treasury.clone(),
            pending_treasury: self.pending_treasury.clone(),
            paused: self.paused,
        }
    }

    pub fn get_paid(&self, invoice_id: String) -> Option<PaidRecord> {
        rt::read(&paid_key(&invoice_id)).and_then(|b| PaidRecord::decode(&b))
    }

    pub fn get_owed(&self, merchant: AccountId, token: AccountId) -> U128 {
        U128(read_u128(&owed_key(&token, &merchant)))
    }

    pub fn get_accrued_fees(&self, token: AccountId) -> U128 {
        U128(read_u128(&fee_key(&token)))
    }

    pub fn is_merchant(&self, account: AccountId) -> bool {
        rt::has(&merchant_key(&account))
    }

    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> PromiseOrValue<U128> {
        let token = rt::predecessor();
        require(rt::has(&token_key(&token)), "ERR_TOKEN_NOT_ACCEPTED");
        match self.check_invoice(&token, &amount, &msg) {
            Err(reason) => {
                emit("invoice_rejected", &event_obj(|w| {
                    w.account("payer", &sender_id).u128("amount", amount.0).key("reason").str(reason);
                }));
                PromiseOrValue::Value(amount)
            }
            Ok(signed) => {
                let invoice = signed.invoice;
                let fee = amount.0.checked_mul(u128::from(self.fee_bps)).unwrap_or_else(|| rt::panic_str("fee overflow")) / 10_000;
                let net = amount.0 - fee;
                let record = PaidRecord {
                    payer: sender_id.clone(),
                    merchant: invoice.merchant.clone(),
                    token: token.clone(),
                    amount,
                    fee: U128(fee),
                    paid_at_ns: U64(now()),
                };
                rt::write(&paid_key(&invoice.invoice_id), &record.encode());
                let mut entry = BorshWriter::new();
                entry.u64(invoice.expires_at_ns.0 + PAID_RETENTION_NS).str(&invoice.invoice_id);
                rt::write(&queue_key(self.q_tail), &entry.0);
                self.q_tail += 1;
                let fk = fee_key(&token);
                let accrued = read_u128(&fk);
                write_u128(&fk, accrued.checked_add(fee).unwrap_or_else(|| rt::panic_str("fee overflow")));
                emit("invoice_paid", &event_obj(|w| {
                    w.key("invoice_id").str(&invoice.invoice_id).account("payer", &sender_id).account("merchant", &invoice.merchant);
                    w.account("token", &token).u128("amount", amount.0).u128("fee", fee);
                }));
                if net > 0 {
                    self.forward(token, invoice.merchant, net, &invoice.invoice_id).detach();
                }
                PromiseOrValue::Value(U128(0))
            }
        }
    }

    fn assert_owner(&self) {
        rt::assert_one_yocto();
        require(rt::predecessor() == self.owner, "ERR_NOT_OWNER");
    }

    fn check_invoice(&self, token: &AccountId, amount: &U128, msg: &str) -> Result<SignedInvoice, &'static str> {
        if self.paused {
            return Err("paused");
        }
        if msg.len() > MAX_MSG_LEN {
            return Err("msg_too_long");
        }
        let signed = SignedInvoice::parse(msg.as_bytes()).map_err(|_| "msg_invalid")?;
        let invoice = &signed.invoice;
        if !is_hex_id(&invoice.invoice_id) {
            return Err("invoice_id_invalid");
        }
        if invoice.reference.as_ref().is_some_and(|r| r.len() > MAX_MEMO_LEN) {
            return Err("reference_too_long");
        }
        let signature = signature_bytes(&signed.signature).ok_or("signature_invalid")?;
        let key = ed25519_key(&self.invoice_key).ok_or("key_invalid")?;
        let digest = rt::sha256_array(&invoice_preimage(&self.network_id, &rt::current_account(), invoice));
        if !rt::verify_ed25519(&signature, &digest, &key) {
            return Err("signature_invalid");
        }
        if !rt::has(&merchant_key(&invoice.merchant)) {
            return Err("merchant_not_registered");
        }
        if now() >= invoice.expires_at_ns.0 {
            return Err("expired");
        }
        if rt::has(&paid_key(&invoice.invoice_id)) {
            return Err("already_paid");
        }
        if invoice.token != *token {
            return Err("token_mismatch");
        }
        if invoice.amount != *amount {
            return Err("amount_mismatch");
        }
        if invoice.fee_bps != self.fee_bps {
            return Err("fee_mismatch");
        }
        Ok(signed)
    }

    fn forward(&self, token: AccountId, merchant: AccountId, amount: u128, invoice_id: &str) -> Promise {
        let mut memo = String::from("obiba-invoice:");
        memo.push_str(invoice_id);
        ft_transfer(&token, &merchant, amount, &memo)
            .then(&rt::current_account())
            .call("on_forward", &forward_args(&token, &merchant, amount, invoice_id), 0, GAS_CALLBACK)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = BorshWriter::new();
        w.var(self.token_list.len() as u128);
        for t in &self.token_list {
            w.short(t.as_str());
        }
        match &self.pending_token {
            Some(p) => w.u8(1).short(p.value.as_str()).u64(p.effective_at_ns.0),
            None => w.u8(0),
        };
        w.short(&self.network_id).short(self.owner.as_str());
        match &self.pending_owner {
            Some(o) => w.u8(1).short(o.as_str()),
            None => w.u8(0),
        };
        w.bytes(self.invoice_key.as_bytes());
        match &self.pending_invoice_key {
            Some(p) => w.u8(1).bytes(p.value.as_bytes()).u64(p.effective_at_ns.0),
            None => w.u8(0),
        };
        w.u16(self.fee_bps);
        match &self.pending_fee {
            Some(p) => w.u8(1).u16(p.value).u64(p.effective_at_ns.0),
            None => w.u8(0),
        };
        w.short(self.treasury.as_str());
        match &self.pending_treasury {
            Some(p) => w.u8(1).short(p.value.as_str()).u64(p.effective_at_ns.0),
            None => w.u8(0),
        };
        w.u8(self.paused as u8).u64(self.q_head).u64(self.q_tail);
        w.0
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut r = ByteReader::new(b);
        let count = r.var()? as usize;
        let mut token_list = Vec::with_capacity(count);
        for _ in 0..count {
            token_list.push(AccountId::from_trusted(r.short()?));
        }
        let pending_token = match r.u8()? {
            0 => None,
            _ => Some(Pending { value: AccountId::from_trusted(r.short()?), effective_at_ns: U64(r.u64()?) }),
        };
        let network_id = r.short()?;
        let owner = AccountId::from_trusted(r.short()?);
        let pending_owner = match r.u8()? {
            0 => None,
            _ => Some(AccountId::from_trusted(r.short()?)),
        };
        let invoice_key = PublicKey::from_bytes(r.bytes()?)?;
        let pending_invoice_key = match r.u8()? {
            0 => None,
            _ => Some(Pending { value: PublicKey::from_bytes(r.bytes()?)?, effective_at_ns: U64(r.u64()?) }),
        };
        let fee_bps = u16::from_le_bytes(r.take(2)?.try_into().ok()?);
        let pending_fee = match r.u8()? {
            0 => None,
            _ => Some(Pending { value: u16::from_le_bytes(r.take(2)?.try_into().ok()?), effective_at_ns: U64(r.u64()?) }),
        };
        let treasury = AccountId::from_trusted(r.short()?);
        let pending_treasury = match r.u8()? {
            0 => None,
            _ => Some(Pending { value: AccountId::from_trusted(r.short()?), effective_at_ns: U64(r.u64()?) }),
        };
        let paused = r.bool()?;
        let q_head = r.u64()?;
        let q_tail = r.u64()?;
        r.done().then_some(Self {
            token_list,
            pending_token,
            network_id,
            owner,
            pending_owner,
            invoice_key,
            pending_invoice_key,
            fee_bps,
            pending_fee,
            treasury,
            pending_treasury,
            paused,
            q_head,
            q_tail,
        })
    }
}

fn load() -> ObibaPay {
    let bytes = rt::read(STATE_KEY).unwrap_or_else(|| rt::panic_str("The contract is not initialized"));
    ObibaPay::decode(&bytes).unwrap_or_else(|| rt::panic_str("ERR_STATE"))
}

fn save(c: &ObibaPay) {
    rt::write(STATE_KEY, &c.encode());
}

fn args<T>(f: impl FnOnce(&mut Reader) -> R<T>) -> T {
    let input = rt::input_bytes();
    let mut r = Reader::new(&input);
    f(&mut r).and_then(|v| r.end().map(|_| v)).unwrap_or_else(|_| rt::bad_args())
}

fn one<T>(field: &str, f: impl Fn(&mut Reader) -> R<T>) -> T {
    args(|r| {
        let mut v = None;
        r.object(|r, k| if k == field { set(&mut v, f(r)) } else { Ok(false) })?;
        v.ok_or(())
    })
}

fn two<A, B>(fa: &str, a: impl Fn(&mut Reader) -> R<A>, fb: &str, b: impl Fn(&mut Reader) -> R<B>) -> (A, B) {
    args(|r| {
        let (mut va, mut vb) = (None, None);
        r.object(|r, k| {
            if k == fa {
                set(&mut va, a(r))
            } else if k == fb {
                set(&mut vb, b(r))
            } else {
                Ok(false)
            }
        })?;
        Ok((va.ok_or(())?, vb.ok_or(())?))
    })
}

fn mutate<T>(method: &str, payable: bool, f: impl FnOnce(&mut ObibaPay) -> T) -> T {
    if !payable {
        rt::assert_no_deposit(method);
    }
    let mut c = load();
    let out = f(&mut c);
    save(&c);
    out
}

fn account(r: &mut Reader) -> R<AccountId> {
    r.account()
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn new() {
    rt::assert_no_deposit("new");
    require(!rt::has(STATE_KEY), "The contract has already been initialized");
    let (tokens, network, owner, key, fee, treasury) = args(|r| {
        let (mut tokens, mut network, mut owner, mut key, mut fee, mut treasury) = (None, None, None, None, None, None);
        r.object(|r, k| match k {
            "tokens" => {
                let mut list = Vec::new();
                let res = r.array(|r| {
                    list.push(r.account()?);
                    Ok(())
                });
                set(&mut tokens, res.map(|_| list))
            }
            "network_id" => set(&mut network, r.string()),
            "owner" => set(&mut owner, r.account()),
            "invoice_key" => set(&mut key, r.public_key()),
            "fee_bps" => set(&mut fee, r.uint(u16::MAX as u128).map(|v| v as u16)),
            "treasury" => set(&mut treasury, r.account()),
            _ => Ok(false),
        })?;
        Ok((tokens.ok_or(())?, network.ok_or(())?, owner.ok_or(())?, key.ok_or(())?, fee.ok_or(())?, treasury.ok_or(())?))
    });
    save(&ObibaPay::new(tokens, network, owner, key, fee, treasury));
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn on_forward() {
    rt::assert_private("on_forward");
    let input = rt::input_bytes();
    let mut r = ByteReader::new(&input);
    let parsed = (|| {
        let token = AccountId::parse_str(&r.string()?)?;
        let merchant = AccountId::parse_str(&r.string()?)?;
        let amount = r.u128()?;
        let id = r.string()?;
        r.done().then_some((token, merchant, amount, id))
    })();
    let (token, merchant, amount, id) = parsed.unwrap_or_else(|| rt::bad_args());
    mutate("on_forward", false, |c| c.on_forward(token, merchant, U128(amount), id));
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn on_fee_withdraw() {
    rt::assert_private("on_fee_withdraw");
    let input = rt::input_bytes();
    let mut r = ByteReader::new(&input);
    let parsed = (|| {
        let token = AccountId::parse_str(&r.string()?)?;
        let amount = r.u128()?;
        r.done().then_some((token, amount))
    })();
    let (token, amount) = parsed.unwrap_or_else(|| rt::bad_args());
    mutate("on_fee_withdraw", false, |c| c.on_fee_withdraw(token, U128(amount)));
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn retry_owed() {
    let (merchant, token) = two("merchant", account, "token", account);
    mutate("retry_owed", false, |c| c.retry_owed(merchant, token)).as_return();
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn propose_token() {
    let token = one("token", account);
    mutate("propose_token", true, |c| c.propose_token(token));
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn apply_token() {
    mutate("apply_token", false, |c| c.apply_token());
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn disable_token() {
    let token = one("token", account);
    mutate("disable_token", true, |c| c.disable_token(token));
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn pause() {
    mutate("pause", true, |c| c.pause());
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn unpause() {
    mutate("unpause", true, |c| c.unpause());
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn register_merchant() {
    let merchant = one("merchant", account);
    mutate("register_merchant", true, |c| c.register_merchant(merchant));
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn unregister_merchant() {
    let merchant = one("merchant", account);
    mutate("unregister_merchant", true, |c| c.unregister_merchant(merchant));
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn propose_fee() {
    let fee = one("fee_bps", |r| r.uint(u16::MAX as u128).map(|v| v as u16));
    mutate("propose_fee", true, |c| c.propose_fee(fee));
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn apply_fee() {
    mutate("apply_fee", false, |c| c.apply_fee());
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn propose_invoice_key() {
    let key = one("invoice_key", |r| r.public_key());
    mutate("propose_invoice_key", true, |c| c.propose_invoice_key(key));
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn apply_invoice_key() {
    mutate("apply_invoice_key", false, |c| c.apply_invoice_key());
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn propose_treasury() {
    let treasury = one("treasury", account);
    mutate("propose_treasury", true, |c| c.propose_treasury(treasury));
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn apply_treasury() {
    mutate("apply_treasury", false, |c| c.apply_treasury());
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn withdraw_fees() {
    let (token, amount) = two("token", account, "amount", |r| r.u128_str());
    mutate("withdraw_fees", true, |c| c.withdraw_fees(token, amount)).as_return();
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn propose_owner() {
    let owner = one("new_owner", account);
    mutate("propose_owner", true, |c| c.propose_owner(owner));
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn accept_owner() {
    mutate("accept_owner", true, |c| c.accept_owner());
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn prune() {
    let max = one("max", |r| r.uint(u32::MAX as u128).map(|v| v as u32));
    let removed = mutate("prune", false, |c| c.prune(max));
    let mut w = Writer::new();
    w.uint(removed as u128);
    rt::ret(w.0.as_bytes());
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn ft_on_transfer() {
    let (sender, amount, msg) = args(|r| {
        let (mut sender, mut amount, mut msg) = (None, None, None);
        r.object(|r, k| match k {
            "sender_id" => set(&mut sender, r.account()),
            "amount" => set(&mut amount, r.u128_str()),
            "msg" => set(&mut msg, r.string()),
            _ => Ok(false),
        })?;
        Ok((sender.ok_or(())?, amount.ok_or(())?, msg.ok_or(())?))
    });
    match mutate("ft_on_transfer", false, |c| c.ft_on_transfer(sender, amount, msg)) {
        PromiseOrValue::Promise(p) => p.as_return(),
        PromiseOrValue::Value(v) => {
            let mut w = Writer::new();
            w.quoted(v.0);
            rt::ret(w.0.as_bytes());
        }
    }
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn get_config() {
    rt::ret(load().get_config().to_json().as_bytes());
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn get_paid() {
    let id = one("invoice_id", |r| r.string());
    let out = load().get_paid(id).map(|p| p.to_json()).unwrap_or_else(|| String::from("null"));
    rt::ret(out.as_bytes());
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn get_owed() {
    let (merchant, token) = two("merchant", account, "token", account);
    let mut w = Writer::new();
    w.quoted(load().get_owed(merchant, token).0);
    rt::ret(w.0.as_bytes());
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn get_accrued_fees() {
    let token = one("token", account);
    let mut w = Writer::new();
    w.quoted(load().get_accrued_fees(token).0);
    rt::ret(w.0.as_bytes());
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn is_merchant() {
    let a = one("account", account);
    let mut w = Writer::new();
    w.bool(load().is_merchant(a));
    rt::ret(w.0.as_bytes());
}

#[cfg(test)]
mod tests;
