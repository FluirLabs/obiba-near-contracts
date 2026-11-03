#![cfg_attr(target_arch = "wasm32", no_std)]
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use obiba_common::codec::{hex_decode, BorshWriter, ByteReader};
use obiba_common::json::{set, set_opt, Reader, Writer, R};
use obiba_common::rt::{self, require, Promise};
use obiba_common::{
    ed25519_key, emit, guardian_preimage, is_hex_id, signature_bytes, usd_units, AccountId, Base64VecU8, Borsh,
    FreezePayload, KeyPayload, LimitPayload, NoncePayload, Op, OpKind, PublicKey, Purpose, SignedInvoice, SpendWindow,
    TokenConfig, TokenPayload, HOUR_NS, MAX_MEMO_LEN, MAX_TOKENS, MAX_TOKEN_DECIMALS, U128, U64,
};

const TGAS: u64 = 1_000_000_000_000;
pub const GAS_FT_TRANSFER: u64 = 15 * TGAS;
pub const GAS_FT_TRANSFER_CALL: u64 = 100 * TGAS;
pub const GAS_OP_CALLBACK: u64 = 15 * TGAS;
pub const GAS_KEYS_CALLBACK: u64 = 10 * TGAS;
pub const MAX_OP_TTL_NS: u64 = HOUR_NS;
pub const RAISE_DELAY_NS: u64 = 24 * HOUR_NS;
pub const RECOVERY_DELAY_NS: u64 = 48 * HOUR_NS;
pub const MAX_FREEZE_NS: u64 = 72 * HOUR_NS;
pub const FREEZE_COOLDOWN_NS: u64 = 7 * 24 * HOUR_NS;
pub const GUARDIAN_CHANGE_DELAY_NS: u64 = 7 * 24 * HOUR_NS;
pub const MAX_DEVICES: usize = 5;
pub const MAX_INVOICE_MSG_LEN: usize = 1024;
pub const MAX_NETWORK_ID_LEN: usize = 16;
pub const DEVICE_ALLOWANCE: u128 = 250_000_000_000_000_000_000_000;
pub const DEVICE_METHODS: &str = "execute,pay_invoice,set_limit,cancel_recovery,unfreeze,add_device,remove_device,propose_guardian,rotate_guardian,add_token,disable_token";
const STATE_KEY: &[u8] = b"s";
const SEC_NS: u64 = 1_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpStatus {
    Pending,
    Done,
    Failed,
}

impl OpStatus {
    fn name(self) -> &'static str {
        match self {
            OpStatus::Pending => "Pending",
            OpStatus::Done => "Done",
            OpStatus::Failed => "Failed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpView {
    pub status: OpStatus,
    pub cosigned: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecentOp {
    pub id: [u8; 16],
    pub expires_s: u64,
    pub status: OpStatus,
    pub cosigned: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpCallback {
    pub op_id: String,
    pub kind: OpKind,
    pub token: AccountId,
    pub amount: u128,
    pub counted_usd: u128,
    pub decimals: u8,
    pub spent_hour: u64,
    pub cosigned: bool,
}

impl OpCallback {
    fn encode(&self) -> Vec<u8> {
        let mut w = BorshWriter::new();
        w.str(&self.op_id).u8(self.kind as u8).str(self.token.as_str()).u128(self.amount).u128(self.counted_usd);
        w.u8(self.decimals).u64(self.spent_hour).u8(self.cosigned as u8);
        w.0
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut r = ByteReader::new(b);
        let v = OpCallback {
            op_id: r.string()?,
            kind: OpKind::from_u8(r.u8()?)?,
            token: AccountId::parse_str(&r.string()?)?,
            amount: r.u128()?,
            counted_usd: r.u128()?,
            decimals: r.u8()?,
            spent_hour: r.u64()?,
            cosigned: r.bool()?,
        };
        r.done().then_some(v)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recovery {
    pub new_key: PublicKey,
    pub executable_at_ns: U64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingLimit {
    pub new_limit: U128,
    pub effective_at_ns: U64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardianChange {
    pub new_guardian: PublicKey,
    pub effective_at_ns: U64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenInit {
    pub token: AccountId,
    pub decimals: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenView {
    pub token: AccountId,
    pub decimals: u8,
    pub enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyView {
    pub tokens: Vec<TokenView>,
    pub pay_contract: AccountId,
    pub network_id: String,
    pub guardian: PublicKey,
    pub guardian_nonce: U64,
    pub devices: Vec<PublicKey>,
    pub daily_limit: U128,
    pub effective_daily_limit: U128,
    pub pending_limit: Option<PendingLimit>,
    pub max_op_amount: U128,
    pub spent_24h: U128,
    pub frozen_until_ns: U64,
    pub last_freeze_start_ns: U64,
    pub recovery: Option<Recovery>,
    pub guardian_change: Option<GuardianChange>,
}

impl PolicyView {
    pub fn to_json(&self) -> String {
        let mut w = Writer::new();
        w.raw("{").key("tokens").raw("[");
        for t in &self.tokens {
            w.item().raw("{").account("token", &t.token).key("decimals").uint(t.decimals as u128);
            w.key("enabled").bool(t.enabled).raw("}");
        }
        w.raw("]").account("pay_contract", &self.pay_contract).key("network_id").str(&self.network_id);
        w.pk("guardian", &self.guardian).u128("guardian_nonce", self.guardian_nonce.0 as u128);
        w.key("devices").raw("[");
        for d in &self.devices {
            let s = d.to_string_repr();
            w.item().str(&s);
        }
        w.raw("]").u128("daily_limit", self.daily_limit.0).u128("effective_daily_limit", self.effective_daily_limit.0);
        w.key("pending_limit");
        match &self.pending_limit {
            Some(p) => w.raw("{").u128("new_limit", p.new_limit.0).u128("effective_at_ns", p.effective_at_ns.0 as u128).raw("}"),
            None => w.null(),
        };
        w.u128("max_op_amount", self.max_op_amount.0).u128("spent_24h", self.spent_24h.0);
        w.u128("frozen_until_ns", self.frozen_until_ns.0 as u128).u128("last_freeze_start_ns", self.last_freeze_start_ns.0 as u128);
        w.key("recovery");
        match &self.recovery {
            Some(r) => w.raw("{").pk("new_key", &r.new_key).u128("executable_at_ns", r.executable_at_ns.0 as u128).raw("}"),
            None => w.null(),
        };
        w.key("guardian_change");
        match &self.guardian_change {
            Some(g) => w.raw("{").pk("new_guardian", &g.new_guardian).u128("effective_at_ns", g.effective_at_ns.0 as u128).raw("}"),
            None => w.null(),
        };
        w.raw("}");
        w.into_string()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObibaAccount {
    tokens: Vec<(AccountId, TokenConfig)>,
    pay_contract: AccountId,
    network_id: String,
    guardian: PublicKey,
    guardian_nonce: u64,
    devices: Vec<PublicKey>,
    daily_limit: u128,
    max_op_amount: u128,
    pending_limit: Option<PendingLimit>,
    window: SpendWindow,
    recent: Vec<RecentOp>,
    frozen_until_ns: u64,
    last_freeze_start_ns: u64,
    recovery: Option<Recovery>,
    guardian_change: Option<GuardianChange>,
}

fn now() -> u64 {
    rt::now()
}

fn require_ed25519(key: &PublicKey) {
    require(ed25519_key(key).is_some(), "ERR_KEY_NOT_ED25519");
}

fn key32(key: &PublicKey) -> [u8; 32] {
    ed25519_key(key).unwrap_or_else(|| rt::panic_str("ERR_KEY_NOT_ED25519"))
}

fn event_obj(f: impl FnOnce(&mut Writer)) -> String {
    let mut w = Writer::new();
    w.raw("{");
    f(&mut w);
    w.raw("}");
    w.into_string()
}

fn op_memo(op: &Op) -> String {
    let mut memo = String::from("obiba:");
    memo.push_str(&op.op_id);
    if let Some(m) = &op.memo {
        memo.push(':');
        memo.push_str(m);
    }
    memo
}

fn op_key(op_id: &str) -> [u8; 16] {
    let bytes = hex_decode(op_id).unwrap_or_else(|| rt::panic_str("ERR_OP_ID"));
    bytes.as_slice().try_into().unwrap_or_else(|_| rt::panic_str("ERR_OP_ID"))
}

impl ObibaAccount {
    pub fn new(
        tokens: Vec<TokenInit>,
        pay_contract: AccountId,
        network_id: String,
        guardian: PublicKey,
        device: PublicKey,
        daily_limit: U128,
        max_op_amount: U128,
    ) -> Self {
        let me = rt::current_account();
        require(me.get_parent_account_id() == Some(rt::predecessor().as_str()), "ERR_ONLY_PARENT_CAN_INIT");
        require(!network_id.is_empty() && network_id.len() <= MAX_NETWORK_ID_LEN, "ERR_NETWORK_ID");
        require_ed25519(&guardian);
        require_ed25519(&device);
        require(guardian != device, "ERR_GUARDIAN_IS_DEVICE");
        require(max_op_amount.0 > 0, "ERR_MAX_OP_AMOUNT");
        require(daily_limit.0 <= max_op_amount.0, "ERR_LIMIT_ABOVE_MAX_OP");
        require(pay_contract != me, "ERR_SELF_REFERENCE");
        require(!tokens.is_empty() && tokens.len() <= MAX_TOKENS, "ERR_TOKEN_COUNT");
        let mut registry: Vec<(AccountId, TokenConfig)> = Vec::with_capacity(tokens.len());
        for t in tokens {
            require(t.decimals <= MAX_TOKEN_DECIMALS, "ERR_TOKEN_DECIMALS");
            require(t.token != me && t.token != pay_contract, "ERR_SELF_REFERENCE");
            require(!registry.iter().any(|(id, _)| *id == t.token), "ERR_TOKEN_DUPLICATE");
            registry.push((t.token, TokenConfig { decimals: t.decimals, enabled: true }));
        }
        Self {
            tokens: registry,
            pay_contract,
            network_id,
            guardian,
            guardian_nonce: 0,
            devices: alloc::vec![device],
            daily_limit: daily_limit.0,
            max_op_amount: max_op_amount.0,
            pending_limit: None,
            window: SpendWindow::default(),
            recent: Vec::new(),
            frozen_until_ns: 0,
            last_freeze_start_ns: 0,
            recovery: None,
            guardian_change: None,
        }
    }

    pub fn execute(&mut self, op: Op, guardian_sig: Option<Base64VecU8>) -> Promise {
        self.assert_device();
        self.assert_not_frozen();
        self.prune();
        require(op.receiver != rt::current_account(), "ERR_SELF_TRANSFER");
        let callback = self.admit(&op, OpKind::Transfer, guardian_sig.as_ref());
        let mut args = Writer::new();
        args.raw("{").account("receiver_id", &op.receiver).u128("amount", op.amount.0).key("memo").str(&op_memo(&op)).raw("}");
        Promise::new(&op.token)
            .call("ft_transfer", args.0.as_bytes(), 1, GAS_FT_TRANSFER)
            .then(&rt::current_account())
            .call("on_op_result", &callback.encode(), 0, GAS_OP_CALLBACK)
    }

    pub fn pay_invoice(&mut self, op: Op, invoice: SignedInvoice, guardian_sig: Option<Base64VecU8>) -> Promise {
        self.assert_device();
        self.assert_not_frozen();
        self.prune();
        require(op.receiver == self.pay_contract, "ERR_RECEIVER_NOT_PAY_CONTRACT");
        require(op.amount == invoice.invoice.amount, "ERR_INVOICE_AMOUNT");
        require(op.token == invoice.invoice.token, "ERR_INVOICE_TOKEN");
        require(self.enabled_token(&op.token).is_some(), "ERR_TOKEN_NOT_ENABLED");
        require(op.memo.as_deref() == Some(invoice.invoice.invoice_id.as_str()), "ERR_INVOICE_NOT_BOUND_TO_OP");
        require(invoice.invoice.expires_at_ns.0 > now(), "ERR_INVOICE_EXPIRED");
        let msg = invoice.to_json();
        require(msg.len() <= MAX_INVOICE_MSG_LEN, "ERR_INVOICE_TOO_LONG");
        let callback = self.admit(&op, OpKind::PayInvoice, guardian_sig.as_ref());
        let mut args = Writer::new();
        args.raw("{").account("receiver_id", &op.receiver).u128("amount", op.amount.0).key("memo").str(&op_memo(&op));
        args.key("msg").str(&msg).raw("}");
        Promise::new(&op.token)
            .call("ft_transfer_call", args.0.as_bytes(), 1, GAS_FT_TRANSFER_CALL)
            .then(&rt::current_account())
            .call("on_op_result", &callback.encode(), 0, GAS_OP_CALLBACK)
    }

    pub fn on_op_result(&mut self, cb: OpCallback) {
        require(rt::results_count() == 1, "ERR_NOT_A_CALLBACK");
        let id = op_key(&cb.op_id);
        let Some(index) = self.recent.iter().position(|r| r.id == id) else {
            emit("op_result_orphaned", &event_obj(|w| {
                w.key("op_id").str(&cb.op_id);
            }));
            return;
        };
        if self.recent[index].status != OpStatus::Pending {
            return;
        }
        self.window.roll(SpendWindow::hour_of(now()));
        let amount = cb.amount;
        let used = match rt::result_bounded(0, 64) {
            Err(_) => 0,
            Ok(bytes) => match cb.kind {
                OpKind::Transfer => amount,
                OpKind::PayInvoice => parse_used(&bytes).map(|u| u.min(amount)).unwrap_or(amount),
            },
        };
        let used_usd = usd_units(used, cb.decimals).unwrap_or(cb.counted_usd);
        self.window.release(cb.counted_usd.saturating_sub(used_usd), cb.spent_hour);
        self.recent[index].status = if used == 0 { OpStatus::Failed } else { OpStatus::Done };
        let event = if used == 0 { "op_failed" } else { "op_executed" };
        emit(event, &event_obj(|w| {
            w.key("op_id").str(&cb.op_id).key("kind").str(cb.kind.name()).account("token", &cb.token);
            w.u128("amount", amount).u128("used", used).key("cosigned").bool(cb.cosigned);
        }));
    }

    pub fn set_limit(&mut self, new_limit: U128, guardian_sig: Option<Base64VecU8>, guardian_nonce: Option<U64>) {
        self.assert_device();
        let current = self.apply_pending_limit();
        if new_limit.0 <= current {
            self.daily_limit = new_limit.0;
            self.pending_limit = None;
            emit("limit_lowered", &event_obj(|w| {
                w.u128("new_limit", new_limit.0);
            }));
            return;
        }
        self.assert_not_frozen();
        require(new_limit.0 <= self.max_op_amount.saturating_mul(24), "ERR_LIMIT_TOO_HIGH");
        let nonce = guardian_nonce.unwrap_or_else(|| rt::panic_str("ERR_GUARDIAN_REQUIRED"));
        let sig = guardian_sig.unwrap_or_else(|| rt::panic_str("ERR_GUARDIAN_REQUIRED"));
        self.verify_guardian(Purpose::RaiseLimit, &LimitPayload { new_limit, guardian_nonce: nonce }, &sig);
        self.take_nonce(nonce);
        let effective_at = now() + RAISE_DELAY_NS;
        self.pending_limit = Some(PendingLimit { new_limit, effective_at_ns: U64(effective_at) });
        emit("limit_raise_scheduled", &event_obj(|w| {
            w.u128("new_limit", new_limit.0).u128("effective_at_ns", effective_at as u128);
        }));
    }

    pub fn add_device(&mut self, public_key: PublicKey, guardian_sig: Base64VecU8, guardian_nonce: U64) -> Promise {
        self.assert_device();
        self.assert_not_frozen();
        require_ed25519(&public_key);
        require(public_key != self.guardian, "ERR_GUARDIAN_IS_DEVICE");
        require(!self.devices.contains(&public_key), "ERR_DEVICE_EXISTS");
        require(self.devices.len() < MAX_DEVICES, "ERR_TOO_MANY_DEVICES");
        self.verify_guardian(Purpose::AddDevice, &KeyPayload { public_key: public_key.clone(), guardian_nonce }, &guardian_sig);
        self.take_nonce(guardian_nonce);
        let previous = self.devices.clone();
        self.devices.push(public_key.clone());
        emit("device_added", &event_obj(|w| {
            w.pk("public_key", &public_key);
        }));
        let recovery = self.recovery.clone();
        add_device_key(Promise::new(&rt::current_account()), &public_key).then(&rt::current_account()).call(
            "on_keys_result",
            &encode_keys(&previous, &recovery),
            0,
            GAS_KEYS_CALLBACK,
        )
    }

    pub fn remove_device(&mut self, public_key: PublicKey, guardian_sig: Base64VecU8, guardian_nonce: U64) -> Promise {
        self.assert_device();
        require(self.devices.contains(&public_key), "ERR_UNKNOWN_DEVICE");
        require(self.devices.len() > 1, "ERR_LAST_DEVICE");
        self.verify_guardian(Purpose::RemoveDevice, &KeyPayload { public_key: public_key.clone(), guardian_nonce }, &guardian_sig);
        self.take_nonce(guardian_nonce);
        let previous = self.devices.clone();
        self.devices.retain(|d| d != &public_key);
        emit("device_removed", &event_obj(|w| {
            w.pk("public_key", &public_key);
        }));
        let recovery = self.recovery.clone();
        Promise::new(&rt::current_account())
            .delete_key(&public_key)
            .then(&rt::current_account())
            .call("on_keys_result", &encode_keys(&previous, &recovery), 0, GAS_KEYS_CALLBACK)
    }

    pub fn begin_recovery(&mut self, new_key: PublicKey, guardian_sig: Base64VecU8, guardian_nonce: U64) {
        require_ed25519(&new_key);
        require(new_key != self.guardian, "ERR_GUARDIAN_IS_DEVICE");
        require(self.recovery.is_none(), "ERR_RECOVERY_ACTIVE");
        self.verify_guardian(Purpose::BeginRecovery, &KeyPayload { public_key: new_key.clone(), guardian_nonce }, &guardian_sig);
        self.take_nonce(guardian_nonce);
        let executable_at = now() + RECOVERY_DELAY_NS;
        self.recovery = Some(Recovery { new_key: new_key.clone(), executable_at_ns: U64(executable_at) });
        emit("recovery_started", &event_obj(|w| {
            w.pk("new_key", &new_key).u128("executable_at_ns", executable_at as u128);
        }));
    }

    pub fn cancel_recovery(&mut self) {
        self.assert_device();
        require(self.recovery.take().is_some(), "ERR_NO_RECOVERY");
        emit("recovery_cancelled", "{}");
    }

    pub fn complete_recovery(&mut self) -> Promise {
        let recovery = self.recovery.clone().unwrap_or_else(|| rt::panic_str("ERR_NO_RECOVERY"));
        require(now() >= recovery.executable_at_ns.0, "ERR_RECOVERY_NOT_READY");
        let previous = self.devices.clone();
        let mut promise = Promise::new(&rt::current_account());
        for device in previous.iter().filter(|d| **d != recovery.new_key) {
            promise = promise.delete_key(device);
        }
        if !previous.contains(&recovery.new_key) {
            promise = add_device_key(promise, &recovery.new_key);
        }
        self.devices = alloc::vec![recovery.new_key.clone()];
        self.recovery = None;
        emit("recovery_completed", &event_obj(|w| {
            w.pk("new_key", &recovery.new_key);
        }));
        promise.then(&rt::current_account()).call("on_keys_result", &encode_keys(&previous, &Some(recovery)), 0, GAS_KEYS_CALLBACK)
    }

    pub fn on_keys_result(&mut self, previous_devices: Vec<PublicKey>, previous_recovery: Option<Recovery>) {
        require(rt::results_count() == 1, "ERR_NOT_A_CALLBACK");
        if rt::result_bounded(0, 0).is_err() {
            self.devices = previous_devices;
            self.recovery = previous_recovery;
            emit("keys_change_reverted", "{}");
        }
    }

    pub fn freeze(&mut self, until_ns: U64, guardian_sig: Base64VecU8, guardian_nonce: U64) {
        let t = now();
        require(until_ns.0 > t && until_ns.0 <= t + MAX_FREEZE_NS, "ERR_FREEZE_WINDOW");
        require(self.last_freeze_start_ns == 0 || t >= self.last_freeze_start_ns + FREEZE_COOLDOWN_NS, "ERR_FREEZE_COOLDOWN");
        self.verify_guardian(Purpose::Freeze, &FreezePayload { until_ns, guardian_nonce }, &guardian_sig);
        self.take_nonce(guardian_nonce);
        self.frozen_until_ns = until_ns.0;
        self.last_freeze_start_ns = t;
        emit("frozen", &event_obj(|w| {
            w.u128("until_ns", until_ns.0 as u128);
        }));
    }

    pub fn unfreeze(&mut self, guardian_sig: Base64VecU8, guardian_nonce: U64) {
        self.assert_device();
        self.verify_guardian(Purpose::Unfreeze, &NoncePayload { guardian_nonce }, &guardian_sig);
        self.take_nonce(guardian_nonce);
        self.frozen_until_ns = 0;
        emit("unfrozen", "{}");
    }

    pub fn rotate_guardian(&mut self, new_guardian: PublicKey, guardian_sig: Base64VecU8, guardian_nonce: U64) {
        self.assert_device();
        require_ed25519(&new_guardian);
        require(!self.devices.contains(&new_guardian), "ERR_GUARDIAN_IS_DEVICE");
        self.verify_guardian(Purpose::RotateGuardian, &KeyPayload { public_key: new_guardian.clone(), guardian_nonce }, &guardian_sig);
        self.take_nonce(guardian_nonce);
        self.guardian = new_guardian.clone();
        self.guardian_change = None;
        emit("guardian_rotated", &event_obj(|w| {
            w.pk("new_guardian", &new_guardian);
        }));
    }

    pub fn propose_guardian(&mut self, new_guardian: PublicKey) {
        self.assert_device();
        require_ed25519(&new_guardian);
        require(!self.devices.contains(&new_guardian), "ERR_GUARDIAN_IS_DEVICE");
        let effective_at = now() + GUARDIAN_CHANGE_DELAY_NS;
        self.guardian_change = Some(GuardianChange { new_guardian: new_guardian.clone(), effective_at_ns: U64(effective_at) });
        emit("guardian_change_proposed", &event_obj(|w| {
            w.pk("new_guardian", &new_guardian).u128("effective_at_ns", effective_at as u128);
        }));
    }

    pub fn veto_guardian_change(&mut self, guardian_sig: Base64VecU8, guardian_nonce: U64) {
        let change = self.guardian_change.clone().unwrap_or_else(|| rt::panic_str("ERR_NO_GUARDIAN_CHANGE"));
        self.verify_guardian(Purpose::VetoGuardianChange, &KeyPayload { public_key: change.new_guardian, guardian_nonce }, &guardian_sig);
        self.take_nonce(guardian_nonce);
        self.guardian_change = None;
        emit("guardian_change_vetoed", "{}");
    }

    pub fn apply_guardian_change(&mut self) {
        let change = self.guardian_change.clone().unwrap_or_else(|| rt::panic_str("ERR_NO_GUARDIAN_CHANGE"));
        require(now() >= change.effective_at_ns.0, "ERR_GUARDIAN_CHANGE_NOT_READY");
        self.guardian = change.new_guardian.clone();
        self.guardian_change = None;
        emit("guardian_change_applied", &event_obj(|w| {
            w.pk("new_guardian", &change.new_guardian);
        }));
    }

    pub fn add_token(&mut self, token: AccountId, decimals: u8, guardian_sig: Base64VecU8, guardian_nonce: U64) {
        self.assert_device();
        require(decimals <= MAX_TOKEN_DECIMALS, "ERR_TOKEN_DECIMALS");
        require(token != rt::current_account() && token != self.pay_contract, "ERR_SELF_REFERENCE");
        if let Some((_, existing)) = self.tokens.iter().find(|(id, _)| *id == token) {
            require(existing.decimals == decimals, "ERR_TOKEN_DECIMALS_IMMUTABLE");
        } else {
            require(self.tokens.len() < MAX_TOKENS, "ERR_TOKEN_COUNT");
        }
        self.verify_guardian(Purpose::AddToken, &TokenPayload { token: token.clone(), decimals, guardian_nonce }, &guardian_sig);
        self.take_nonce(guardian_nonce);
        match self.tokens.iter_mut().find(|(id, _)| *id == token) {
            Some((_, cfg)) => *cfg = TokenConfig { decimals, enabled: true },
            None => self.tokens.push((token.clone(), TokenConfig { decimals, enabled: true })),
        }
        emit("token_enabled", &event_obj(|w| {
            w.account("token", &token).key("decimals").uint(decimals as u128);
        }));
    }

    pub fn disable_token(&mut self, token: AccountId) {
        self.assert_device();
        let cfg = self
            .tokens
            .iter_mut()
            .find(|(id, _)| *id == token)
            .map(|(_, c)| c)
            .unwrap_or_else(|| rt::panic_str("ERR_UNKNOWN_TOKEN"));
        cfg.enabled = false;
        emit("token_disabled", &event_obj(|w| {
            w.account("token", &token);
        }));
    }

    pub fn get_policy(&self) -> PolicyView {
        let t = now();
        let effective = match &self.pending_limit {
            Some(p) if t >= p.effective_at_ns.0 => p.new_limit.0,
            _ => self.daily_limit,
        };
        let mut window = self.window.clone();
        window.roll(SpendWindow::hour_of(t));
        PolicyView {
            tokens: self
                .tokens
                .iter()
                .map(|(id, c)| TokenView { token: id.clone(), decimals: c.decimals, enabled: c.enabled })
                .collect(),
            pay_contract: self.pay_contract.clone(),
            network_id: self.network_id.clone(),
            guardian: self.guardian.clone(),
            guardian_nonce: U64(self.guardian_nonce),
            devices: self.devices.clone(),
            daily_limit: U128(self.daily_limit),
            effective_daily_limit: U128(effective),
            pending_limit: self.pending_limit.clone(),
            max_op_amount: U128(self.max_op_amount),
            spent_24h: U128(window.spent()),
            frozen_until_ns: U64(self.frozen_until_ns),
            last_freeze_start_ns: U64(self.last_freeze_start_ns),
            recovery: self.recovery.clone(),
            guardian_change: self.guardian_change.clone(),
        }
    }

    pub fn get_op(&self, op_id: String) -> Option<OpView> {
        let id: [u8; 16] = hex_decode(&op_id)?.as_slice().try_into().ok()?;
        self.recent.iter().find(|r| r.id == id).map(|r| OpView { status: r.status, cosigned: r.cosigned })
    }

    fn assert_device(&self) {
        require(rt::predecessor() == rt::current_account(), "ERR_DEVICE_ONLY");
    }

    fn assert_not_frozen(&self) {
        require(now() >= self.frozen_until_ns, "ERR_FROZEN");
    }

    fn verify_guardian<T: Borsh>(&self, purpose: Purpose, payload: &T, sig: &Base64VecU8) {
        let preimage = guardian_preimage(&self.network_id, &rt::current_account(), purpose, payload);
        let digest = rt::sha256_array(&preimage);
        let signature = signature_bytes(sig).unwrap_or_else(|| rt::panic_str("ERR_BAD_SIGNATURE_LENGTH"));
        let key = key32(&self.guardian);
        require(rt::verify_ed25519(&signature, &digest, &key), "ERR_BAD_GUARDIAN_SIGNATURE");
    }

    fn enabled_token(&self, token: &AccountId) -> Option<TokenConfig> {
        self.tokens.iter().find(|(id, c)| id == token && c.enabled).map(|(_, c)| *c)
    }

    fn take_nonce(&mut self, nonce: U64) {
        require(nonce.0 == self.guardian_nonce, "ERR_GUARDIAN_NONCE");
        self.guardian_nonce += 1;
    }

    fn apply_pending_limit(&mut self) -> u128 {
        if let Some(p) = &self.pending_limit {
            if now() >= p.effective_at_ns.0 {
                self.daily_limit = p.new_limit.0;
                self.pending_limit = None;
            }
        }
        self.daily_limit
    }

    fn admit(&mut self, op: &Op, kind: OpKind, guardian_sig: Option<&Base64VecU8>) -> OpCallback {
        let t = now();
        let amount = op.amount.0;
        require(op.kind == kind, "ERR_OP_KIND");
        require(op.token != rt::current_account(), "ERR_TOKEN");
        require(is_hex_id(&op.op_id), "ERR_OP_ID");
        require(amount > 0, "ERR_ZERO_AMOUNT");
        let token = self.enabled_token(&op.token);
        let (counted_usd, decimals) = match token {
            Some(cfg) => {
                let usd = usd_units(amount, cfg.decimals).unwrap_or_else(|| rt::panic_str("ERR_AMOUNT_OVERFLOW"));
                require(usd <= self.max_op_amount, "ERR_ABOVE_MAX_OP_AMOUNT");
                (usd, cfg.decimals)
            }
            None => (0, 0),
        };
        require(op.expires_at_ns.0 > t, "ERR_OP_EXPIRED");
        require(op.expires_at_ns.0 <= t + MAX_OP_TTL_NS, "ERR_OP_TTL");
        require(op.memo.as_ref().is_none_or(|m| m.len() <= MAX_MEMO_LEN), "ERR_MEMO_TOO_LONG");
        let id = op_key(&op.op_id);
        require(!self.recent.iter().any(|r| r.id == id), "ERR_OP_REPLAY");
        let hour = SpendWindow::hour_of(t);
        self.window.roll(hour);
        let limit = self.apply_pending_limit();
        let over_limit = token.is_none() || self.window.spent().checked_add(counted_usd).is_none_or(|total| total > limit);
        if over_limit {
            let sig = guardian_sig.unwrap_or_else(|| rt::panic_str("ERR_GUARDIAN_REQUIRED"));
            self.verify_guardian(Purpose::ExecuteOp, op, sig);
        }
        self.window.add(counted_usd);
        self.recent.push(RecentOp { id, expires_s: op.expires_at_ns.0.div_ceil(SEC_NS), status: OpStatus::Pending, cosigned: over_limit });
        emit("op_submitted", &event_obj(|w| {
            w.key("op_id").str(&op.op_id).key("kind").str(kind.name()).account("token", &op.token);
            w.account("receiver", &op.receiver).u128("amount", amount).u128("usd", counted_usd).key("cosigned").bool(over_limit);
        }));
        OpCallback {
            op_id: op.op_id.clone(),
            kind,
            token: op.token.clone(),
            amount,
            counted_usd,
            decimals,
            spent_hour: hour,
            cosigned: over_limit,
        }
    }

    fn prune(&mut self) {
        let t = now();
        self.recent.retain(|r| r.status == OpStatus::Pending || r.expires_s.saturating_mul(SEC_NS) > t);
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = BorshWriter::new();
        w.var(self.tokens.len() as u128);
        for (id, cfg) in &self.tokens {
            w.short(id.as_str()).u8(cfg.decimals).u8(cfg.enabled as u8);
        }
        w.short(self.pay_contract.as_str()).short(&self.network_id).raw(&key32(&self.guardian)).var(self.guardian_nonce as u128);
        w.var(self.devices.len() as u128);
        for d in &self.devices {
            w.raw(&key32(d));
        }
        w.var(self.daily_limit).var(self.max_op_amount);
        match &self.pending_limit {
            Some(p) => w.u8(1).var(p.new_limit.0).var(p.effective_at_ns.0 as u128),
            None => w.u8(0),
        };
        w.var(self.window.hour.0 as u128).var(self.window.entries.len() as u128);
        for (h, a) in &self.window.entries {
            w.var(*h as u128).var(*a);
        }
        w.var(self.recent.len() as u128);
        for r in &self.recent {
            w.raw(&r.id).var(r.expires_s as u128).u8(r.status as u8 | (r.cosigned as u8) << 2);
        }
        w.var(self.frozen_until_ns as u128).var(self.last_freeze_start_ns as u128);
        match &self.recovery {
            Some(r) => w.u8(1).raw(&key32(&r.new_key)).var(r.executable_at_ns.0 as u128),
            None => w.u8(0),
        };
        match &self.guardian_change {
            Some(g) => w.u8(1).raw(&key32(&g.new_guardian)).var(g.effective_at_ns.0 as u128),
            None => w.u8(0),
        };
        w.0
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut r = ByteReader::new(b);
        let count = r.var()? as usize;
        let mut tokens = Vec::with_capacity(count);
        for _ in 0..count {
            let id = AccountId::from_trusted(r.short()?);
            tokens.push((id, TokenConfig { decimals: r.u8()?, enabled: r.bool()? }));
        }
        let pay_contract = AccountId::from_trusted(r.short()?);
        let network_id = r.short()?;
        let guardian = PublicKey::ed25519(r.arr32()?);
        let guardian_nonce = r.var64()?;
        let count = r.var()? as usize;
        let mut devices = Vec::with_capacity(count);
        for _ in 0..count {
            devices.push(PublicKey::ed25519(r.arr32()?));
        }
        let daily_limit = r.var()?;
        let max_op_amount = r.var()?;
        let pending_limit = match r.u8()? {
            0 => None,
            _ => Some(PendingLimit { new_limit: U128(r.var()?), effective_at_ns: U64(r.var64()?) }),
        };
        let hour = U64(r.var64()?);
        let count = r.var()? as usize;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push((r.var64()?, r.var()?));
        }
        let count = r.var()? as usize;
        let mut recent = Vec::with_capacity(count);
        for _ in 0..count {
            let id: [u8; 16] = r.take(16)?.try_into().ok()?;
            let expires_s = r.var64()?;
            let flags = r.u8()?;
            let status = match flags & 3 {
                0 => OpStatus::Pending,
                1 => OpStatus::Done,
                2 => OpStatus::Failed,
                _ => return None,
            };
            recent.push(RecentOp { id, expires_s, status, cosigned: flags & 4 != 0 });
        }
        let frozen_until_ns = r.var64()?;
        let last_freeze_start_ns = r.var64()?;
        let recovery = match r.u8()? {
            0 => None,
            _ => Some(Recovery { new_key: PublicKey::ed25519(r.arr32()?), executable_at_ns: U64(r.var64()?) }),
        };
        let guardian_change = match r.u8()? {
            0 => None,
            _ => Some(GuardianChange { new_guardian: PublicKey::ed25519(r.arr32()?), effective_at_ns: U64(r.var64()?) }),
        };
        if !r.done() {
            return None;
        }
        Some(Self {
            tokens,
            pay_contract,
            network_id,
            guardian,
            guardian_nonce,
            devices,
            daily_limit,
            max_op_amount,
            pending_limit,
            window: SpendWindow { entries, hour },
            recent,
            frozen_until_ns,
            last_freeze_start_ns,
            recovery,
            guardian_change,
        })
    }
}

fn parse_used(bytes: &[u8]) -> Option<u128> {
    let mut r = Reader::new(bytes);
    let v = r.u128_str().ok()?;
    r.end().ok()?;
    Some(v.0)
}

fn add_device_key(promise: Promise, key: &PublicKey) -> Promise {
    promise.add_key(key, DEVICE_ALLOWANCE, &rt::current_account(), DEVICE_METHODS)
}

fn encode_keys(devices: &[PublicKey], recovery: &Option<Recovery>) -> Vec<u8> {
    let mut w = BorshWriter::new();
    w.var(devices.len() as u128);
    for d in devices {
        w.raw(&key32(d));
    }
    match recovery {
        Some(r) => w.u8(1).raw(&key32(&r.new_key)).u64(r.executable_at_ns.0),
        None => w.u8(0),
    };
    w.0
}

pub fn decode_keys(b: &[u8]) -> Option<(Vec<PublicKey>, Option<Recovery>)> {
    let mut r = ByteReader::new(b);
    let count = r.var()? as usize;
    let mut devices = Vec::with_capacity(count);
    for _ in 0..count {
        devices.push(PublicKey::ed25519(r.arr32()?));
    }
    let recovery = match r.u8()? {
        0 => None,
        _ => Some(Recovery { new_key: PublicKey::ed25519(r.arr32()?), executable_at_ns: U64(r.u64()?) }),
    };
    r.done().then_some((devices, recovery))
}

fn load() -> ObibaAccount {
    let bytes = rt::read(STATE_KEY).unwrap_or_else(|| rt::panic_str("The contract is not initialized"));
    ObibaAccount::decode(&bytes).unwrap_or_else(|| rt::panic_str("ERR_STATE"))
}

fn save(c: &ObibaAccount) {
    rt::write(STATE_KEY, &c.encode());
}

fn args<T>(f: impl FnOnce(&mut Reader) -> R<T>) -> T {
    let input = rt::input_bytes();
    let mut r = Reader::new(&input);
    f(&mut r).and_then(|v| r.end().map(|_| v)).unwrap_or_else(|_| rt::bad_args())
}

fn mutate<T>(method: &str, f: impl FnOnce(&mut ObibaAccount) -> T) -> T {
    rt::assert_no_deposit(method);
    let mut c = load();
    let out = f(&mut c);
    save(&c);
    out
}

fn guardian_args(r: &mut Reader, extra: &str, mut on_extra: impl FnMut(&mut Reader) -> R<bool>) -> R<(Base64VecU8, U64)> {
    let (mut sig, mut nonce) = (None, None);
    r.object(|r, k| match k {
        "guardian_sig" => set(&mut sig, r.base64()),
        "guardian_nonce" => set(&mut nonce, r.u64_str()),
        k if k == extra => on_extra(r),
        _ => Ok(false),
    })?;
    Ok((sig.ok_or(())?, nonce.ok_or(())?))
}

fn key_and_guardian(field: &str) -> (PublicKey, Base64VecU8, U64) {
    args(|r| {
        let mut key = None;
        let (sig, nonce) = guardian_args(r, field, |r| set(&mut key, r.public_key()))?;
        Ok((key.ok_or(())?, sig, nonce))
    })
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn new() {
    rt::assert_no_deposit("new");
    require(!rt::has(STATE_KEY), "The contract has already been initialized");
    let (tokens, pay, network, guardian, device, daily, max_op) = args(|r| {
        let (mut tokens, mut pay, mut network, mut guardian, mut device, mut daily, mut max_op) = (None, None, None, None, None, None, None);
        r.object(|r, k| match k {
            "tokens" => {
                let mut list = Vec::new();
                let res = r.array(|r| {
                    let (mut token, mut decimals) = (None, None);
                    r.object(|r, k| match k {
                        "token" => set(&mut token, r.account()),
                        "decimals" => set(&mut decimals, r.uint(u8::MAX as u128).map(|v| v as u8)),
                        _ => Ok(false),
                    })?;
                    list.push(TokenInit { token: token.ok_or(())?, decimals: decimals.ok_or(())? });
                    Ok(())
                });
                set(&mut tokens, res.map(|_| list))
            }
            "pay_contract" => set(&mut pay, r.account()),
            "network_id" => set(&mut network, r.string()),
            "guardian" => set(&mut guardian, r.public_key()),
            "device" => set(&mut device, r.public_key()),
            "daily_limit" => set(&mut daily, r.u128_str()),
            "max_op_amount" => set(&mut max_op, r.u128_str()),
            _ => Ok(false),
        })?;
        Ok((tokens.ok_or(())?, pay.ok_or(())?, network.ok_or(())?, guardian.ok_or(())?, device.ok_or(())?, daily.ok_or(())?, max_op.ok_or(())?))
    });
    save(&ObibaAccount::new(tokens, pay, network, guardian, device, daily, max_op));
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn execute() {
    let (op, sig) = args(|r| {
        let (mut op, mut sig) = (None, None);
        r.object(|r, k| match k {
            "op" => set(&mut op, Op::read(r)),
            "guardian_sig" => set_opt(&mut sig, r.opt(|r| r.base64())),
            _ => Ok(false),
        })?;
        Ok((op.ok_or(())?, sig.flatten()))
    });
    mutate("execute", |c| c.execute(op, sig)).as_return();
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn pay_invoice() {
    let (op, invoice, sig) = args(|r| {
        let (mut op, mut invoice, mut sig) = (None, None, None);
        r.object(|r, k| match k {
            "op" => set(&mut op, Op::read(r)),
            "invoice" => set(&mut invoice, SignedInvoice::read(r)),
            "guardian_sig" => set_opt(&mut sig, r.opt(|r| r.base64())),
            _ => Ok(false),
        })?;
        Ok((op.ok_or(())?, invoice.ok_or(())?, sig.flatten()))
    });
    mutate("pay_invoice", |c| c.pay_invoice(op, invoice, sig)).as_return();
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn on_op_result() {
    rt::assert_private("on_op_result");
    let cb = OpCallback::decode(&rt::input_bytes()).unwrap_or_else(|| rt::bad_args());
    mutate("on_op_result", |c| c.on_op_result(cb));
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn set_limit() {
    let (limit, sig, nonce) = args(|r| {
        let (mut limit, mut sig, mut nonce) = (None, None, None);
        r.object(|r, k| match k {
            "new_limit" => set(&mut limit, r.u128_str()),
            "guardian_sig" => set_opt(&mut sig, r.opt(|r| r.base64())),
            "guardian_nonce" => set_opt(&mut nonce, r.opt(|r| r.u64_str())),
            _ => Ok(false),
        })?;
        Ok((limit.ok_or(())?, sig.flatten(), nonce.flatten()))
    });
    mutate("set_limit", |c| c.set_limit(limit, sig, nonce));
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn add_device() {
    let (key, sig, nonce) = key_and_guardian("public_key");
    mutate("add_device", |c| c.add_device(key, sig, nonce)).as_return();
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn remove_device() {
    let (key, sig, nonce) = key_and_guardian("public_key");
    mutate("remove_device", |c| c.remove_device(key, sig, nonce)).as_return();
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn begin_recovery() {
    let (key, sig, nonce) = key_and_guardian("new_key");
    mutate("begin_recovery", |c| c.begin_recovery(key, sig, nonce));
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn cancel_recovery() {
    mutate("cancel_recovery", |c| c.cancel_recovery());
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn complete_recovery() {
    mutate("complete_recovery", |c| c.complete_recovery()).as_return();
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn on_keys_result() {
    rt::assert_private("on_keys_result");
    let (devices, recovery) = decode_keys(&rt::input_bytes()).unwrap_or_else(|| rt::bad_args());
    mutate("on_keys_result", |c| c.on_keys_result(devices, recovery));
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn freeze() {
    let (until, sig, nonce) = args(|r| {
        let mut until = None;
        let (sig, nonce) = guardian_args(r, "until_ns", |r| set(&mut until, r.u64_str()))?;
        Ok((until.ok_or(())?, sig, nonce))
    });
    mutate("freeze", |c| c.freeze(until, sig, nonce));
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn unfreeze() {
    let (sig, nonce) = args(|r| guardian_args(r, "", |_| Ok(false)));
    mutate("unfreeze", |c| c.unfreeze(sig, nonce));
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn rotate_guardian() {
    let (key, sig, nonce) = key_and_guardian("new_guardian");
    mutate("rotate_guardian", |c| c.rotate_guardian(key, sig, nonce));
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn propose_guardian() {
    let key = args(|r| {
        let mut key = None;
        r.object(|r, k| match k {
            "new_guardian" => set(&mut key, r.public_key()),
            _ => Ok(false),
        })?;
        key.ok_or(())
    });
    mutate("propose_guardian", |c| c.propose_guardian(key));
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn veto_guardian_change() {
    let (sig, nonce) = args(|r| guardian_args(r, "", |_| Ok(false)));
    mutate("veto_guardian_change", |c| c.veto_guardian_change(sig, nonce));
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn apply_guardian_change() {
    mutate("apply_guardian_change", |c| c.apply_guardian_change());
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn add_token() {
    let (token, decimals, sig, nonce) = args(|r| {
        let (mut token, mut decimals, mut sig, mut nonce) = (None, None, None, None);
        r.object(|r, k| match k {
            "token" => set(&mut token, r.account()),
            "decimals" => set(&mut decimals, r.uint(u8::MAX as u128).map(|v| v as u8)),
            "guardian_sig" => set(&mut sig, r.base64()),
            "guardian_nonce" => set(&mut nonce, r.u64_str()),
            _ => Ok(false),
        })?;
        Ok((token.ok_or(())?, decimals.ok_or(())?, sig.ok_or(())?, nonce.ok_or(())?))
    });
    mutate("add_token", |c| c.add_token(token, decimals, sig, nonce));
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn disable_token() {
    let token = args(|r| {
        let mut token = None;
        r.object(|r, k| match k {
            "token" => set(&mut token, r.account()),
            _ => Ok(false),
        })?;
        token.ok_or(())
    });
    mutate("disable_token", |c| c.disable_token(token));
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn get_policy() {
    rt::ret(load().get_policy().to_json().as_bytes());
}

#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C-unwind" fn get_op() {
    let op_id = args(|r| {
        let mut id = None;
        r.object(|r, k| match k {
            "op_id" => set(&mut id, r.string()),
            _ => Ok(false),
        })?;
        id.ok_or(())
    });
    let out = match load().get_op(op_id) {
        Some(v) => event_obj(|w| {
            w.key("status").str(v.status.name()).key("cosigned").bool(v.cosigned);
        }),
        None => String::from("null"),
    };
    rt::ret(out.as_bytes());
}

#[cfg(test)]
mod tests;
