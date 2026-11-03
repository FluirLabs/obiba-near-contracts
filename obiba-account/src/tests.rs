use super::*;
use ed25519_dalek::{Signer, SigningKey};
use near_sdk::mock::MockAction;
use near_sdk::test_utils::{get_created_receipts, get_logs, VMContextBuilder};
use near_sdk::{testing_env, NearToken, PromiseResult, RuntimeFeesConfig};
use obiba_common::{CurveType, Invoice, TokenPayload, HOUR_NS};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::HashMap;

const T0: u64 = 1_800_000_000 * 1_000_000_000;
const LIMIT: u128 = 50_000_000;
const MAX_OP: u128 = 500_000_000;

thread_local! {
    static CALLBACKS: RefCell<HashMap<String, OpCallback>> = RefCell::new(HashMap::new());
}

fn id(s: &str) -> AccountId {
    s.parse().unwrap()
}
fn sdk(a: &AccountId) -> near_sdk::AccountId {
    a.as_str().parse().unwrap()
}
fn me() -> AccountId {
    id("u-test.obiba.near")
}
fn parent() -> AccountId {
    id("obiba.near")
}
fn usdc() -> AccountId {
    id("usdc.near")
}
fn pay() -> AccountId {
    id("pay.obiba.near")
}
fn alice() -> AccountId {
    id("alice.near")
}
fn guardian_key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}
fn other_key() -> SigningKey {
    SigningKey::from_bytes(&[3u8; 32])
}
fn pk(key: &SigningKey) -> PublicKey {
    PublicKey::from_parts(CurveType::ED25519, key.verifying_key().to_bytes().to_vec()).unwrap()
}
fn device_pk() -> PublicKey {
    pk(&SigningKey::from_bytes(&[1u8; 32]))
}

fn ctx(predecessor: AccountId, ts: u64) -> VMContextBuilder {
    let mut b = VMContextBuilder::new();
    b.current_account_id(sdk(&me()))
        .predecessor_account_id(sdk(&predecessor))
        .signer_account_id(sdk(&predecessor))
        .block_timestamp(ts)
        .account_balance(NearToken::from_near(1));
    b
}

fn set(predecessor: AccountId, ts: u64) {
    testing_env!(ctx(predecessor, ts).build());
}

fn set_result(ts: u64, result: PromiseResult) {
    testing_env!(
        ctx(me(), ts).build(),
        near_sdk::test_vm_config(),
        RuntimeFeesConfig::test(),
        Default::default(),
        vec![result]
    );
}

fn calls(method: &str) -> Vec<(String, Vec<u8>)> {
    let mut out = vec![];
    for r in get_created_receipts() {
        for a in r.actions {
            if let MockAction::FunctionCallWeight { method_name, args, .. } = a {
                if method_name == method.as_bytes() {
                    out.push((r.receiver_id.to_string(), args));
                }
            }
        }
    }
    out
}

fn track(_p: Promise) {
    for (_, args) in calls("on_op_result") {
        let cb = OpCallback::decode(&args).unwrap();
        CALLBACKS.with(|m| m.borrow_mut().insert(cb.op_id.clone(), cb));
    }
}

fn cb(n: u8) -> OpCallback {
    CALLBACKS.with(|m| m.borrow().get(&format!("{:032x}", n)).cloned()).expect("callback was scheduled")
}

fn setup() -> ObibaAccount {
    CALLBACKS.with(|m| m.borrow_mut().clear());
    set(parent(), T0);
    ObibaAccount::new(
        vec![TokenInit { token: usdc(), decimals: 6 }],
        pay(),
        "mainnet".into(),
        pk(&guardian_key()),
        device_pk(),
        U128(LIMIT),
        U128(MAX_OP),
    )
}

fn sign_as<T: Borsh>(key: &SigningKey, network: &str, account: &AccountId, purpose: Purpose, payload: &T) -> Base64VecU8 {
    let preimage = obiba_common::guardian_preimage(network, account, purpose, payload);
    let digest = Sha256::digest(&preimage);
    Base64VecU8(key.sign(&digest).to_bytes().to_vec())
}

fn gsign<T: Borsh>(purpose: Purpose, payload: &T) -> Base64VecU8 {
    sign_as(&guardian_key(), "mainnet", &me(), purpose, payload)
}

fn op(n: u8, amount: u128, ts: u64) -> Op {
    Op {
        op_id: format!("{:032x}", n),
        kind: OpKind::Transfer,
        token: usdc(),
        receiver: alice(),
        amount: U128(amount),
        expires_at_ns: U64(ts + 10 * 60 * 1_000_000_000),
        memo: None,
    }
}

fn spent(c: &ObibaAccount) -> u128 {
    c.get_policy().spent_24h.0
}

#[test]
fn init_by_parent_records_policy() {
    let c = setup();
    let p = c.get_policy();
    assert_eq!(p.devices, vec![device_pk()]);
    assert_eq!(p.daily_limit.0, LIMIT);
    assert_eq!(p.guardian_nonce.0, 0);
}

#[test]
#[should_panic(expected = "ERR_ONLY_PARENT_CAN_INIT")]
fn init_by_stranger_panics() {
    set(alice(), T0);
    ObibaAccount::new(vec![TokenInit { token: usdc(), decimals: 6 }], pay(), "mainnet".into(), pk(&guardian_key()), device_pk(), U128(LIMIT), U128(MAX_OP));
}

#[test]
#[should_panic(expected = "ERR_LIMIT_ABOVE_MAX_OP")]
fn init_rejects_limit_above_max_op() {
    set(parent(), T0);
    ObibaAccount::new(vec![TokenInit { token: usdc(), decimals: 6 }], pay(), "mainnet".into(), pk(&guardian_key()), device_pk(), U128(MAX_OP + 1), U128(MAX_OP));
}

#[test]
#[should_panic(expected = "ERR_GUARDIAN_IS_DEVICE")]
fn init_rejects_guardian_equal_to_device() {
    set(parent(), T0);
    ObibaAccount::new(vec![TokenInit { token: usdc(), decimals: 6 }], pay(), "mainnet".into(), device_pk(), device_pk(), U128(LIMIT), U128(MAX_OP));
}

#[test]
fn execute_within_limit_schedules_transfer_and_records_op() {
    let mut c = setup();
    set(me(), T0);
    track(c.execute(op(1, 10_000_000, T0), None));
    let rec = c.get_op(format!("{:032x}", 1)).unwrap();
    assert_eq!(rec.status, OpStatus::Pending);
    assert!(!rec.cosigned);
    assert_eq!(spent(&c), 10_000_000);
    assert!(get_logs().iter().any(|l| l.contains("op_submitted")));
    assert!(!get_created_receipts().is_empty());
}

#[test]
#[should_panic(expected = "ERR_DEVICE_ONLY")]
fn execute_from_other_account_panics() {
    let mut c = setup();
    set(alice(), T0);
    track(c.execute(op(1, 1, T0), None));
}

#[test]
#[should_panic(expected = "ERR_GUARDIAN_REQUIRED")]
fn over_limit_without_guardian_panics() {
    let mut c = setup();
    set(me(), T0);
    track(c.execute(op(1, 40_000_000, T0), None));
    track(c.execute(op(2, 10_000_001, T0), None));
}

#[test]
fn exactly_at_limit_needs_no_guardian() {
    let mut c = setup();
    set(me(), T0);
    track(c.execute(op(1, 40_000_000, T0), None));
    track(c.execute(op(2, 10_000_000, T0), None));
    assert_eq!(spent(&c), LIMIT);
}

#[test]
fn over_limit_with_guardian_signature_succeeds() {
    let mut c = setup();
    set(me(), T0);
    let o = op(1, 200_000_000, T0);
    let sig = gsign(Purpose::ExecuteOp, &o);
    track(c.execute(o.clone(), Some(sig)));
    assert!(c.get_op(o.op_id).unwrap().cosigned);
}

fn assert_rejected_sig(sig: Base64VecU8, o: Op) {
    let mut c = setup();
    set(me(), T0);
    track(c.execute(o, Some(sig)));
}

#[test]
#[should_panic(expected = "ERR_BAD_GUARDIAN_SIGNATURE")]
fn guardian_signature_for_another_op_is_rejected() {
    let signed = op(1, 200_000_000, T0);
    let mut submitted = signed.clone();
    submitted.receiver = "mallory.near".parse().unwrap();
    assert_rejected_sig(gsign(Purpose::ExecuteOp, &signed), submitted);
}

#[test]
#[should_panic(expected = "ERR_BAD_GUARDIAN_SIGNATURE")]
fn guardian_signature_for_another_account_is_rejected() {
    let o = op(1, 200_000_000, T0);
    let other: AccountId = "u-other.obiba.near".parse().unwrap();
    assert_rejected_sig(sign_as(&guardian_key(), "mainnet", &other, Purpose::ExecuteOp, &o), o);
}

#[test]
#[should_panic(expected = "ERR_BAD_GUARDIAN_SIGNATURE")]
fn guardian_signature_for_another_network_is_rejected() {
    let o = op(1, 200_000_000, T0);
    assert_rejected_sig(sign_as(&guardian_key(), "testnet", &me(), Purpose::ExecuteOp, &o), o);
}

#[test]
#[should_panic(expected = "ERR_BAD_GUARDIAN_SIGNATURE")]
fn signature_from_wrong_key_is_rejected() {
    let o = op(1, 200_000_000, T0);
    assert_rejected_sig(sign_as(&other_key(), "mainnet", &me(), Purpose::ExecuteOp, &o), o);
}

#[test]
#[should_panic(expected = "ERR_BAD_GUARDIAN_SIGNATURE")]
fn signature_for_another_purpose_is_rejected() {
    let o = op(1, 200_000_000, T0);
    assert_rejected_sig(gsign(Purpose::RaiseLimit, &o), o);
}

#[test]
#[should_panic(expected = "ERR_BAD_SIGNATURE_LENGTH")]
fn truncated_signature_is_rejected() {
    let o = op(1, 200_000_000, T0);
    assert_rejected_sig(Base64VecU8(vec![0u8; 63]), o);
}

#[test]
#[should_panic(expected = "ERR_OP_REPLAY")]
fn replayed_op_id_panics() {
    let mut c = setup();
    set(me(), T0);
    track(c.execute(op(1, 1_000_000, T0), None));
    track(c.execute(op(1, 1_000_000, T0), None));
}

#[test]
#[should_panic(expected = "ERR_OP_EXPIRED")]
fn expired_op_panics() {
    let mut c = setup();
    let o = op(1, 1, T0);
    set(me(), o.expires_at_ns.0);
    track(c.execute(o, None));
}

#[test]
#[should_panic(expected = "ERR_OP_TTL")]
fn op_with_long_ttl_panics() {
    let mut c = setup();
    set(me(), T0);
    let mut o = op(1, 1, T0);
    o.expires_at_ns = U64(T0 + 2 * HOUR_NS);
    track(c.execute(o, None));
}

#[test]
#[should_panic(expected = "ERR_ABOVE_MAX_OP_AMOUNT")]
fn above_max_op_amount_panics_even_with_guardian() {
    let mut c = setup();
    set(me(), T0);
    let o = op(1, MAX_OP + 1, T0);
    let sig = gsign(Purpose::ExecuteOp, &o);
    track(c.execute(o, Some(sig)));
}

#[test]
#[should_panic(expected = "ERR_GUARDIAN_REQUIRED")]
fn unregistered_token_always_needs_guardian() {
    let mut c = setup();
    set(me(), T0);
    let mut o = op(1, 1, T0);
    o.token = "stray-token.near".parse().unwrap();
    track(c.execute(o, None));
}

#[test]
fn unregistered_token_can_be_rescued_with_guardian_and_does_not_count() {
    let mut c = setup();
    set(me(), T0);
    let mut o = op(1, 999_999_999_999, T0);
    o.token = "stray-token.near".parse().unwrap();
    let sig = gsign(Purpose::ExecuteOp, &o);
    track(c.execute(o.clone(), Some(sig)));
    assert!(c.get_op(o.op_id).unwrap().cosigned);
    assert_eq!(spent(&c), 0);
}

fn usdt() -> AccountId {
    "usdt.near".parse().unwrap()
}
fn dai18() -> AccountId {
    "dai18.near".parse().unwrap()
}

fn add_token(c: &mut ObibaAccount, token: AccountId, decimals: u8, nonce: u64) {
    let sig = gsign(Purpose::AddToken, &TokenPayload { token: token.clone(), decimals, guardian_nonce: U64(nonce) });
    c.add_token(token, decimals, sig, U64(nonce));
}

#[test]
fn added_stablecoins_share_one_usd_limit() {
    let mut c = setup();
    set(me(), T0);
    add_token(&mut c, usdt(), 6, 0);
    add_token(&mut c, dai18(), 18, 1);
    track(c.execute(op(1, 20_000_000, T0), None));
    let mut t = op(2, 20_000_000, T0);
    t.token = usdt();
    track(c.execute(t, None));
    let mut d = op(3, 10_000_000_000_000_000_000, T0);
    d.token = dai18();
    track(c.execute(d, None));
    assert_eq!(spent(&c), LIMIT);
    let tokens = c.get_policy().tokens;
    assert_eq!(tokens.len(), 3);
}

#[test]
#[should_panic(expected = "ERR_GUARDIAN_REQUIRED")]
fn spreading_across_tokens_cannot_exceed_the_limit() {
    let mut c = setup();
    set(me(), T0);
    add_token(&mut c, dai18(), 18, 0);
    track(c.execute(op(1, LIMIT, T0), None));
    let mut d = op(2, 1, T0);
    d.token = dai18();
    track(c.execute(d, None));
}

#[test]
fn eighteen_decimal_dust_rounds_up() {
    let mut c = setup();
    set(me(), T0);
    add_token(&mut c, dai18(), 18, 0);
    let mut d = op(1, 1, T0);
    d.token = dai18();
    track(c.execute(d, None));
    assert_eq!(spent(&c), 1);
}

#[test]
#[should_panic(expected = "ERR_BAD_GUARDIAN_SIGNATURE")]
fn adding_a_token_needs_the_guardian() {
    let mut c = setup();
    set(me(), T0);
    let sig = gsign(Purpose::AddToken, &TokenPayload { token: usdt(), decimals: 18, guardian_nonce: U64(0) });
    c.add_token(usdt(), 6, sig, U64(0));
}

#[test]
#[should_panic(expected = "ERR_DEVICE_ONLY")]
fn adding_a_token_needs_the_device() {
    let mut c = setup();
    set(alice(), T0);
    add_token(&mut c, usdt(), 6, 0);
}

#[test]
#[should_panic(expected = "ERR_TOKEN_DECIMALS_IMMUTABLE")]
fn token_decimals_cannot_be_changed() {
    let mut c = setup();
    set(me(), T0);
    add_token(&mut c, usdc(), 18, 0);
}

#[test]
#[should_panic(expected = "ERR_GUARDIAN_REQUIRED")]
fn disabled_token_needs_guardian_again() {
    let mut c = setup();
    set(me(), T0);
    c.disable_token(usdc());
    track(c.execute(op(1, 1, T0), None));
}

#[test]
fn disabled_token_can_be_re_enabled_with_same_decimals() {
    let mut c = setup();
    set(me(), T0);
    c.disable_token(usdc());
    add_token(&mut c, usdc(), 6, 0);
    track(c.execute(op(1, 1, T0), None));
}

#[test]
#[should_panic(expected = "ERR_OP_KIND")]
fn wrong_kind_panics() {
    let mut c = setup();
    set(me(), T0);
    let mut o = op(1, 1, T0);
    o.kind = OpKind::PayInvoice;
    track(c.execute(o, None));
}

#[test]
#[should_panic(expected = "ERR_OP_ID")]
fn malformed_op_id_panics() {
    let mut c = setup();
    set(me(), T0);
    let mut o = op(1, 1, T0);
    o.op_id = "not-hex".into();
    track(c.execute(o, None));
}

#[test]
#[should_panic(expected = "ERR_ZERO_AMOUNT")]
fn zero_amount_panics() {
    let mut c = setup();
    set(me(), T0);
    track(c.execute(op(1, 0, T0), None));
}

#[test]
#[should_panic(expected = "ERR_SELF_TRANSFER")]
fn self_transfer_panics() {
    let mut c = setup();
    set(me(), T0);
    let mut o = op(1, 1, T0);
    o.receiver = me();
    track(c.execute(o, None));
}

#[test]
fn failed_transfer_releases_spend_and_marks_failed() {
    let mut c = setup();
    set(me(), T0);
    track(c.execute(op(1, 30_000_000, T0), None));
    set_result(T0 + 1, PromiseResult::Failed);
    c.on_op_result(cb(1));
    let rec = c.get_op(format!("{:032x}", 1)).unwrap();
    assert_eq!(rec.status, OpStatus::Failed);
    assert_eq!(spent(&c), 0);
    set(me(), T0 + 2);
    track(c.execute(op(2, LIMIT, T0 + 2), None));
}

#[test]
fn successful_transfer_keeps_spend() {
    let mut c = setup();
    set(me(), T0);
    track(c.execute(op(1, 30_000_000, T0), None));
    set_result(T0 + 1, PromiseResult::Successful(vec![]));
    c.on_op_result(cb(1));
    assert_eq!(c.get_op(format!("{:032x}", 1)).unwrap().status, OpStatus::Done);
    assert_eq!(spent(&c), 30_000_000);
}

#[test]
fn callback_runs_only_once() {
    let mut c = setup();
    set(me(), T0);
    track(c.execute(op(1, 30_000_000, T0), None));
    set_result(T0 + 1, PromiseResult::Failed);
    c.on_op_result(cb(1));
    c.on_op_result(cb(1));
    assert_eq!(spent(&c), 0);
}

fn invoice(id: u8, amount: u128, ts: u64) -> SignedInvoice {
    SignedInvoice {
        invoice: Invoice {
            invoice_id: format!("{:032x}", id),
            merchant: "cafe.obiba.near".parse().unwrap(),
            token: usdc(),
            amount: U128(amount),
            fee_bps: 50,
            expires_at_ns: U64(ts + HOUR_NS),
            reference: None,
        },
        signature: Base64VecU8(vec![0u8; 64]),
    }
}

fn pay_op(n: u8, inv: &SignedInvoice, ts: u64) -> Op {
    let mut o = op(n, inv.invoice.amount.0, ts);
    o.kind = OpKind::PayInvoice;
    o.receiver = pay();
    o.memo = Some(inv.invoice.invoice_id.clone());
    o
}

#[test]
fn pay_invoice_partial_refund_releases_unused() {
    let mut c = setup();
    set(me(), T0);
    let inv = invoice(7, 20_000_000, T0);
    track(c.pay_invoice(pay_op(1, &inv, T0), inv, None));
    set_result(T0 + 1, PromiseResult::Successful(b"\"0\"".to_vec()));
    c.on_op_result(cb(1));
    let rec = c.get_op(format!("{:032x}", 1)).unwrap();
    assert_eq!(rec.status, OpStatus::Failed);
    assert_eq!(spent(&c), 0);
}

#[test]
fn pay_invoice_fully_used_is_done() {
    let mut c = setup();
    set(me(), T0);
    let inv = invoice(7, 20_000_000, T0);
    track(c.pay_invoice(pay_op(1, &inv, T0), inv, None));
    set_result(T0 + 1, PromiseResult::Successful(b"\"20000000\"".to_vec()));
    c.on_op_result(cb(1));
    assert_eq!(c.get_op(format!("{:032x}", 1)).unwrap().status, OpStatus::Done);
    assert_eq!(spent(&c), 20_000_000);
}

#[test]
fn pay_invoice_garbage_result_counts_as_used() {
    let mut c = setup();
    set(me(), T0);
    let inv = invoice(7, 20_000_000, T0);
    track(c.pay_invoice(pay_op(1, &inv, T0), inv, None));
    set_result(T0 + 1, PromiseResult::Successful(b"garbage".to_vec()));
    c.on_op_result(cb(1));
    assert_eq!(spent(&c), 20_000_000);
}

#[test]
#[should_panic(expected = "ERR_INVOICE_NOT_BOUND_TO_OP")]
fn pay_invoice_requires_memo_binding() {
    let mut c = setup();
    set(me(), T0);
    let inv = invoice(7, 20_000_000, T0);
    let mut o = pay_op(1, &inv, T0);
    o.memo = Some(format!("{:032x}", 8));
    track(c.pay_invoice(o, inv, None));
}

#[test]
#[should_panic(expected = "ERR_RECEIVER_NOT_PAY_CONTRACT")]
fn pay_invoice_to_other_receiver_panics() {
    let mut c = setup();
    set(me(), T0);
    let inv = invoice(7, 20_000_000, T0);
    let mut o = pay_op(1, &inv, T0);
    o.receiver = alice();
    track(c.pay_invoice(o, inv, None));
}

#[test]
#[should_panic(expected = "ERR_INVOICE_TOKEN")]
fn pay_invoice_token_must_match_op() {
    let mut c = setup();
    set(me(), T0);
    add_token(&mut c, usdt(), 6, 0);
    let mut inv = invoice(7, 20_000_000, T0);
    inv.invoice.token = usdt();
    let o = pay_op(1, &inv, T0);
    track(c.pay_invoice(o, inv, None));
}

#[test]
#[should_panic(expected = "ERR_INVOICE_AMOUNT")]
fn pay_invoice_amount_mismatch_panics() {
    let mut c = setup();
    set(me(), T0);
    let inv = invoice(7, 20_000_000, T0);
    let mut o = pay_op(1, &inv, T0);
    o.amount = U128(19_000_000);
    track(c.pay_invoice(o, inv, None));
}

#[test]
fn window_frees_after_24_hours() {
    let mut c = setup();
    set(me(), T0);
    track(c.execute(op(1, LIMIT, T0), None));
    let later = T0 + 24 * HOUR_NS;
    set(me(), later);
    track(c.execute(op(2, LIMIT, later), None));
    assert_eq!(spent(&c), LIMIT);
}

#[test]
fn lowering_limit_is_immediate() {
    let mut c = setup();
    set(me(), T0);
    c.set_limit(U128(1_000_000), None, None);
    assert_eq!(c.get_policy().effective_daily_limit.0, 1_000_000);
}

#[test]
#[should_panic(expected = "ERR_GUARDIAN_REQUIRED")]
fn raising_limit_requires_guardian() {
    let mut c = setup();
    set(me(), T0);
    c.set_limit(U128(LIMIT * 2), None, None);
}

#[test]
fn raising_limit_takes_effect_after_delay() {
    let mut c = setup();
    set(me(), T0);
    let new_limit = U128(LIMIT * 2);
    let sig = gsign(Purpose::RaiseLimit, &LimitPayload { new_limit, guardian_nonce: U64(0) });
    c.set_limit(new_limit, Some(sig), Some(U64(0)));
    assert_eq!(c.get_policy().effective_daily_limit.0, LIMIT);
    assert_eq!(c.get_policy().guardian_nonce.0, 1);
    set(me(), T0 + RAISE_DELAY_NS);
    assert_eq!(c.get_policy().effective_daily_limit.0, LIMIT * 2);
    track(c.execute(op(1, LIMIT * 2, T0 + RAISE_DELAY_NS), None));
}

#[test]
#[should_panic(expected = "ERR_GUARDIAN_NONCE")]
fn guardian_nonce_cannot_be_replayed() {
    let mut c = setup();
    set(me(), T0);
    let new_limit = U128(LIMIT * 2);
    let sig = gsign(Purpose::RaiseLimit, &LimitPayload { new_limit, guardian_nonce: U64(0) });
    c.set_limit(new_limit, Some(sig.clone()), Some(U64(0)));
    c.set_limit(new_limit, Some(sig), Some(U64(0)));
}

fn freeze(c: &mut ObibaAccount, until: u64, nonce: u64) {
    let sig = gsign(Purpose::Freeze, &FreezePayload { until_ns: U64(until), guardian_nonce: U64(nonce) });
    c.freeze(U64(until), sig, U64(nonce));
}

#[test]
#[should_panic(expected = "ERR_FROZEN")]
fn frozen_account_cannot_spend() {
    let mut c = setup();
    set(alice(), T0);
    freeze(&mut c, T0 + HOUR_NS, 0);
    set(me(), T0 + 1);
    track(c.execute(op(1, 1, T0 + 1), None));
}

#[test]
fn freeze_expires_by_itself() {
    let mut c = setup();
    set(alice(), T0);
    freeze(&mut c, T0 + HOUR_NS, 0);
    set(me(), T0 + HOUR_NS);
    track(c.execute(op(1, 1, T0 + HOUR_NS), None));
}

#[test]
#[should_panic(expected = "ERR_FREEZE_WINDOW")]
fn freeze_longer_than_cap_panics() {
    let mut c = setup();
    set(alice(), T0);
    freeze(&mut c, T0 + MAX_FREEZE_NS + 1, 0);
}

#[test]
#[should_panic(expected = "ERR_FREEZE_COOLDOWN")]
fn refreeze_within_cooldown_panics() {
    let mut c = setup();
    set(alice(), T0);
    freeze(&mut c, T0 + HOUR_NS, 0);
    set(alice(), T0 + 2 * HOUR_NS);
    freeze(&mut c, T0 + 3 * HOUR_NS, 1);
}

#[test]
fn unfreeze_needs_device_and_guardian() {
    let mut c = setup();
    set(alice(), T0);
    freeze(&mut c, T0 + HOUR_NS, 0);
    set(me(), T0 + 1);
    let sig = gsign(Purpose::Unfreeze, &NoncePayload { guardian_nonce: U64(1) });
    c.unfreeze(sig, U64(1));
    track(c.execute(op(1, 1, T0 + 1), None));
}

fn begin_recovery(c: &mut ObibaAccount, nonce: u64) -> PublicKey {
    let new_key = pk(&SigningKey::from_bytes(&[5u8; 32]));
    let sig = gsign(Purpose::BeginRecovery, &KeyPayload { public_key: new_key.clone(), guardian_nonce: U64(nonce) });
    c.begin_recovery(new_key.clone(), sig, U64(nonce));
    new_key
}

#[test]
#[should_panic(expected = "ERR_RECOVERY_NOT_READY")]
fn recovery_cannot_complete_early() {
    let mut c = setup();
    set(alice(), T0);
    begin_recovery(&mut c, 0);
    set(alice(), T0 + RECOVERY_DELAY_NS - 1);
    let _ = c.complete_recovery();
}

#[test]
fn recovery_completes_after_delay_and_replaces_devices() {
    let mut c = setup();
    set(alice(), T0);
    let new_key = begin_recovery(&mut c, 0);
    set(alice(), T0 + RECOVERY_DELAY_NS);
    let _ = c.complete_recovery();
    assert_eq!(c.get_policy().devices, vec![new_key]);
    assert!(c.get_policy().recovery.is_none());
}

#[test]
#[should_panic(expected = "ERR_NO_RECOVERY")]
fn cancelled_recovery_cannot_complete() {
    let mut c = setup();
    set(alice(), T0);
    begin_recovery(&mut c, 0);
    set(me(), T0 + 1);
    c.cancel_recovery();
    set(alice(), T0 + RECOVERY_DELAY_NS);
    let _ = c.complete_recovery();
}

#[test]
#[should_panic(expected = "ERR_DEVICE_ONLY")]
fn only_device_can_cancel_recovery() {
    let mut c = setup();
    set(alice(), T0);
    begin_recovery(&mut c, 0);
    c.cancel_recovery();
}

#[test]
fn failed_key_change_reverts_state() {
    let mut c = setup();
    set(alice(), T0);
    begin_recovery(&mut c, 0);
    set(alice(), T0 + RECOVERY_DELAY_NS);
    let _ = c.complete_recovery();
    let recovery_before = Some(Recovery {
        new_key: pk(&SigningKey::from_bytes(&[5u8; 32])),
        executable_at_ns: U64(T0 + RECOVERY_DELAY_NS),
    });
    set_result(T0 + RECOVERY_DELAY_NS + 1, PromiseResult::Failed);
    c.on_keys_result(vec![device_pk()], recovery_before.clone());
    assert_eq!(c.get_policy().devices, vec![device_pk()]);
    assert_eq!(c.get_policy().recovery, recovery_before);
}

#[test]
#[should_panic(expected = "ERR_LAST_DEVICE")]
fn cannot_remove_last_device() {
    let mut c = setup();
    set(me(), T0);
    let sig = gsign(Purpose::RemoveDevice, &KeyPayload { public_key: device_pk(), guardian_nonce: U64(0) });
    let _ = c.remove_device(device_pk(), sig, U64(0));
}

#[test]
fn add_device_with_guardian() {
    let mut c = setup();
    set(me(), T0);
    let k = pk(&SigningKey::from_bytes(&[6u8; 32]));
    let sig = gsign(Purpose::AddDevice, &KeyPayload { public_key: k.clone(), guardian_nonce: U64(0) });
    let _ = c.add_device(k.clone(), sig, U64(0));
    assert!(c.get_policy().devices.contains(&k));
}

#[test]
#[should_panic(expected = "ERR_BAD_GUARDIAN_SIGNATURE")]
fn add_device_with_signature_for_other_key_panics() {
    let mut c = setup();
    set(me(), T0);
    let k = pk(&SigningKey::from_bytes(&[6u8; 32]));
    let other = pk(&SigningKey::from_bytes(&[8u8; 32]));
    let sig = gsign(Purpose::AddDevice, &KeyPayload { public_key: other, guardian_nonce: U64(0) });
    let _ = c.add_device(k, sig, U64(0));
}

#[test]
fn guardian_change_proposal_veto_and_apply() {
    let mut c = setup();
    set(me(), T0);
    let new_g = pk(&other_key());
    c.propose_guardian(new_g.clone());
    set(alice(), T0 + 1);
    let sig = gsign(Purpose::VetoGuardianChange, &KeyPayload { public_key: new_g.clone(), guardian_nonce: U64(0) });
    c.veto_guardian_change(sig, U64(0));
    assert!(c.get_policy().guardian_change.is_none());
    set(me(), T0 + 2);
    c.propose_guardian(new_g.clone());
    set(alice(), T0 + 2 + GUARDIAN_CHANGE_DELAY_NS);
    c.apply_guardian_change();
    assert_eq!(c.get_policy().guardian, new_g);
}

#[test]
#[should_panic(expected = "ERR_GUARDIAN_CHANGE_NOT_READY")]
fn guardian_change_cannot_apply_early() {
    let mut c = setup();
    set(me(), T0);
    c.propose_guardian(pk(&other_key()));
    set(alice(), T0 + GUARDIAN_CHANGE_DELAY_NS - 1);
    c.apply_guardian_change();
}

#[test]
fn rotate_guardian_with_current_signature() {
    let mut c = setup();
    set(me(), T0);
    let new_g = pk(&other_key());
    let sig = gsign(Purpose::RotateGuardian, &KeyPayload { public_key: new_g.clone(), guardian_nonce: U64(0) });
    c.rotate_guardian(new_g.clone(), sig, U64(0));
    assert_eq!(c.get_policy().guardian, new_g);
    let o = op(1, 200_000_000, T0);
    let new_sig = sign_as(&other_key(), "mainnet", &me(), Purpose::ExecuteOp, &o);
    track(c.execute(o, Some(new_sig)));
}

#[test]
fn settled_ops_are_pruned_once_expired() {
    let mut c = setup();
    set(me(), T0);
    let first = op(1, 1, T0);
    track(c.execute(first.clone(), None));
    set_result(T0 + 1, PromiseResult::Successful(vec![]));
    c.on_op_result(cb(1));
    let later = first.expires_at_ns.0;
    set(me(), later);
    track(c.execute(op(2, 1, later), None));
    assert!(c.get_op(first.op_id).is_none());
    assert!(c.get_op(format!("{:032x}", 2)).is_some());
}

#[test]
fn ops_are_kept_until_they_expire() {
    let mut c = setup();
    set(me(), T0);
    let first = op(1, 1, T0);
    track(c.execute(first.clone(), None));
    set_result(T0 + 1, PromiseResult::Successful(vec![]));
    c.on_op_result(cb(1));
    let later = first.expires_at_ns.0 - 1;
    set(me(), later);
    track(c.execute(op(2, 1, later), None));
    assert!(c.get_op(first.op_id).is_some());
}

#[test]
fn pending_ops_are_never_pruned() {
    let mut c = setup();
    set(me(), T0);
    let first = op(1, 1, T0);
    track(c.execute(first.clone(), None));
    let later = first.expires_at_ns.0 + 48 * HOUR_NS;
    set(me(), later);
    track(c.execute(op(2, 1, later), None));
    assert_eq!(c.get_op(first.op_id).unwrap().status, OpStatus::Pending);
    set_result(later + 1, PromiseResult::Failed);
    c.on_op_result(cb(1));
    assert_eq!(c.get_op(format!("{:032x}", 1)).unwrap().status, OpStatus::Failed);
}

#[test]
#[should_panic(expected = "ERR_OP_REPLAY")]
fn settled_op_cannot_be_replayed_before_expiry() {
    let mut c = setup();
    set(me(), T0);
    track(c.execute(op(1, 1, T0), None));
    set_result(T0 + 1, PromiseResult::Successful(vec![]));
    c.on_op_result(cb(1));
    set(me(), T0 + 2);
    track(c.execute(op(1, 1, T0), None));
}

#[test]
#[should_panic(expected = "ERR_NOT_A_CALLBACK")]
fn callback_without_a_promise_result_is_refused() {
    let mut c = setup();
    set(me(), T0);
    track(c.execute(op(1, 30_000_000, T0), None));
    set(me(), T0 + 1);
    c.on_op_result(cb(1));
}

#[test]
#[should_panic(expected = "ERR_NOT_A_CALLBACK")]
fn keys_callback_without_a_promise_result_is_refused() {
    let mut c = setup();
    set(me(), T0);
    c.on_keys_result(vec![device_pk()], None);
}

#[test]
fn orphaned_callback_changes_nothing() {
    let mut c = setup();
    set(me(), T0);
    track(c.execute(op(1, 30_000_000, T0), None));
    let mut stray = cb(1);
    stray.op_id = format!("{:032x}", 9);
    set_result(T0 + 1, PromiseResult::Failed);
    c.on_op_result(stray);
    assert_eq!(spent(&c), 30_000_000);
    assert!(get_logs().iter().any(|l| l.contains("op_result_orphaned")));
}

#[test]
fn transfer_promise_carries_the_same_arguments_as_before() {
    let mut c = setup();
    set(me(), T0);
    let mut o = op(1, 10_000_000, T0);
    o.memo = Some("rent \"may\"".into());
    track(c.execute(o, None));
    let transfers = calls("ft_transfer");
    assert_eq!(transfers.len(), 1);
    assert_eq!(transfers[0].0, "usdc.near");
    assert_eq!(
        String::from_utf8(transfers[0].1.clone()).unwrap(),
        r#"{"receiver_id":"alice.near","amount":"10000000","memo":"obiba:00000000000000000000000000000001:rent \"may\""}"#
    );
    let cb = cb(1);
    assert_eq!((cb.amount, cb.counted_usd, cb.decimals, cb.cosigned), (10_000_000, 10_000_000, 6, false));
}

#[test]
fn invoice_promise_forwards_the_signed_invoice_as_json() {
    let mut c = setup();
    set(me(), T0);
    let inv = invoice(7, 20_000_000, T0);
    let expected_msg = inv.to_json();
    track(c.pay_invoice(pay_op(1, &inv, T0), inv, None));
    let call = calls("ft_transfer_call");
    let args: serde_json::Value = serde_json::from_slice(&call[0].1).unwrap();
    assert_eq!(args["receiver_id"], "pay.obiba.near");
    assert_eq!(args["amount"], "20000000");
    assert_eq!(args["msg"], expected_msg.as_str());
    let parsed = SignedInvoice::parse(args["msg"].as_str().unwrap().as_bytes()).unwrap();
    assert_eq!(parsed.invoice.invoice_id, format!("{:032x}", 7));
}

#[test]
fn events_are_byte_identical_to_the_previous_contract() {
    let mut c = setup();
    set(me(), T0);
    track(c.execute(op(1, 10_000_000, T0), None));
    let logs = get_logs();
    assert_eq!(
        logs[0],
        r#"EVENT_JSON:{"standard":"obiba","version":"1.0.0","event":"op_submitted","data":[{"op_id":"00000000000000000000000000000001","kind":"Transfer","token":"usdc.near","receiver":"alice.near","amount":"10000000","usd":"10000000","cosigned":false}]}"#
    );
    set_result(T0 + 1, PromiseResult::Successful(vec![]));
    c.on_op_result(cb(1));
    assert_eq!(
        get_logs()[0],
        r#"EVENT_JSON:{"standard":"obiba","version":"1.0.0","event":"op_executed","data":[{"op_id":"00000000000000000000000000000001","kind":"Transfer","token":"usdc.near","amount":"10000000","used":"10000000","cosigned":false}]}"#
    );
    set(me(), T0 + 2);
    c.set_limit(U128(1), None, None);
    assert_eq!(get_logs()[0], r#"EVENT_JSON:{"standard":"obiba","version":"1.0.0","event":"limit_lowered","data":[{"new_limit":"1"}]}"#);
}

#[test]
fn policy_view_json_matches_the_serde_layout() {
    let c = setup();
    let json = c.get_policy().to_json();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let keys: Vec<&str> = json.trim_start_matches('{').split(",\"").map(|k| k.trim_matches('"').split('"').next().unwrap()).collect();
    assert_eq!(keys[0], "tokens");
    assert_eq!(v["tokens"][0]["token"], "usdc.near");
    assert_eq!(v["tokens"][0]["decimals"], 6);
    assert_eq!(v["tokens"][0]["enabled"], true);
    assert_eq!(v["pay_contract"], "pay.obiba.near");
    assert_eq!(v["network_id"], "mainnet");
    assert_eq!(v["guardian"], pk(&guardian_key()).to_string());
    assert_eq!(v["guardian_nonce"], "0");
    assert_eq!(v["devices"][0], device_pk().to_string());
    assert_eq!(v["daily_limit"], LIMIT.to_string());
    assert_eq!(v["effective_daily_limit"], LIMIT.to_string());
    assert!(v["pending_limit"].is_null());
    assert_eq!(v["max_op_amount"], MAX_OP.to_string());
    assert_eq!(v["spent_24h"], "0");
    assert_eq!(v["frozen_until_ns"], "0");
    assert_eq!(v["last_freeze_start_ns"], "0");
    assert!(v["recovery"].is_null());
    assert!(v["guardian_change"].is_null());
    assert_eq!(v.as_object().unwrap().len(), 15);
}

#[test]
fn state_round_trips_through_storage_encoding() {
    let mut c = setup();
    set(me(), T0);
    add_token(&mut c, dai18(), 18, 0);
    track(c.execute(op(1, 10_000_000, T0), None));
    let sig = gsign(Purpose::RaiseLimit, &LimitPayload { new_limit: U128(LIMIT * 2), guardian_nonce: U64(1) });
    c.set_limit(U128(LIMIT * 2), Some(sig), Some(U64(1)));
    c.propose_guardian(pk(&other_key()));
    set(alice(), T0 + 1);
    begin_recovery(&mut c, 2);
    assert_eq!(ObibaAccount::decode(&c.encode()).unwrap(), c);
    let mut bytes = c.encode();
    bytes.push(0);
    assert!(ObibaAccount::decode(&bytes).is_none());
}

const ACCOUNT_RECORD: usize = 100;
const RECORD_OVERHEAD: usize = 40;
const GLOBAL_REFERENCE: usize = 32;
const ZERO_BALANCE_LIMIT: usize = 770;

fn device_key_bytes(account: &str) -> usize {
    let methods: usize = DEVICE_METHODS.split(',').map(|m| 4 + m.len()).sum();
    RECORD_OVERHEAD + 33 + 8 + 1 + 17 + 4 + account.len() + 4 + methods
}

fn storage_usage(account: &str, c: &ObibaAccount) -> usize {
    ACCOUNT_RECORD + GLOBAL_REFERENCE + device_key_bytes(account) + RECORD_OVERHEAD + STATE_KEY.len() + c.encode().len()
}

fn mainnet_account(name: &str) -> ObibaAccount {
    let mut b = VMContextBuilder::new();
    b.current_account_id(name.parse().unwrap()).predecessor_account_id("obiba.near".parse().unwrap()).block_timestamp(T0);
    testing_env!(b.build());
    ObibaAccount::new(
        vec![TokenInit { token: id("17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1"), decimals: 6 }],
        id("pay.obiba.near"),
        "mainnet".into(),
        pk(&guardian_key()),
        device_pk(),
        U128(50_000_000),
        U128(500_000_000),
    )
}

#[test]
fn a_fresh_mainnet_account_fits_the_zero_balance_limit() {
    let name = "kwame-mensah.obiba.near";
    let c = mainnet_account(name);
    let used = storage_usage(name, &c);
    assert!(used <= ZERO_BALANCE_LIMIT, "{used} bytes");
}

#[test]
fn a_busy_mainnet_account_still_fits_the_zero_balance_limit() {
    let name = "kwame-mensah.obiba.near";
    let mut c = mainnet_account(name);
    for hour in 0..3u64 {
        let ts = T0 + hour * HOUR_NS;
        let mut b = VMContextBuilder::new();
        b.current_account_id(name.parse().unwrap()).predecessor_account_id(name.parse().unwrap()).block_timestamp(ts);
        testing_env!(b.build());
        let mut o = op(hour as u8 + 1, 5_000_000, ts);
        o.token = id("17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1");
        track(c.execute(o, None));
    }
    let used = storage_usage(name, &c);
    assert!(used <= ZERO_BALANCE_LIMIT, "{used} bytes");
}

#[test]
fn state_is_less_than_half_of_the_previous_layout() {
    let c = mainnet_account("kwame-mensah.obiba.near");
    let previous_state_bytes = 720;
    assert!(c.encode().len() * 2 < previous_state_bytes, "{} bytes", c.encode().len());
}

fn wrapper_ctx(predecessor: &str, deposit: u128, input: &str) {
    let mut b = ctx(id(predecessor), T0);
    b.attached_deposit(NearToken::from_yoctonear(deposit));
    let mut context = b.build();
    context.input = input.as_bytes().to_vec().into();
    testing_env!(context);
}

fn init_json() -> String {
    format!(
        r#"{{"tokens":[{{"token":"usdc.near","decimals":6}}],"pay_contract":"pay.obiba.near","network_id":"mainnet","guardian":"{}","device":"{}","daily_limit":"{}","max_op_amount":"{}"}}"#,
        pk(&guardian_key()),
        device_pk(),
        LIMIT,
        MAX_OP
    )
}

#[test]
fn wrapper_init_parses_json_and_persists_state() {
    wrapper_ctx("obiba.near", 0, &init_json());
    super::new();
    let stored = ObibaAccount::decode(&rt::read(STATE_KEY).unwrap()).unwrap();
    assert_eq!(stored.get_policy().daily_limit.0, LIMIT);
    let op_json = format!(
        r#"{{"op":{{"op_id":"{:032x}","kind":"Transfer","token":"usdc.near","receiver":"alice.near","amount":"1000","expires_at_ns":"{}"}},"guardian_sig":null}}"#,
        1,
        T0 + 60_000_000_000
    );
    let mut context = ctx(me(), T0).build();
    context.input = op_json.into_bytes().into();
    testing_env!(context);
    rt::write(STATE_KEY, &stored.encode());
    super::execute();
    let after = ObibaAccount::decode(&rt::read(STATE_KEY).unwrap()).unwrap();
    assert_eq!(after.get_policy().spent_24h.0, 1000);
}

#[test]
#[should_panic(expected = "Method new doesn't accept deposit")]
fn wrapper_rejects_deposits() {
    wrapper_ctx("obiba.near", 1, &init_json());
    super::new();
}

#[test]
#[should_panic(expected = "The contract has already been initialized")]
fn wrapper_init_runs_once() {
    wrapper_ctx("obiba.near", 0, &init_json());
    rt::write(STATE_KEY, b"x");
    super::new();
}

#[test]
#[should_panic(expected = "Failed to deserialize input from JSON.")]
fn wrapper_rejects_malformed_json() {
    wrapper_ctx("obiba.near", 0, &init_json().replace("\"6\"", "6").replace("6}", "6,}"));
    super::new();
}

#[test]
#[should_panic(expected = "Failed to deserialize input from JSON.")]
fn wrapper_rejects_duplicate_fields() {
    wrapper_ctx("obiba.near", 0, &init_json().replacen("\"network_id\":\"mainnet\"", "\"network_id\":\"mainnet\",\"network_id\":\"testnet\"", 1));
    super::new();
}

#[test]
#[should_panic(expected = "Method on_op_result is private")]
fn wrapper_callbacks_are_private() {
    wrapper_ctx("alice.near", 0, "");
    super::on_op_result();
}

#[test]
#[should_panic(expected = "The contract is not initialized")]
fn wrapper_requires_state() {
    wrapper_ctx("u-test.obiba.near", 0, "");
    super::cancel_recovery();
}
