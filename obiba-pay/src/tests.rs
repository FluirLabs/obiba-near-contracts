use super::*;
use ed25519_dalek::{Signer, SigningKey};
use near_sdk::test_utils::{get_logs, VMContextBuilder};
use near_sdk::{testing_env, NearToken, PromiseResult, RuntimeFeesConfig};
use obiba_common::{Base64VecU8, CurveType, Invoice};
use sha2::{Digest, Sha256};

fn sdk(a: &AccountId) -> near_sdk::AccountId {
    a.as_str().parse().unwrap()
}

const T0: u64 = 1_800_000_000 * 1_000_000_000;
const AMOUNT: u128 = 20_000_000;
const FEE_BPS: u16 = 50;

fn me() -> AccountId {
    "pay.obiba.near".parse().unwrap()
}
fn usdc() -> AccountId {
    "usdc.near".parse().unwrap()
}
fn owner() -> AccountId {
    "owner.near".parse().unwrap()
}
fn treasury() -> AccountId {
    "treasury.obiba.near".parse().unwrap()
}
fn merchant() -> AccountId {
    "cafe.obiba.near".parse().unwrap()
}
fn payer() -> AccountId {
    "u-1.obiba.near".parse().unwrap()
}
fn invoice_key() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}
fn pk(key: &SigningKey) -> PublicKey {
    PublicKey::from_parts(CurveType::ED25519, key.verifying_key().to_bytes().to_vec()).unwrap()
}

fn ctx(predecessor: AccountId, ts: u64, deposit: u128) -> VMContextBuilder {
    let mut b = VMContextBuilder::new();
    b.current_account_id(sdk(&me()))
        .predecessor_account_id(sdk(&predecessor))
        .signer_account_id(sdk(&predecessor))
        .block_timestamp(ts)
        .attached_deposit(NearToken::from_yoctonear(deposit))
        .account_balance(NearToken::from_near(5));
    b
}

fn set(predecessor: AccountId, ts: u64) {
    testing_env!(ctx(predecessor, ts, 0).build());
}

fn set_owner(ts: u64) {
    testing_env!(ctx(owner(), ts, 1).build());
}

fn set_result(ts: u64, result: PromiseResult) {
    testing_env!(
        ctx(me(), ts, 0).build(),
        near_sdk::test_vm_config(),
        RuntimeFeesConfig::test(),
        Default::default(),
        vec![result]
    );
}

fn setup() -> ObibaPay {
    set(me(), T0);
    let mut c = ObibaPay::new(vec![usdc()], "mainnet".into(), owner(), pk(&invoice_key()), FEE_BPS, treasury());
    set_owner(T0);
    c.register_merchant(merchant());
    c
}

fn invoice(id: u8, amount: u128) -> Invoice {
    Invoice {
        invoice_id: format!("{:032x}", id),
        merchant: merchant(),
        token: usdc(),
        amount: U128(amount),
        fee_bps: FEE_BPS,
        expires_at_ns: U64(T0 + HOUR_NS),
        reference: Some("order-1".into()),
    }
}

fn sign_with(key: &SigningKey, network: &str, contract: &AccountId, inv: Invoice) -> String {
    let digest = Sha256::digest(invoice_preimage(network, contract, &inv));
    SignedInvoice {
        invoice: inv,
        signature: Base64VecU8(key.sign(&digest).to_bytes().to_vec()),
    }
    .to_json()
}

fn signed(inv: Invoice) -> String {
    sign_with(&invoice_key(), "mainnet", &me(), inv)
}

fn pay(c: &mut ObibaPay, amount: u128, msg: String) -> u128 {
    set(usdc(), T0 + 1);
    match c.ft_on_transfer(payer(), U128(amount), msg) {
        PromiseOrValue::Value(v) => v.0,
        PromiseOrValue::Promise(_) => panic!("unexpected promise"),
    }
}

fn rejected_reason() -> String {
    get_logs().into_iter().find(|l| l.contains("invoice_rejected")).unwrap_or_default()
}

#[test]
fn valid_invoice_is_paid_with_fee() {
    let mut c = setup();
    let refund = pay(&mut c, AMOUNT, signed(invoice(1, AMOUNT)));
    assert_eq!(refund, 0);
    let rec = c.get_paid(format!("{:032x}", 1)).unwrap();
    assert_eq!(rec.fee.0, AMOUNT * 50 / 10_000);
    assert_eq!(rec.merchant, merchant());
    assert_eq!(c.get_accrued_fees(usdc()).0, AMOUNT * 50 / 10_000);
    assert!(get_logs().iter().any(|l| l.contains("invoice_paid")));
}

#[test]
fn second_payment_of_same_invoice_is_refunded() {
    let mut c = setup();
    let msg = signed(invoice(1, AMOUNT));
    assert_eq!(pay(&mut c, AMOUNT, msg.clone()), 0);
    assert_eq!(pay(&mut c, AMOUNT, msg), AMOUNT);
    assert!(rejected_reason().contains("already_paid"));
}

#[test]
fn wrong_amount_is_refunded() {
    let mut c = setup();
    assert_eq!(pay(&mut c, AMOUNT - 1, signed(invoice(1, AMOUNT))), AMOUNT - 1);
    assert!(rejected_reason().contains("amount_mismatch"));
    assert_eq!(pay(&mut c, AMOUNT + 1, signed(invoice(1, AMOUNT))), AMOUNT + 1);
    assert!(c.get_paid(format!("{:032x}", 1)).is_none());
}

#[test]
fn expired_invoice_is_refunded() {
    let mut c = setup();
    let mut inv = invoice(1, AMOUNT);
    inv.expires_at_ns = U64(T0 + 1);
    assert_eq!(pay(&mut c, AMOUNT, signed(inv)), AMOUNT);
    assert!(rejected_reason().contains("expired"));
}

#[test]
fn unregistered_merchant_is_refunded() {
    let mut c = setup();
    let mut inv = invoice(1, AMOUNT);
    inv.merchant = "mallory.near".parse().unwrap();
    assert_eq!(pay(&mut c, AMOUNT, signed(inv)), AMOUNT);
    assert!(rejected_reason().contains("merchant_not_registered"));
}

#[test]
fn signature_from_other_key_network_or_contract_is_refunded() {
    let mut c = setup();
    let other = SigningKey::from_bytes(&[12u8; 32]);
    let cases = [
        sign_with(&other, "mainnet", &me(), invoice(1, AMOUNT)),
        sign_with(&invoice_key(), "testnet", &me(), invoice(1, AMOUNT)),
        sign_with(&invoice_key(), "mainnet", &"pay2.obiba.near".parse().unwrap(), invoice(1, AMOUNT)),
    ];
    for msg in cases {
        assert_eq!(pay(&mut c, AMOUNT, msg), AMOUNT);
        assert!(rejected_reason().contains("signature_invalid"));
    }
}

#[test]
fn tampered_invoice_is_refunded() {
    let mut c = setup();
    let msg = signed(invoice(1, AMOUNT)).replace(merchant().as_str(), "evil.obiba.near");
    assert_eq!(pay(&mut c, AMOUNT, msg), AMOUNT);
    assert!(rejected_reason().contains("signature_invalid"));
}

#[test]
fn fee_mismatch_is_refunded() {
    let mut c = setup();
    let mut inv = invoice(1, AMOUNT);
    inv.fee_bps = 0;
    assert_eq!(pay(&mut c, AMOUNT, signed(inv)), AMOUNT);
    assert!(rejected_reason().contains("fee_mismatch"));
}

#[test]
fn malformed_messages_are_refunded_without_state() {
    let mut c = setup();
    for msg in ["", "not json", "{}", &"x".repeat(MAX_MSG_LEN + 1)] {
        assert_eq!(pay(&mut c, AMOUNT, msg.to_string()), AMOUNT);
    }
    assert_eq!(c.get_accrued_fees(usdc()).0, 0);
}

#[test]
#[should_panic(expected = "ERR_TOKEN_NOT_ACCEPTED")]
fn other_token_is_rejected() {
    let mut c = setup();
    set("fake-usdc.near".parse().unwrap(), T0);
    let _ = c.ft_on_transfer(payer(), U128(AMOUNT), signed(invoice(1, AMOUNT)));
}

#[test]
fn paused_contract_refunds() {
    let mut c = setup();
    set_owner(T0);
    c.pause();
    assert_eq!(pay(&mut c, AMOUNT, signed(invoice(1, AMOUNT))), AMOUNT);
    set_owner(T0);
    c.unpause();
    assert_eq!(pay(&mut c, AMOUNT, signed(invoice(1, AMOUNT))), 0);
}

#[test]
fn failed_forward_is_owed_and_retryable() {
    let mut c = setup();
    pay(&mut c, AMOUNT, signed(invoice(1, AMOUNT)));
    let net = AMOUNT - AMOUNT * 50 / 10_000;
    set_result(T0 + 2, PromiseResult::Failed);
    c.on_forward(usdc(), merchant(), U128(net), format!("{:032x}", 1));
    assert_eq!(c.get_owed(merchant(), usdc()).0, net);
    set("anyone.near".parse().unwrap(), T0 + 3);
    let _ = c.retry_owed(merchant(), usdc());
    assert_eq!(c.get_owed(merchant(), usdc()).0, 0);
}

#[test]
fn successful_forward_owes_nothing() {
    let mut c = setup();
    pay(&mut c, AMOUNT, signed(invoice(1, AMOUNT)));
    set_result(T0 + 2, PromiseResult::Successful(vec![]));
    c.on_forward(usdc(), merchant(), U128(1), format!("{:032x}", 1));
    assert_eq!(c.get_owed(merchant(), usdc()).0, 0);
}

#[test]
#[should_panic(expected = "ERR_NOTHING_OWED")]
fn retry_without_debt_panics() {
    let mut c = setup();
    set(merchant(), T0);
    let _ = c.retry_owed(merchant(), usdc());
}

#[test]
#[should_panic(expected = "ERR_NOT_OWNER")]
fn non_owner_cannot_pause() {
    let mut c = setup();
    testing_env!(ctx(merchant(), T0, 1).build());
    c.pause();
}

#[test]
#[should_panic(expected = "Requires attached deposit of exactly 1 yoctoNEAR")]
fn owner_methods_require_one_yocto() {
    let mut c = setup();
    set(owner(), T0);
    c.pause();
}

#[test]
#[should_panic(expected = "ERR_FEE_TOO_HIGH")]
fn fee_cannot_exceed_cap() {
    let mut c = setup();
    set_owner(T0);
    c.propose_fee(MAX_FEE_BPS + 1);
}

#[test]
fn fee_change_waits_for_delay() {
    let mut c = setup();
    set_owner(T0);
    c.propose_fee(80);
    set(merchant(), T0 + OWNER_DELAY_NS);
    c.apply_fee();
    assert_eq!(c.get_config().fee_bps, 80);
}

#[test]
#[should_panic(expected = "ERR_NOT_READY")]
fn fee_change_cannot_apply_early() {
    let mut c = setup();
    set_owner(T0);
    c.propose_fee(80);
    set(merchant(), T0 + OWNER_DELAY_NS - 1);
    c.apply_fee();
}

#[test]
#[should_panic(expected = "ERR_NOT_READY")]
fn invoice_key_rotation_cannot_apply_early() {
    let mut c = setup();
    set_owner(T0);
    c.propose_invoice_key(pk(&SigningKey::from_bytes(&[13u8; 32])));
    set(merchant(), T0 + 1);
    c.apply_invoice_key();
}

#[test]
fn withdraw_fees_and_restore_on_failure() {
    let mut c = setup();
    pay(&mut c, AMOUNT, signed(invoice(1, AMOUNT)));
    let fee = AMOUNT * 50 / 10_000;
    set_owner(T0 + 2);
    let _ = c.withdraw_fees(usdc(), U128(fee));
    assert_eq!(c.get_accrued_fees(usdc()).0, 0);
    set_result(T0 + 3, PromiseResult::Failed);
    c.on_fee_withdraw(usdc(), U128(fee));
    assert_eq!(c.get_accrued_fees(usdc()).0, fee);
}

#[test]
#[should_panic(expected = "ERR_FEE_AMOUNT")]
fn cannot_withdraw_more_than_accrued() {
    let mut c = setup();
    set_owner(T0);
    let _ = c.withdraw_fees(usdc(), U128(1));
}

#[test]
fn ownership_transfer_is_two_step() {
    let mut c = setup();
    set_owner(T0);
    c.propose_owner(merchant());
    assert_eq!(c.get_config().owner, owner());
    testing_env!(ctx(merchant(), T0, 1).build());
    c.accept_owner();
    assert_eq!(c.get_config().owner, merchant());
}

#[test]
#[should_panic(expected = "ERR_NOT_PENDING_OWNER")]
fn only_pending_owner_can_accept() {
    let mut c = setup();
    set_owner(T0);
    c.propose_owner(merchant());
    testing_env!(ctx(payer(), T0, 1).build());
    c.accept_owner();
}

#[test]
fn paid_records_are_pruned_only_after_retention() {
    let mut c = setup();
    let inv = invoice(1, AMOUNT);
    pay(&mut c, AMOUNT, signed(inv.clone()));
    set(merchant(), inv.expires_at_ns.0 + PAID_RETENTION_NS - 1);
    assert_eq!(c.prune(10), 0);
    set(merchant(), inv.expires_at_ns.0 + PAID_RETENTION_NS);
    assert_eq!(c.prune(10), 1);
    assert!(c.get_paid(inv.invoice_id.clone()).is_none());
    set(usdc(), inv.expires_at_ns.0 + PAID_RETENTION_NS);
    let refund = match c.ft_on_transfer(payer(), U128(AMOUNT), signed(inv)) {
        PromiseOrValue::Value(v) => v.0,
        PromiseOrValue::Promise(_) => panic!(),
    };
    assert_eq!(refund, AMOUNT);
}

fn usdt() -> AccountId {
    "usdt.near".parse().unwrap()
}

#[test]
fn invoice_for_another_token_is_refunded() {
    let mut c = setup();
    let mut inv = invoice(1, AMOUNT);
    inv.token = usdt();
    assert_eq!(pay(&mut c, AMOUNT, signed(inv)), AMOUNT);
    assert!(rejected_reason().contains("token_mismatch"));
}

#[test]
#[should_panic(expected = "ERR_TOKEN_NOT_ACCEPTED")]
fn unlisted_token_cannot_call_the_receiver() {
    let mut c = setup();
    set(usdt(), T0);
    let mut inv = invoice(1, AMOUNT);
    inv.token = usdt();
    let _ = c.ft_on_transfer(payer(), U128(AMOUNT), signed(inv));
}

#[test]
fn new_token_is_accepted_only_after_the_public_delay() {
    let mut c = setup();
    set_owner(T0);
    c.propose_token(usdt());
    assert_eq!(c.get_config().tokens, vec![usdc()]);
    set(merchant(), T0 + OWNER_DELAY_NS);
    c.apply_token();
    assert_eq!(c.get_config().tokens, vec![usdc(), usdt()]);
    let mut inv = invoice(2, AMOUNT);
    inv.token = usdt();
    inv.expires_at_ns = U64(T0 + OWNER_DELAY_NS + HOUR_NS);
    set(usdt(), T0 + OWNER_DELAY_NS + 1);
    let refund = match c.ft_on_transfer(payer(), U128(AMOUNT), signed(inv)) {
        PromiseOrValue::Value(v) => v.0,
        PromiseOrValue::Promise(_) => panic!(),
    };
    assert_eq!(refund, 0);
    assert_eq!(c.get_accrued_fees(usdt()).0, AMOUNT * 50 / 10_000);
    assert_eq!(c.get_accrued_fees(usdc()).0, 0);
}

#[test]
#[should_panic(expected = "ERR_NOT_READY")]
fn new_token_cannot_apply_early() {
    let mut c = setup();
    set_owner(T0);
    c.propose_token(usdt());
    set(merchant(), T0 + OWNER_DELAY_NS - 1);
    c.apply_token();
}

#[test]
#[should_panic(expected = "ERR_TOKEN_NOT_ACCEPTED")]
fn disabled_token_is_rejected_immediately() {
    let mut c = setup();
    set_owner(T0);
    c.disable_token(usdc());
    set(usdc(), T0 + 1);
    let _ = c.ft_on_transfer(payer(), U128(AMOUNT), signed(invoice(1, AMOUNT)));
}

#[test]
fn owed_balances_are_tracked_per_token() {
    let mut c = setup();
    pay(&mut c, AMOUNT, signed(invoice(1, AMOUNT)));
    set_result(T0 + 2, PromiseResult::Failed);
    c.on_forward(usdc(), merchant(), U128(5), format!("{:032x}", 1));
    assert_eq!(c.get_owed(merchant(), usdc()).0, 5);
    assert_eq!(c.get_owed(merchant(), usdt()).0, 0);
}

#[test]
fn events_are_byte_identical_to_the_previous_contract() {
    let mut c = setup();
    pay(&mut c, AMOUNT, signed(invoice(1, AMOUNT)));
    assert_eq!(
        get_logs()[0],
        r#"EVENT_JSON:{"standard":"obiba","version":"1.0.0","event":"invoice_paid","data":[{"invoice_id":"00000000000000000000000000000001","payer":"u-1.obiba.near","merchant":"cafe.obiba.near","token":"usdc.near","amount":"20000000","fee":"100000"}]}"#
    );
    pay(&mut c, AMOUNT, signed(invoice(1, AMOUNT)));
    assert_eq!(
        get_logs()[0],
        r#"EVENT_JSON:{"standard":"obiba","version":"1.0.0","event":"invoice_rejected","data":[{"payer":"u-1.obiba.near","amount":"20000000","reason":"already_paid"}]}"#
    );
}

#[test]
fn config_view_matches_the_serde_layout() {
    let mut c = setup();
    set_owner(T0);
    c.propose_fee(80);
    let json = c.get_config().to_json();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["tokens"], serde_json::json!(["usdc.near"]));
    assert!(v["pending_token"].is_null());
    assert_eq!(v["network_id"], "mainnet");
    assert_eq!(v["owner"], "owner.near");
    assert!(v["pending_owner"].is_null());
    assert_eq!(v["invoice_key"], pk(&invoice_key()).to_string());
    assert_eq!(v["fee_bps"], 50);
    assert_eq!(v["pending_fee"]["value"], 80);
    assert_eq!(v["pending_fee"]["effective_at_ns"], (T0 + OWNER_DELAY_NS).to_string());
    assert_eq!(v["treasury"], "treasury.obiba.near");
    assert_eq!(v["paused"], false);
    assert_eq!(v.as_object().unwrap().len(), 12);
    assert!(json.starts_with("{\"tokens\":"));
}

#[test]
fn paid_record_json_matches_the_serde_layout() {
    let mut c = setup();
    pay(&mut c, AMOUNT, signed(invoice(1, AMOUNT)));
    let rec = c.get_paid(format!("{:032x}", 1)).unwrap();
    assert_eq!(
        rec.to_json(),
        format!(r#"{{"payer":"u-1.obiba.near","merchant":"cafe.obiba.near","token":"usdc.near","amount":"20000000","fee":"100000","paid_at_ns":"{}"}}"#, T0 + 1)
    );
}

#[test]
fn forward_carries_the_same_transfer_arguments() {
    let mut c = setup();
    pay(&mut c, AMOUNT, signed(invoice(1, AMOUNT)));
    let mut found = None;
    for r in near_sdk::test_utils::get_created_receipts() {
        for a in r.actions {
            if let near_sdk::mock::MockAction::FunctionCallWeight { method_name, args, .. } = a {
                if method_name == b"ft_transfer" {
                    found = Some(String::from_utf8(args).unwrap());
                }
            }
        }
    }
    assert_eq!(
        found.unwrap(),
        r#"{"receiver_id":"cafe.obiba.near","amount":"19900000","memo":"obiba-invoice:00000000000000000000000000000001"}"#
    );
}

#[test]
fn state_round_trips_through_storage_encoding() {
    let mut c = setup();
    set_owner(T0);
    c.propose_token(usdt());
    set_owner(T0);
    c.propose_invoice_key(pk(&SigningKey::from_bytes(&[13u8; 32])));
    set_owner(T0);
    c.propose_owner(merchant());
    pay(&mut c, AMOUNT, signed(invoice(1, AMOUNT)));
    assert_eq!(ObibaPay::decode(&c.encode()).unwrap(), c);
}

#[test]
#[should_panic(expected = "ERR_NOT_A_CALLBACK")]
fn forward_callback_without_a_promise_result_is_refused() {
    let mut c = setup();
    set(me(), T0);
    c.on_forward(usdc(), merchant(), U128(5), format!("{:032x}", 1));
}
