use ed25519_dalek::{Signer, SigningKey};
use near_workspaces::network::Sandbox;
use near_workspaces::operations::Function;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{AccessKey, Gas, KeyType, NearToken, SecretKey};
use near_workspaces::{Account, AccountId, Contract, Worker};
use obiba_common::json::Writer;
use obiba_common::{guardian_preimage, invoice_preimage, Borsh, Invoice, KeyPayload, Op, OpKind, PublicKey, Purpose, TokenPayload, U128, U64};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const ACCOUNT_WASM: &str = "../target/near/obiba_account/obiba_account.wasm";
const PAY_WASM: &str = "../target/near/obiba_pay/obiba_pay.wasm";
const FT_WASM: &str = "../target/near/obiba_mock_ft/obiba_mock_ft.wasm";
const DEVICE_METHODS: &[&str] = &[
    "execute", "pay_invoice", "set_limit", "cancel_recovery", "unfreeze", "add_device",
    "remove_device", "propose_guardian", "rotate_guardian", "add_token", "disable_token",
];
const LIMIT: u128 = 50_000_000;
const MAX_OP: u128 = 500_000_000;
const FEE_BPS: u16 = 50;
const SUPPLY: u128 = 1_000_000_000_000;

struct Env {
    worker: Worker<Sandbox>,
    usdc: Contract,
    pay: Contract,
    parent: Account,
    owner: Account,
    alice: Account,
    merchant: Account,
    user: Account,
    device_sk: SecretKey,
    guardian: SigningKey,
    invoice_key: SigningKey,
}

fn pk_string(key: &SigningKey) -> String {
    format!("ed25519:{}", bs58::encode(key.verifying_key().to_bytes()).into_string())
}

fn sdk_id(id: &AccountId) -> obiba_common::AccountId {
    id.as_str().parse().unwrap()
}

fn opj(o: &Op) -> Value {
    let mut w = Writer::new();
    o.write(&mut w);
    serde_json::from_str(&w.0).unwrap()
}

fn invj(i: &Invoice) -> Value {
    let mut w = Writer::new();
    i.write(&mut w);
    serde_json::from_str(&w.0).unwrap()
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn failures(r: &ExecutionFinalResult) -> Vec<String> {
    r.receipt_failures().iter().map(|f| format!("{:?}", f)).collect()
}

async fn now_ns(worker: &Worker<Sandbox>) -> anyhow::Result<u64> {
    Ok(worker.view_block().await?.timestamp())
}

async fn register(usdc: &Contract, who: &AccountId) -> anyhow::Result<()> {
    let r = usdc
        .as_account()
        .call(usdc.id(), "storage_deposit")
        .args_json(json!({"account_id": who}))
        .deposit(NearToken::from_millinear(125))
        .transact()
        .await?;
    assert!(r.is_success(), "{:?}", failures(&r));
    Ok(())
}

async fn send_usdc(usdc: &Contract, to: &AccountId, amount: u128) -> anyhow::Result<()> {
    let r = usdc
        .as_account()
        .call(usdc.id(), "ft_transfer")
        .args_json(json!({"receiver_id": to, "amount": amount.to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?;
    assert!(r.is_success(), "{:?}", failures(&r));
    Ok(())
}

async fn balance(usdc: &Contract, who: &AccountId) -> anyhow::Result<u128> {
    let v: String = usdc.view("ft_balance_of").args_json(json!({"account_id": who})).await?.json()?;
    Ok(v.parse()?)
}

async fn provision(e: &Env, name: &str, device_sk: &SecretKey) -> anyhow::Result<(Account, ExecutionFinalResult)> {
    let user_id: AccountId = format!("{name}.{}", e.parent.id()).parse()?;
    let wasm = std::fs::read(ACCOUNT_WASM)?;
    let r = e
        .parent
        .batch(&user_id)
        .create_account()
        .transfer(NearToken::from_near(5))
        .deploy(&wasm)
        .add_key(
            device_sk.public_key(),
            AccessKey::function_call_access(&user_id, DEVICE_METHODS, Some(NearToken::from_millinear(250))),
        )
        .call(
            Function::new("new")
                .args_json(json!({
                    "tokens": [{"token": e.usdc.id(), "decimals": 6}],
                    "pay_contract": e.pay.id(),
                    "network_id": "sandbox",
                    "guardian": pk_string(&e.guardian),
                    "device": device_sk.public_key(),
                    "daily_limit": LIMIT.to_string(),
                    "max_op_amount": MAX_OP.to_string(),
                }))
                .gas(Gas::from_tgas(50)),
        )
        .transact()
        .await?;
    Ok((Account::from_secret_key(user_id, device_sk.clone(), &e.worker), r))
}

async fn setup() -> anyhow::Result<Env> {
    let worker = near_workspaces::sandbox().await?;
    let root = worker.root_account()?;
    let make = |name: &'static str, near: u128| {
        let root = root.clone();
        async move {
            root.create_subaccount(name)
                .initial_balance(NearToken::from_near(near))
                .transact()
                .await
                .map(|r| r.into_result().unwrap())
        }
    };
    let usdc_acc = make("usdc", 20).await?;
    let usdc = usdc_acc.deploy(&std::fs::read(FT_WASM)?).await?.into_result()?;
    let r = usdc.call("new").args_json(json!({"owner_id": usdc.id(), "total_supply": SUPPLY.to_string()})).transact().await?;
    assert!(r.is_success());

    let parent = make("obiba", 100).await?;
    let owner = make("owner", 10).await?;
    let alice = make("alice", 10).await?;
    let invoice_key = SigningKey::from_bytes(&[21u8; 32]);
    let guardian = SigningKey::from_bytes(&[22u8; 32]);

    let pay_acc = parent
        .create_subaccount("pay")
        .initial_balance(NearToken::from_near(20))
        .transact()
        .await?
        .into_result()?;
    let pay = pay_acc.deploy(&std::fs::read(PAY_WASM)?).await?.into_result()?;
    let treasury = parent.create_subaccount("treasury").initial_balance(NearToken::from_near(2)).transact().await?.into_result()?;
    let r = pay
        .call("new")
        .args_json(json!({
            "tokens": [usdc.id()],
            "network_id": "sandbox",
            "owner": owner.id(),
            "invoice_key": pk_string(&invoice_key),
            "fee_bps": FEE_BPS,
            "treasury": treasury.id(),
        }))
        .transact()
        .await?;
    assert!(r.is_success(), "{:?}", failures(&r));
    let merchant = parent.create_subaccount("cafe").initial_balance(NearToken::from_near(2)).transact().await?.into_result()?;
    let r = owner
        .call(pay.id(), "register_merchant")
        .args_json(json!({"merchant": merchant.id()}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?;
    assert!(r.is_success(), "{:?}", failures(&r));
    for who in [pay.id(), treasury.id(), merchant.id(), alice.id()] {
        register(&usdc, who).await?;
    }

    let device_sk = SecretKey::from_seed(KeyType::ED25519, "device-1");
    let mut env = Env {
        worker,
        usdc,
        pay,
        parent,
        owner,
        alice,
        merchant,
        user: root.clone(),
        device_sk: device_sk.clone(),
        guardian,
        invoice_key,
    };
    let (user, r) = provision(&env, "u-1", &device_sk).await?;
    assert!(r.is_success(), "{:?}", failures(&r));
    register(&env.usdc, user.id()).await?;
    send_usdc(&env.usdc, user.id(), 1_000_000_000).await?;
    env.user = user;
    Ok(env)
}

fn op(e: &Env, n: u32, receiver: &AccountId, amount: u128, now: u64, kind: OpKind, memo: Option<String>) -> Op {
    Op {
        op_id: format!("{:032x}", n),
        kind,
        token: sdk_id(e.usdc.id()),
        receiver: sdk_id(receiver),
        amount: U128(amount),
        expires_at_ns: U64(now + 10 * 60 * 1_000_000_000),
        memo,
    }
}

fn guardian_sig<T: Borsh>(e: &Env, purpose: Purpose, payload: &T) -> String {
    let preimage = guardian_preimage("sandbox", &sdk_id(e.user.id()), purpose, payload);
    b64(&e.guardian.sign(&Sha256::digest(preimage)).to_bytes())
}

async fn execute(e: &Env, o: &Op, sig: Option<String>) -> anyhow::Result<ExecutionFinalResult> {
    Ok(e.user
        .call(e.user.id(), "execute")
        .args_json(json!({"op": opj(o), "guardian_sig": sig}))
        .gas(Gas::from_tgas(60))
        .transact()
        .await?)
}

async fn get_op(e: &Env, op_id: &str) -> anyhow::Result<Value> {
    Ok(e.user.view(e.user.id(), "get_op").args_json(json!({"op_id": op_id})).await?.json()?)
}

async fn policy(e: &Env) -> anyhow::Result<Value> {
    Ok(e.user.view(e.user.id(), "get_policy").args_json(json!({})).await?.json()?)
}

#[tokio::test]
async fn provisioning_leaves_only_the_device_function_call_key() -> anyhow::Result<()> {
    let e = setup().await?;
    let keys = e.user.view_access_keys().await?;
    assert_eq!(keys.len(), 1, "exactly one key on a Smart Account");
    let k = &keys[0];
    assert_eq!(k.public_key, e.device_sk.public_key());
    assert!(
        matches!(k.access_key.permission, near_workspaces::types::AccessKeyPermission::FunctionCall(_)),
        "the only key must be a function-call key"
    );
    let again = e
        .parent
        .call(e.user.id(), "new")
        .args_json(json!({
            "tokens": [{"token": e.usdc.id(), "decimals": 6}], "pay_contract": e.pay.id(), "network_id": "sandbox",
            "guardian": pk_string(&e.guardian), "device": e.device_sk.public_key(),
            "daily_limit": "1", "max_op_amount": "1"
        }))
        .transact()
        .await?;
    assert!(again.is_failure(), "re-initialization must fail");
    Ok(())
}

#[tokio::test]
async fn device_transfer_settles_and_is_recorded() -> anyhow::Result<()> {
    let e = setup().await?;
    let now = now_ns(&e.worker).await?;
    let o = op(&e, 1, e.alice.id(), 10_000_000, now, OpKind::Transfer, None);
    let r = execute(&e, &o, None).await?;
    assert!(r.is_success(), "{:?}", failures(&r));
    println!("GAS execute: {} TGas", r.total_gas_burnt.as_tgas());
    assert_eq!(balance(&e.usdc, e.alice.id()).await?, 10_000_000);
    assert_eq!(get_op(&e, &o.op_id).await?["status"], "Done");
    assert!(r.logs().iter().any(|l| l.contains("op_executed")));
    let replay = execute(&e, &o, None).await?;
    assert!(replay.is_failure(), "replayed op must fail");
    assert_eq!(balance(&e.usdc, e.alice.id()).await?, 10_000_000);
    Ok(())
}

#[tokio::test]
async fn device_key_cannot_reach_other_contracts_or_callbacks() -> anyhow::Result<()> {
    let e = setup().await?;
    let direct = e
        .user
        .call(e.usdc.id(), "ft_transfer")
        .args_json(json!({"receiver_id": e.alice.id(), "amount": "1"}))
        .transact()
        .await;
    assert!(direct.is_err() || direct.unwrap().is_failure(), "device key must not call the token directly");
    let callback = e
        .user
        .call(e.user.id(), "on_op_result")
        .args_json(json!({"op_id": format!("{:032x}", 1)}))
        .transact()
        .await;
    assert!(callback.is_err() || callback.unwrap().is_failure(), "device key must not call callbacks");
    let stranger = e
        .alice
        .call(e.user.id(), "on_op_result")
        .args_json(json!({"op_id": format!("{:032x}", 1)}))
        .transact()
        .await?;
    assert!(stranger.is_failure(), "callbacks are private");
    let foreign = e
        .alice
        .call(e.user.id(), "execute")
        .args_json(json!({"op": opj(&op(&e, 9, e.alice.id(), 1, now_ns(&e.worker).await?, OpKind::Transfer, None)), "guardian_sig": null}))
        .gas(Gas::from_tgas(60))
        .transact()
        .await?;
    assert!(foreign.is_failure(), "other accounts cannot spend");
    assert_eq!(balance(&e.usdc, e.alice.id()).await?, 0);
    Ok(())
}

#[tokio::test]
async fn over_limit_requires_guardian_onchain() -> anyhow::Result<()> {
    let e = setup().await?;
    let now = now_ns(&e.worker).await?;
    let o = op(&e, 1, e.alice.id(), 200_000_000, now, OpKind::Transfer, None);
    let denied = execute(&e, &o, None).await?;
    assert!(denied.is_failure());
    let r = execute(&e, &o, Some(guardian_sig(&e, Purpose::ExecuteOp, &o))).await?;
    assert!(r.is_success(), "{:?}", failures(&r));
    assert_eq!(balance(&e.usdc, e.alice.id()).await?, 200_000_000);
    assert_eq!(get_op(&e, &o.op_id).await?["cosigned"], true);
    Ok(())
}

#[tokio::test]
async fn transfer_to_unregistered_receiver_fails_and_releases_limit() -> anyhow::Result<()> {
    let e = setup().await?;
    let now = now_ns(&e.worker).await?;
    let nobody: AccountId = "nobody.test.near".parse()?;
    let o = op(&e, 1, &nobody, LIMIT, now, OpKind::Transfer, None);
    let r = execute(&e, &o, None).await?;
    assert!(r.logs().iter().any(|l| l.contains("op_failed")), "{:?}", r.logs());
    assert_eq!(get_op(&e, &o.op_id).await?["status"], "Failed");
    assert_eq!(policy(&e).await?["spent_24h"], "0");
    assert_eq!(balance(&e.usdc, e.user.id()).await?, 1_000_000_000);
    let next = op(&e, 2, e.alice.id(), LIMIT, now, OpKind::Transfer, None);
    assert!(execute(&e, &next, None).await?.is_success());
    Ok(())
}

#[tokio::test]
async fn transfer_call_into_user_account_is_refunded() -> anyhow::Result<()> {
    let e = setup().await?;
    send_usdc(&e.usdc, e.alice.id(), 5_000_000).await?;
    let r = e
        .alice
        .call(e.usdc.id(), "ft_transfer_call")
        .args_json(json!({"receiver_id": e.user.id(), "amount": "5000000", "msg": "hi"}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    assert!(!failures(&r).is_empty(), "receiver has no ft_on_transfer");
    assert_eq!(balance(&e.usdc, e.alice.id()).await?, 5_000_000);
    assert_eq!(balance(&e.usdc, e.user.id()).await?, 1_000_000_000);
    Ok(())
}

fn signed_invoice(e: &Env, id: u32, amount: u128, now: u64, key: &SigningKey) -> Value {
    let invoice = Invoice {
        invoice_id: format!("{:032x}", id),
        merchant: sdk_id(e.merchant.id()),
        token: sdk_id(e.usdc.id()),
        amount: U128(amount),
        fee_bps: FEE_BPS,
        expires_at_ns: U64(now + 3_600_000_000_000),
        reference: Some("table-4".into()),
    };
    let digest = Sha256::digest(invoice_preimage("sandbox", &sdk_id(e.pay.id()), &invoice));
    json!({"invoice": invj(&invoice), "signature": b64(&key.sign(&digest).to_bytes())})
}

async fn pay_invoice(e: &Env, n: u32, invoice: &Value, amount: u128, now: u64) -> anyhow::Result<(Op, ExecutionFinalResult)> {
    let id = invoice["invoice"]["invoice_id"].as_str().unwrap().to_string();
    let o = op(e, n, e.pay.id(), amount, now, OpKind::PayInvoice, Some(id));
    let r = e
        .user
        .call(e.user.id(), "pay_invoice")
        .args_json(json!({"op": opj(&o), "invoice": invoice, "guardian_sig": null}))
        .gas(Gas::from_tgas(200))
        .transact()
        .await?;
    Ok((o, r))
}

#[tokio::test]
async fn invoice_payment_settles_with_fee_and_cannot_be_paid_twice() -> anyhow::Result<()> {
    let e = setup().await?;
    let now = now_ns(&e.worker).await?;
    let amount = 20_000_000u128;
    let fee = amount * FEE_BPS as u128 / 10_000;
    let inv = signed_invoice(&e, 7, amount, now, &e.invoice_key);
    let (o, r) = pay_invoice(&e, 1, &inv, amount, now).await?;
    assert!(r.is_success(), "{:?}", failures(&r));
    println!("GAS pay_invoice: {} TGas", r.total_gas_burnt.as_tgas());
    assert_eq!(balance(&e.usdc, e.merchant.id()).await?, amount - fee);
    assert_eq!(balance(&e.usdc, e.pay.id()).await?, fee);
    assert_eq!(get_op(&e, &o.op_id).await?["status"], "Done");
    let (o2, _) = pay_invoice(&e, 2, &inv, amount, now).await?;
    assert_eq!(get_op(&e, &o2.op_id).await?["status"], "Failed");
    assert_eq!(balance(&e.usdc, e.merchant.id()).await?, amount - fee);
    assert_eq!(balance(&e.usdc, e.user.id()).await?, 1_000_000_000 - amount);
    assert_eq!(policy(&e).await?["spent_24h"], amount.to_string());
    Ok(())
}

#[tokio::test]
async fn forged_invoice_is_refunded_to_the_account() -> anyhow::Result<()> {
    let e = setup().await?;
    let now = now_ns(&e.worker).await?;
    let forged = signed_invoice(&e, 7, 20_000_000, now, &SigningKey::from_bytes(&[99u8; 32]));
    let (o, r) = pay_invoice(&e, 1, &forged, 20_000_000, now).await?;
    assert!(r.logs().iter().any(|l| l.contains("signature_invalid")), "{:?}", r.logs());
    assert_eq!(get_op(&e, &o.op_id).await?["status"], "Failed");
    assert_eq!(balance(&e.usdc, e.user.id()).await?, 1_000_000_000);
    assert_eq!(balance(&e.usdc, e.merchant.id()).await?, 0);
    assert_eq!(policy(&e).await?["spent_24h"], "0");
    Ok(())
}

#[tokio::test]
async fn fake_token_cannot_pay_an_invoice() -> anyhow::Result<()> {
    let e = setup().await?;
    let now = now_ns(&e.worker).await?;
    let fake_acc = e.worker.root_account()?.create_subaccount("fake").initial_balance(NearToken::from_near(10)).transact().await?.into_result()?;
    let fake = fake_acc.deploy(&std::fs::read(FT_WASM)?).await?.into_result()?;
    fake.call("new").args_json(json!({"owner_id": fake.id(), "total_supply": SUPPLY.to_string()})).transact().await?.into_result()?;
    for who in [e.pay.id()] {
        register(&fake, who).await?;
    }
    let inv = signed_invoice(&e, 8, 20_000_000, now, &e.invoice_key);
    let r = fake
        .as_account()
        .call(fake.id(), "ft_transfer_call")
        .args_json(json!({"receiver_id": e.pay.id(), "amount": "20000000", "msg": inv["invoice"].to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(150))
        .transact()
        .await?;
    assert!(failures(&r).iter().any(|f| f.contains("ERR_TOKEN_NOT_ACCEPTED")), "{:?}", failures(&r));
    assert_eq!(balance(&fake, e.pay.id()).await?, 0);
    let paid: Option<Value> = e.pay.view("get_paid").args_json(json!({"invoice_id": format!("{:032x}", 8)})).await?.json()?;
    assert!(paid.is_none());
    Ok(())
}

#[tokio::test]
async fn failed_merchant_forward_is_owed_and_retryable() -> anyhow::Result<()> {
    let e = setup().await?;
    let now = now_ns(&e.worker).await?;
    let late = e.parent.create_subaccount("late").initial_balance(NearToken::from_near(2)).transact().await?.into_result()?;
    let r = e.owner.call(e.pay.id(), "register_merchant").args_json(json!({"merchant": late.id()})).deposit(NearToken::from_yoctonear(1)).transact().await?;
    assert!(r.is_success());
    let invoice = Invoice {
        invoice_id: format!("{:032x}", 9),
        merchant: sdk_id(late.id()),
        token: sdk_id(e.usdc.id()),
        amount: U128(10_000_000),
        fee_bps: FEE_BPS,
        expires_at_ns: U64(now + 3_600_000_000_000),
        reference: None,
    };
    let digest = Sha256::digest(invoice_preimage("sandbox", &sdk_id(e.pay.id()), &invoice));
    let inv = json!({"invoice": invj(&invoice), "signature": b64(&e.invoice_key.sign(&digest).to_bytes())});
    let (o, r) = pay_invoice(&e, 1, &inv, 10_000_000, now).await?;
    assert!(r.logs().iter().any(|l| l.contains("forward_failed")), "{:?}", r.logs());
    assert_eq!(get_op(&e, &o.op_id).await?["status"], "Done");
    let net = 10_000_000 - 10_000_000 * FEE_BPS as u128 / 10_000;
    let owed: String = e.pay.view("get_owed").args_json(json!({"merchant": late.id(), "token": e.usdc.id()})).await?.json()?;
    assert_eq!(owed, net.to_string());
    register(&e.usdc, late.id()).await?;
    let retry = e.alice.call(e.pay.id(), "retry_owed").args_json(json!({"merchant": late.id(), "token": e.usdc.id()})).gas(Gas::from_tgas(60)).transact().await?;
    assert!(retry.is_success(), "{:?}", failures(&retry));
    assert_eq!(balance(&e.usdc, late.id()).await?, net);
    Ok(())
}

#[tokio::test]
async fn device_management_changes_real_access_keys() -> anyhow::Result<()> {
    let e = setup().await?;
    let new_sk = SecretKey::from_seed(KeyType::ED25519, "device-2");
    let new_pk: PublicKey = new_sk.public_key().to_string().parse().unwrap();
    let sig = guardian_sig(&e, Purpose::AddDevice, &KeyPayload { public_key: new_pk.clone(), guardian_nonce: U64(0) });
    let r = e
        .user
        .call(e.user.id(), "add_device")
        .args_json(json!({"public_key": new_pk.to_string(), "guardian_sig": sig, "guardian_nonce": "0"}))
        .gas(Gas::from_tgas(60))
        .transact()
        .await?;
    assert!(r.is_success(), "{:?}", failures(&r));
    assert_eq!(e.user.view_access_keys().await?.len(), 2);
    let second = Account::from_secret_key(e.user.id().clone(), new_sk.clone(), &e.worker);
    let now = now_ns(&e.worker).await?;
    let o = op(&e, 3, e.alice.id(), 1_000_000, now, OpKind::Transfer, None);
    let r = second.call(e.user.id(), "execute").args_json(json!({"op": opj(&o), "guardian_sig": null})).gas(Gas::from_tgas(60)).transact().await?;
    assert!(r.is_success(), "{:?}", failures(&r));
    let old_pk: PublicKey = e.device_sk.public_key().to_string().parse().unwrap();
    let sig = guardian_sig(&e, Purpose::RemoveDevice, &KeyPayload { public_key: old_pk.clone(), guardian_nonce: U64(1) });
    let r = second
        .call(e.user.id(), "remove_device")
        .args_json(json!({"public_key": old_pk.to_string(), "guardian_sig": sig, "guardian_nonce": "1"}))
        .gas(Gas::from_tgas(60))
        .transact()
        .await?;
    assert!(r.is_success(), "{:?}", failures(&r));
    let keys = e.user.view_access_keys().await?;
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].public_key, new_sk.public_key());
    let o = op(&e, 4, e.alice.id(), 1, now, OpKind::Transfer, None);
    let old = execute(&e, &o, None).await;
    assert!(old.is_err() || old.unwrap().is_failure(), "removed key must not work");
    Ok(())
}

#[tokio::test]
async fn a_second_stablecoin_is_enabled_without_redeploying_and_shares_the_limit() -> anyhow::Result<()> {
    let e = setup().await?;
    let usdt_acc = e.worker.root_account()?.create_subaccount("usdt").initial_balance(NearToken::from_near(10)).transact().await?.into_result()?;
    let usdt = usdt_acc.deploy(&std::fs::read(FT_WASM)?).await?.into_result()?;
    usdt.call("new").args_json(json!({"owner_id": usdt.id(), "total_supply": SUPPLY.to_string()})).transact().await?.into_result()?;
    for who in [e.user.id(), e.alice.id()] {
        register(&usdt, who).await?;
    }
    send_usdc(&usdt, e.user.id(), 100_000_000).await?;
    let now = now_ns(&e.worker).await?;
    let mut stray = op(&e, 1, e.alice.id(), 1_000_000, now, OpKind::Transfer, None);
    stray.token = sdk_id(usdt.id());
    assert!(execute(&e, &stray, None).await?.is_failure(), "unregistered token needs the guardian");
    let payload = TokenPayload { token: sdk_id(usdt.id()), decimals: 6, guardian_nonce: U64(0) };
    let r = e
        .user
        .call(e.user.id(), "add_token")
        .args_json(json!({"token": usdt.id(), "decimals": 6, "guardian_sig": guardian_sig(&e, Purpose::AddToken, &payload), "guardian_nonce": "0"}))
        .transact()
        .await?;
    assert!(r.is_success(), "{:?}", failures(&r));
    let a = op(&e, 2, e.alice.id(), 30_000_000, now, OpKind::Transfer, None);
    assert!(execute(&e, &a, None).await?.is_success());
    let mut b = op(&e, 3, e.alice.id(), 20_000_000, now, OpKind::Transfer, None);
    b.token = sdk_id(usdt.id());
    assert!(execute(&e, &b, None).await?.is_success());
    assert_eq!(balance(&usdt, e.alice.id()).await?, 20_000_000);
    let mut c = op(&e, 4, e.alice.id(), 1, now, OpKind::Transfer, None);
    c.token = sdk_id(usdt.id());
    assert!(execute(&e, &c, None).await?.is_failure(), "combined spend across tokens is capped by one limit");
    assert_eq!(policy(&e).await?["spent_24h"], LIMIT.to_string());
    Ok(())
}
