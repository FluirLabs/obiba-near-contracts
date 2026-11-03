use crate::types::{AccountId, PublicKey};
use alloc::string::String;
use alloc::vec::Vec;

const REG: u64 = 0;

#[cfg_attr(target_arch = "wasm32", link(wasm_import_module = "env"))]
extern "C-unwind" {
    fn read_register(register_id: u64, ptr: u64);
    fn register_len(register_id: u64) -> u64;
    fn current_account_id(register_id: u64);
    fn predecessor_account_id(register_id: u64);
    fn input(register_id: u64);
    fn block_timestamp() -> u64;
    fn attached_deposit(balance_ptr: u64);
    fn sha256(value_len: u64, value_ptr: u64, register_id: u64);
    fn ed25519_verify(sig_len: u64, sig_ptr: u64, msg_len: u64, msg_ptr: u64, pub_key_len: u64, pub_key_ptr: u64) -> u64;
    fn value_return(value_len: u64, value_ptr: u64);
    fn panic_utf8(len: u64, ptr: u64) -> !;
    fn log_utf8(len: u64, ptr: u64);
    fn promise_batch_create(account_id_len: u64, account_id_ptr: u64) -> u64;
    fn promise_batch_then(promise_index: u64, account_id_len: u64, account_id_ptr: u64) -> u64;
    fn promise_batch_action_function_call_weight(
        promise_index: u64,
        function_name_len: u64,
        function_name_ptr: u64,
        arguments_len: u64,
        arguments_ptr: u64,
        amount_ptr: u64,
        gas: u64,
        weight: u64,
    );
    fn promise_batch_action_add_key_with_function_call(
        promise_index: u64,
        public_key_len: u64,
        public_key_ptr: u64,
        nonce: u64,
        allowance_ptr: u64,
        receiver_id_len: u64,
        receiver_id_ptr: u64,
        function_names_len: u64,
        function_names_ptr: u64,
    );
    fn promise_batch_action_delete_key(promise_index: u64, public_key_len: u64, public_key_ptr: u64);
    fn promise_results_count() -> u64;
    fn promise_result(result_idx: u64, register_id: u64) -> u64;
    fn promise_return(promise_id: u64);
    fn storage_write(key_len: u64, key_ptr: u64, value_len: u64, value_ptr: u64, register_id: u64) -> u64;
    fn storage_read(key_len: u64, key_ptr: u64, register_id: u64) -> u64;
    fn storage_remove(key_len: u64, key_ptr: u64, register_id: u64) -> u64;
    fn storage_has_key(key_len: u64, key_ptr: u64) -> u64;
}

fn ptr(b: &[u8]) -> u64 {
    b.as_ptr() as usize as u64
}

fn read_reg() -> Vec<u8> {
    let len = unsafe { register_len(REG) };
    if len == u64::MAX {
        return Vec::new();
    }
    let mut v = alloc::vec![0u8; len as usize];
    unsafe { read_register(REG, v.as_mut_ptr() as usize as u64) };
    v
}

fn reg_string() -> String {
    String::from_utf8(read_reg()).unwrap_or_else(|_| panic_str("ERR_UTF8"))
}

pub fn panic_str(msg: &str) -> ! {
    unsafe { panic_utf8(msg.len() as u64, ptr(msg.as_bytes())) }
}

pub fn require(cond: bool, msg: &str) {
    if !cond {
        panic_str(msg)
    }
}

pub fn log(msg: &str) {
    unsafe { log_utf8(msg.len() as u64, ptr(msg.as_bytes())) }
}

pub fn now() -> u64 {
    unsafe { block_timestamp() }
}

pub fn current_account() -> AccountId {
    unsafe { current_account_id(REG) };
    AccountId::from_trusted(reg_string())
}

pub fn predecessor() -> AccountId {
    unsafe { predecessor_account_id(REG) };
    AccountId::from_trusted(reg_string())
}

pub fn input_bytes() -> Vec<u8> {
    unsafe { input(REG) };
    read_reg()
}

pub fn deposit() -> u128 {
    let mut buf = [0u8; 16];
    unsafe { attached_deposit(buf.as_mut_ptr() as usize as u64) };
    u128::from_le_bytes(buf)
}

pub fn sha256_array(data: &[u8]) -> [u8; 32] {
    unsafe { sha256(data.len() as u64, ptr(data), REG) };
    let mut out = [0u8; 32];
    out.copy_from_slice(&read_reg());
    out
}

pub fn verify_ed25519(signature: &[u8; 64], message: &[u8], key: &[u8; 32]) -> bool {
    unsafe { ed25519_verify(64, ptr(signature), message.len() as u64, ptr(message), 32, ptr(key)) == 1 }
}

pub fn ret(bytes: &[u8]) {
    unsafe { value_return(bytes.len() as u64, ptr(bytes)) }
}

pub fn read(key: &[u8]) -> Option<Vec<u8>> {
    match unsafe { storage_read(key.len() as u64, ptr(key), REG) } {
        1 => Some(read_reg()),
        _ => None,
    }
}

pub fn write(key: &[u8], value: &[u8]) {
    unsafe { storage_write(key.len() as u64, ptr(key), value.len() as u64, ptr(value), REG) };
}

pub fn remove(key: &[u8]) -> Option<Vec<u8>> {
    match unsafe { storage_remove(key.len() as u64, ptr(key), REG) } {
        1 => Some(read_reg()),
        _ => None,
    }
}

pub fn has(key: &[u8]) -> bool {
    unsafe { storage_has_key(key.len() as u64, ptr(key)) == 1 }
}

pub fn results_count() -> u64 {
    unsafe { promise_results_count() }
}

pub fn result_bounded(index: u64, max_len: usize) -> Result<Vec<u8>, ()> {
    match unsafe { promise_result(index, REG) } {
        1 => {
            if unsafe { register_len(REG) } > max_len as u64 {
                return Err(());
            }
            Ok(read_reg())
        }
        2 => Err(()),
        _ => panic_str("ERR_PROMISE_NOT_READY"),
    }
}

pub fn assert_no_deposit(method: &str) {
    if deposit() != 0 {
        let mut msg = String::from("Method ");
        msg.push_str(method);
        msg.push_str(" doesn't accept deposit");
        panic_str(&msg);
    }
}

pub fn assert_private(method: &str) {
    if predecessor() != current_account() {
        let mut msg = String::from("Method ");
        msg.push_str(method);
        msg.push_str(" is private");
        panic_str(&msg);
    }
}

pub fn assert_one_yocto() {
    require(deposit() == 1, "Requires attached deposit of exactly 1 yoctoNEAR");
}

pub fn bad_args() -> ! {
    panic_str("Failed to deserialize input from JSON.")
}

#[must_use]
pub struct Promise(u64);

impl Promise {
    pub fn new(account: &AccountId) -> Self {
        Self(unsafe { promise_batch_create(account.len() as u64, ptr(account.as_str().as_bytes())) })
    }

    pub fn then(self, account: &AccountId) -> Self {
        Self(unsafe { promise_batch_then(self.0, account.len() as u64, ptr(account.as_str().as_bytes())) })
    }

    pub fn call(self, method: &str, args: &[u8], deposit: u128, gas: u64) -> Self {
        let amount = deposit.to_le_bytes();
        unsafe {
            promise_batch_action_function_call_weight(
                self.0,
                method.len() as u64,
                ptr(method.as_bytes()),
                args.len() as u64,
                ptr(args),
                ptr(&amount),
                gas,
                1,
            )
        };
        self
    }

    pub fn add_key(self, key: &PublicKey, allowance: u128, receiver: &AccountId, methods: &str) -> Self {
        let amount = allowance.to_le_bytes();
        let data = key.as_bytes();
        unsafe {
            promise_batch_action_add_key_with_function_call(
                self.0,
                data.len() as u64,
                ptr(data),
                0,
                ptr(&amount),
                receiver.len() as u64,
                ptr(receiver.as_str().as_bytes()),
                methods.len() as u64,
                ptr(methods.as_bytes()),
            )
        };
        self
    }

    pub fn delete_key(self, key: &PublicKey) -> Self {
        let data = key.as_bytes();
        unsafe { promise_batch_action_delete_key(self.0, data.len() as u64, ptr(data)) };
        self
    }

    pub fn as_return(self) {
        unsafe { promise_return(self.0) }
    }

    pub fn detach(self) {}

    pub fn index(&self) -> u64 {
        self.0
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use core::alloc::{GlobalAlloc, Layout};

    const PAGE: usize = 65536;

    struct Bump;

    static mut NEXT: usize = 0;
    static mut LAST: usize = 0;

    fn grow_to(end: usize) -> bool {
        let have = core::arch::wasm32::memory_size(0) * PAGE;
        if end <= have {
            return true;
        }
        let pages = (end - have).div_ceil(PAGE);
        core::arch::wasm32::memory_grow(0, pages) != usize::MAX
    }

    unsafe impl GlobalAlloc for Bump {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let mut next = NEXT;
            if next == 0 {
                next = core::arch::wasm32::memory_size(0) * PAGE;
            }
            let start = (next + layout.align() - 1) & !(layout.align() - 1);
            let Some(end) = start.checked_add(layout.size()) else {
                return core::ptr::null_mut();
            };
            if !grow_to(end) {
                return core::ptr::null_mut();
            }
            NEXT = end;
            LAST = start;
            start as *mut u8
        }

        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}

        unsafe fn realloc(&self, p: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            let addr = p as usize;
            if addr == LAST && addr + layout.size() == NEXT {
                let Some(end) = addr.checked_add(new_size) else {
                    return core::ptr::null_mut();
                };
                if end <= NEXT || grow_to(end) {
                    NEXT = end.max(addr);
                    return p;
                }
                return core::ptr::null_mut();
            }
            let fresh = self.alloc(Layout::from_size_align_unchecked(new_size, layout.align()));
            if !fresh.is_null() {
                core::ptr::copy_nonoverlapping(p, fresh, layout.size().min(new_size));
            }
            fresh
        }
    }

    #[global_allocator]
    static ALLOC: Bump = Bump;

    #[panic_handler]
    fn panic(_: &core::panic::PanicInfo) -> ! {
        super::panic_str("ERR_PANIC")
    }
}
