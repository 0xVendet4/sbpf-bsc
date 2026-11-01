//! Fonte da verdade do runtime: executa programas Solana reais (os `.so` de exemplo do agave,
//! sBPF v3) no Mollusk — o mesmo `solana-program-runtime` da mainnet — e grava em
//! `fixtures/solana/programs.json` tudo o que o `SolanaVM.sol` precisa reproduzir (o ELF de cada
//! programa fica em `programs`, uma vez só):
//!
//!   - o ELF, o program id e o loader;
//!   - as contas e os dados da instrução, e o input serializado (ABIv1, regiões) exatamente como
//!     o agave entrega ao programa (`serialize_parameters`);
//!   - o resultado: erro/sucesso, compute units, return data, logs e as contas depois.
//!
//! Uso: `cargo run --release -- <dir com os .so>` (de dentro de `reference-runtime/`).

use mollusk_svm::Mollusk;
use serde_json::{json, Value};
use solana_account::{Account, AccountSharedData};
use solana_instruction::{AccountMeta, Instruction};
use solana_program_runtime::serialization::serialize_parameters;
use solana_pubkey::Pubkey;
use solana_rent::Rent;
use solana_sdk_ids::{bpf_loader_upgradeable, incinerator};
use solana_svm_log_collector::LogCollector;
use solana_transaction_context::{instruction_accounts::InstructionAccount, transaction::TransactionContext};
use std::{collections::HashMap, fs, path::Path};

fn hex(b: &[u8]) -> String {
    format!("0x{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>())
}

fn key(seed: u8) -> Pubkey {
    let mut b = [seed; 32];
    b[0] = 0x5b; // evita chaves "bonitas" que coincidam com ids conhecidos
    Pubkey::new_from_array(b)
}

struct Case<'a> {
    name: &'a str,
    program: &'a str,
    accounts: Vec<(Pubkey, Account)>,
    metas: Vec<AccountMeta>,
    data: Vec<u8>,
}

fn account(owner: Pubkey, lamports: u64, data: Vec<u8>) -> Account {
    Account { lamports, data, owner, executable: false, rent_epoch: 0 }
}

/// Serializa os parâmetros com o serializador do agave (mesmas flags que a mainnet: ajustes do
/// espaço de endereçamento, mapeamento direto e ponteiros diretos — SIMD-0219/0449).
fn serialize(program_id: &Pubkey, accounts: &[(Pubkey, Account)], metas: &[AccountMeta], data: &[u8]) -> (Vec<Value>, u64) {
    let mut keys: Vec<Pubkey> = vec![];
    for m in metas {
        if !keys.contains(&m.pubkey) {
            keys.push(m.pubkey);
        }
    }
    let program_index = keys.len() as u16;
    let mut tx_accounts: Vec<(Pubkey, AccountSharedData)> = keys
        .iter()
        .map(|k| (*k, AccountSharedData::from(accounts.iter().find(|(kk, _)| kk == k).expect("conta faltando").1.clone())))
        .collect();
    let program_account = Account { lamports: 1, data: vec![], owner: bpf_loader_upgradeable::id(), executable: true, rent_epoch: 0 };
    tx_accounts.push((*program_id, program_account.into()));
    let mut tc = TransactionContext::new(tx_accounts, Rent::default(), 1, 1, 1);
    let ix_accounts: Vec<InstructionAccount> = metas
        .iter()
        .map(|m| InstructionAccount::new(keys.iter().position(|k| *k == m.pubkey).unwrap() as u16, m.is_signer, m.is_writable))
        .collect();
    tc.configure_top_level_instruction_for_tests(program_index, ix_accounts, data.to_vec()).unwrap();
    tc.push().unwrap();
    let ic = tc.get_current_instruction_context().unwrap();
    let (_mem, regions, _meta, ix_off) = serialize_parameters(&ic, true, true, true).unwrap();
    let out = regions
        .iter()
        .map(|r| {
            let range = r.vm_addr_range();
            let buf = r.host_buffer();
            let bytes: &[u8] = unsafe { &*buf.ptr() };
            json!({ "vaddr": range.start, "len": range.end - range.start, "writable": buf.is_mutable(), "bytes": hex(bytes) })
        })
        .collect();
    (out, ix_off as u64)
}

fn account_json(k: &Pubkey, a: &Account) -> Value {
    json!({
        "key": hex(k.as_ref()),
        "owner": hex(a.owner.as_ref()),
        "lamports": a.lamports,
        "data": hex(&a.data),
        "executable": a.executable,
    })
}

fn run_case(dir: &Path, c: &Case) -> Value {
    run_case_with(dir, c, key(0xee), bpf_loader_upgradeable::id(), false)
}

/// Bytes da sysvar Rent como o agave entrega em `sol_get_sysvar` (serialização bincode, 17 bytes).
fn rent_bytes(r: &Rent) -> Vec<u8> {
    #[allow(deprecated)]
    [r.lamports_per_byte.to_le_bytes().to_vec(), r.exemption_threshold.to_vec(), vec![r.burn_percent]].concat()
}

fn run_case_with(dir: &Path, c: &Case, program_id: Pubkey, loader: Pubkey, with_rent: bool) -> Value {
    let elf = fs::read(dir.join(format!("{}.so", c.program))).unwrap_or_else(|_| panic!("faltando {}.so", c.program));
    let mut mollusk = Mollusk::default();
    mollusk.add_program_with_loader_and_elf(&program_id, &loader, &elf);
    mollusk.config.rent_exempt_checks = false; // o SolanaStore não cobra rent (ver README)
    mollusk.sysvars.clock.slot = 123_456;
    mollusk.sysvars.clock.epoch_start_timestamp = 1_700_000_000;
    mollusk.sysvars.clock.epoch = 42;
    mollusk.sysvars.clock.leader_schedule_epoch = 43;
    mollusk.sysvars.clock.unix_timestamp = 1_700_001_234;
    let logger = LogCollector::new_ref();
    mollusk.logger = Some(logger.clone());

    let instruction = Instruction::new_with_bytes(program_id, &c.data, c.metas.clone());
    let result = mollusk.process_instruction(&instruction, &c.accounts);
    let logs: Vec<String> = logger.borrow().get_recorded_content().to_vec();
    let (regions, ix_off) = serialize(&program_id, &c.accounts, &c.metas, &c.data);

    let clock = &mollusk.sysvars.clock;
    let mut clock_bytes = vec![];
    clock_bytes.extend_from_slice(&clock.slot.to_le_bytes());
    clock_bytes.extend_from_slice(&clock.epoch_start_timestamp.to_le_bytes());
    clock_bytes.extend_from_slice(&clock.epoch.to_le_bytes());
    clock_bytes.extend_from_slice(&clock.leader_schedule_epoch.to_le_bytes());
    clock_bytes.extend_from_slice(&clock.unix_timestamp.to_le_bytes());

    let err = match &result.raw_result {
        Ok(()) => Value::Null,
        Err(e) => json!(format!("{e:?}")),
    };
    let mut sysvars = json!({ "clock": hex(&clock_bytes) });
    if with_rent {
        sysvars["rent"] = json!(hex(&rent_bytes(&mollusk.sysvars.rent)));
    }
    json!({
        "name": c.name,
        "program": c.program,
        "programId": hex(program_id.as_ref()),
        "programIdBase58": program_id.to_string(),
        "loader": hex(loader.as_ref()),
        "maxCu": mollusk.compute_budget.compute_unit_limit,
        "accounts": c.accounts.iter().map(|(k, a)| account_json(k, a)).collect::<Vec<_>>(),
        "metas": c.metas.iter().map(|m| json!({ "key": hex(m.pubkey.as_ref()), "isSigner": m.is_signer, "isWritable": m.is_writable })).collect::<Vec<_>>(),
        "data": hex(&c.data),
        "regions": regions,
        "ixDataOffset": ix_off,
        "sysvars": sysvars,
        "expect": {
            "error": err,
            "cu": result.compute_units_consumed,
            "returnData": hex(&result.return_data),
            "logs": logs,
            "accounts": result.resulting_accounts.iter().map(|(k, a)| account_json(k, a)).collect::<Vec<_>>(),
        }
    })
}

// ------------------------------------------------------------------ programa de teste (PDAs e CPI)
//
// Programa sBPF v3 escrito à mão (assembly montado aqui, ELF mínimo com só o segmento de código),
// para exercitar o que os programas de exemplo do agave não exercitam: sol_create_program_address,
// sol_try_find_program_address e CPI pela ABI C e Rust com seeds de signatário. Os dados da
// instrução trazem os argumentos da syscall (ponteiros absolutos montados pelo gerador):
//   [op][a1][a2][a3][a4][a5][watch][heapLen][heap...]
// O programa copia `heap` para o início do heap (0x300000000), chama a syscall `op`
// (0 create, 1 try_find, 2 invoke_signed_c, 3 invoke_signed_rust) com r1..r5 = a1..a5 e loga o
// resultado (r0, bump e o endereço; ou r0 e o u64 em `watch` depois da CPI).

enum A {
    I(u8, u8, u8, i16, i32),
    J(u8, u8, i32, &'static str),
    S(&'static str),
    L(&'static str),
}

fn assemble(prog: &[A]) -> Vec<u8> {
    let mut labels = HashMap::new();
    let mut pc = 0i64;
    for a in prog {
        match a {
            A::L(n) => {
                labels.insert(*n, pc);
            }
            _ => pc += 1,
        }
    }
    let mut out = vec![];
    pc = 0;
    for a in prog {
        let (opc, dst, src, off, imm) = match a {
            A::L(_) => continue,
            A::I(o, d, s, off, imm) => (*o, *d, *s, *off, *imm),
            A::J(o, d, imm, l) => (*o, *d, 0u8, (labels[l] - pc - 1) as i16, *imm),
            A::S(name) => (0x85, 0, 0, 0, solana_sbpf::ebpf::hash_symbol_name(name.as_bytes()) as i32),
        };
        out.push(opc);
        out.push(dst | (src << 4));
        out.extend_from_slice(&off.to_le_bytes());
        out.extend_from_slice(&imm.to_le_bytes());
        pc += 1;
    }
    out
}

/// ELF sBPF v3 mínimo (SIMD-0189): cabeçalho, um program header PF_X em 1<<32 e o código.
fn elf_v3(text: &[u8]) -> Vec<u8> {
    let mut e = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    e.extend_from_slice(&3u16.to_le_bytes()); // ET_DYN
    e.extend_from_slice(&247u16.to_le_bytes()); // EM_BPF
    e.extend_from_slice(&1u32.to_le_bytes());
    e.extend_from_slice(&(1u64 << 32).to_le_bytes()); // entrada
    e.extend_from_slice(&64u64.to_le_bytes()); // phoff
    e.extend_from_slice(&0u64.to_le_bytes()); // shoff
    e.extend_from_slice(&3u32.to_le_bytes()); // e_flags = v3
    for v in [64u16, 56, 1, 64, 0, 0] {
        e.extend_from_slice(&v.to_le_bytes());
    }
    e.extend_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    e.extend_from_slice(&1u32.to_le_bytes()); // PF_X
    for v in [120u64, 1 << 32, 1 << 32, text.len() as u64, text.len() as u64, 8] {
        e.extend_from_slice(&v.to_le_bytes());
    }
    e.extend_from_slice(text);
    e
}

fn pda_program() -> Vec<u8> {
    use A::*;
    let mov = |d: u8, imm: i32| I(0xb7, d, 0, 0, imm);
    let movr = |d: u8, s: u8| I(0xbf, d, s, 0, 0);
    let ldxdw = |d: u8, s: u8, off: i16| I(0x79, d, s, off, 0);
    let prog = vec![
        movr(9, 2),
        ldxdw(6, 9, 0),
        ldxdw(7, 9, 32),
        ldxdw(8, 9, 40),
        ldxdw(3, 9, 56),
        J(0x15, 3, 0, "args"),
        mov(1, 3),
        I(0x67, 1, 0, 0, 32), // r1 = 0x300000000
        movr(2, 9),
        I(0x07, 2, 0, 0, 64),
        S("sol_memcpy_"),
        L("args"),
        ldxdw(1, 9, 8),
        ldxdw(2, 9, 16),
        ldxdw(3, 9, 24),
        movr(4, 7),
        movr(5, 8),
        J(0x15, 6, 0, "create"),
        J(0x15, 6, 1, "find"),
        J(0x15, 6, 2, "invoke_c"),
        J(0x15, 6, 3, "invoke_rust"),
        mov(0, 99),
        I(0x95, 0, 0, 0, 0),
        L("create"),
        S("sol_create_program_address"),
        J(0x05, 0, 0, "after_pda"),
        L("find"),
        S("sol_try_find_program_address"),
        J(0x05, 0, 0, "after_pda"),
        L("invoke_c"),
        S("sol_invoke_signed_c"),
        J(0x05, 0, 0, "after_invoke"),
        L("invoke_rust"),
        S("sol_invoke_signed_rust"),
        J(0x05, 0, 0, "after_invoke"),
        L("after_pda"),
        movr(6, 0),
        movr(1, 6),
        mov(2, 0),
        J(0x15, 8, 0, "logres"),
        I(0x71, 2, 8, 0, 0), // ldxb r2, [r8]
        L("logres"),
        mov(3, 0),
        mov(4, 0),
        mov(5, 0),
        S("sol_log_64_"),
        J(0x55, 6, 0, "done"),
        movr(1, 7),
        S("sol_log_pubkey"),
        L("done"),
        mov(0, 0),
        I(0x95, 0, 0, 0, 0),
        L("after_invoke"),
        ldxdw(3, 9, 48),
        movr(1, 0),
        mov(2, 0),
        J(0x15, 3, 0, "logw"),
        ldxdw(2, 3, 0),
        L("logw"),
        mov(3, 0),
        mov(4, 0),
        mov(5, 0),
        S("sol_log_64_"),
        mov(0, 0),
        I(0x95, 0, 0, 0, 0),
    ];
    elf_v3(&assemble(&prog))
}

const HEAP: u64 = 0x3_0000_0000;
const INPUT: u64 = 0x4_0000_0000;

/// Bytes que o programa copia para o heap; `put` devolve o endereço virtual (alinhado a 8).
#[derive(Default)]
struct Heap {
    bytes: Vec<u8>,
}

impl Heap {
    fn put(&mut self, b: &[u8]) -> u64 {
        while self.bytes.len() % 8 != 0 {
            self.bytes.push(0);
        }
        let a = HEAP + self.bytes.len() as u64;
        self.bytes.extend_from_slice(b);
        a
    }
    /// Array de VmSlice (ptr, len) para as seeds.
    fn seeds(&mut self, list: &[Vec<u8>]) -> u64 {
        let mut arr = vec![];
        for s in list {
            let a = if s.is_empty() { HEAP } else { self.put(s) };
            arr.extend_from_slice(&a.to_le_bytes());
            arr.extend_from_slice(&(s.len() as u64).to_le_bytes());
        }
        self.put(&arr)
    }
    /// Array de signatários (VmSlice de VmSlices).
    fn signers(&mut self, list: &[Vec<Vec<u8>>]) -> u64 {
        let mut arr = vec![];
        for seeds in list {
            let a = self.seeds(seeds);
            arr.extend_from_slice(&a.to_le_bytes());
            arr.extend_from_slice(&(seeds.len() as u64).to_le_bytes());
        }
        self.put(&arr)
    }
}

fn pda_ix(op: u64, a: [u64; 5], watch: u64, heap: &Heap) -> Vec<u8> {
    let mut d = vec![];
    for v in [op, a[0], a[1], a[2], a[3], a[4], watch, heap.bytes.len() as u64] {
        d.extend_from_slice(&v.to_le_bytes());
    }
    d.extend_from_slice(&heap.bytes);
    d
}

/// Endereço do marcador de cada meta no input serializado (ABIv1 com espaço reservado).
fn markers(accounts: &[(Pubkey, Account)], metas: &[AccountMeta]) -> Vec<u64> {
    let mut v = INPUT + 8;
    let mut seen: Vec<(Pubkey, u64)> = vec![];
    let mut out = vec![];
    for m in metas {
        if let Some((_, a)) = seen.iter().find(|(k, _)| *k == m.pubkey) {
            out.push(*a);
            v += 8;
            continue;
        }
        out.push(v);
        seen.push((m.pubkey, v));
        let len = accounts.iter().find(|(k, _)| *k == m.pubkey).unwrap().1.data.len() as u64;
        v += 88 + len + 10240 + (8 - len % 8) % 8 + 8;
    }
    out
}

/// Conta da CPI: chave, marcador no input, tamanho dos dados, signer, writable.
struct CpiAcc {
    key: Pubkey,
    m: u64,
    len: u64,
    signer: bool,
    writable: bool,
}

/// SolInstruction + SolAccountMeta[] + SolAccountInfo[] (ABI C) no heap: devolve (ix, infos).
fn cpi_c(h: &mut Heap, program: &Pubkey, metas: &[CpiAcc], infos: &[CpiAcc], data: &[u8]) -> (u64, u64) {
    let pid = h.put(program.as_ref());
    let mut ma = vec![];
    for m in metas {
        let k = h.put(m.key.as_ref());
        ma.extend_from_slice(&k.to_le_bytes());
        ma.extend_from_slice(&[m.writable as u8, m.signer as u8, 0, 0, 0, 0, 0, 0]);
    }
    let metas_addr = if ma.is_empty() { HEAP } else { h.put(&ma) };
    let data_addr = if data.is_empty() { HEAP } else { h.put(data) };
    let mut ix = vec![];
    for v in [pid, metas_addr, metas.len() as u64, data_addr, data.len() as u64] {
        ix.extend_from_slice(&v.to_le_bytes());
    }
    let ix_addr = h.put(&ix);
    let mut ia = vec![];
    for a in infos {
        for v in [a.m + 8, a.m + 72, a.len, a.m + 88, a.m + 40, 0] {
            ia.extend_from_slice(&v.to_le_bytes());
        }
        ia.extend_from_slice(&[a.signer as u8, a.writable as u8, 0, 0, 0, 0, 0, 0]);
    }
    let infos_addr = h.put(&ia);
    (ix_addr, infos_addr)
}

/// StableInstruction + AccountMeta[] + AccountInfo[] com os Rc<RefCell<..>> (ABI Rust) no heap.
fn cpi_rust(h: &mut Heap, program: &Pubkey, metas: &[CpiAcc], infos: &[CpiAcc], data: &[u8]) -> (u64, u64) {
    let mut ma = vec![];
    for m in metas {
        ma.extend_from_slice(m.key.as_ref());
        ma.extend_from_slice(&[m.signer as u8, m.writable as u8]);
    }
    let metas_addr = if ma.is_empty() { HEAP } else { h.put(&ma) };
    let data_addr = if data.is_empty() { HEAP } else { h.put(data) };
    let mut ix = vec![];
    for v in [metas_addr, metas.len() as u64, metas.len() as u64, data_addr, data.len() as u64, data.len() as u64] {
        ix.extend_from_slice(&v.to_le_bytes());
    }
    ix.extend_from_slice(program.as_ref());
    let ix_addr = h.put(&ix);
    let mut ia = vec![];
    for a in infos {
        let mut lam = vec![];
        for v in [1u64, 1, 0, a.m + 72] {
            lam.extend_from_slice(&v.to_le_bytes());
        }
        let lam_rc = h.put(&lam);
        let mut dat = vec![];
        for v in [1u64, 1, 0, a.m + 88, a.len] {
            dat.extend_from_slice(&v.to_le_bytes());
        }
        let data_rc = h.put(&dat);
        for v in [a.m + 8, lam_rc, data_rc, a.m + 40, 0] {
            ia.extend_from_slice(&v.to_le_bytes());
        }
        ia.extend_from_slice(&[a.signer as u8, a.writable as u8, 0, 0, 0, 0, 0, 0]);
    }
    let infos_addr = h.put(&ia);
    (ix_addr, infos_addr)
}

fn sys_transfer(lamports: u64) -> Vec<u8> {
    [vec![2, 0, 0, 0], lamports.to_le_bytes().to_vec()].concat()
}

struct CpiSpec {
    rust: bool,
    callee: Vec<(Pubkey, bool, bool)>, // chave, signer, writable
    infos: Vec<Pubkey>,
    data: Vec<u8>,
    signers: Vec<Vec<Vec<u8>>>,
    watch: Option<(Pubkey, u64)>, // u64 a logar depois da CPI: conta + offset no registro
    infos_in_input: bool,
    bad_key_ptr: bool,
    bad_bool: bool,
}

impl CpiSpec {
    fn new(callee: Vec<(Pubkey, bool, bool)>, infos: Vec<Pubkey>, data: Vec<u8>, signers: Vec<Vec<Vec<u8>>>) -> Self {
        CpiSpec { rust: false, callee, infos, data, signers, watch: None, infos_in_input: false, bad_key_ptr: false, bad_bool: false }
    }
}

fn cpi_case(name: &'static str, program_id: &Pubkey, accounts: Vec<(Pubkey, Account)>, metas: Vec<AccountMeta>, sp: CpiSpec) -> Case<'static> {
    let ms = markers(&accounts, &metas);
    let acc = |k: &Pubkey| -> CpiAcc {
        let i = metas.iter().position(|m| m.pubkey == *k);
        let len = accounts.iter().find(|(kk, _)| kk == k).map(|(_, a)| a.data.len() as u64).unwrap_or(0);
        CpiAcc { key: *k, m: i.map(|i| ms[i]).unwrap_or(0), len, signer: i.map(|i| metas[i].is_signer).unwrap_or(false), writable: i.map(|i| metas[i].is_writable).unwrap_or(false) }
    };
    let callee: Vec<CpiAcc> = sp.callee.iter().map(|(k, sg, wr)| CpiAcc { signer: *sg, writable: *wr, ..acc(k) }).collect();
    let infos: Vec<CpiAcc> = sp.infos.iter().map(|k| acc(k)).collect();
    let mut h = Heap::default();
    let system = Pubkey::default();
    let (ix_addr, infos_addr) = if sp.rust { cpi_rust(&mut h, &system, &callee, &infos, &sp.data) } else { cpi_c(&mut h, &system, &callee, &infos, &sp.data) };
    if sp.bad_key_ptr {
        let o = (infos_addr - HEAP) as usize;
        let bad = infos[0].m + 16;
        h.bytes[o..o + 8].copy_from_slice(&bad.to_le_bytes());
    }
    if sp.bad_bool {
        let o = (ix_addr - HEAP) as usize + 8;
        let metas_addr = u64::from_le_bytes(h.bytes[o..o + 8].try_into().unwrap());
        h.bytes[(metas_addr - HEAP) as usize + 9] = 2;
    }
    let signers = if sp.signers.is_empty() { 0 } else { h.signers(&sp.signers) };
    let watch = sp.watch.map(|(k, off)| acc(&k).m + off).unwrap_or(0);
    let op = if sp.rust { 3 } else { 2 };
    let args = [ix_addr, infos_addr, infos.len() as u64, signers, sp.signers.len() as u64];
    let mut data = pda_ix(op, args, watch, &h);
    if sp.infos_in_input {
        // o mesmo array, mas na cópia que está nos dados da instrução (região de input)
        let (_, ix_off) = serialize(program_id, &accounts, &metas, &data);
        let a2 = ix_off + 64 + (infos_addr - HEAP);
        data = pda_ix(op, [ix_addr, a2, args[2], args[3], args[4]], watch, &h);
    }
    Case { name, program: "pda_program", accounts, metas, data }
}

// ------------------------------------------------------------------ SPL Token (sBPF v0)
//
// O programa SPL Token oficial (`token.so` do pacote mollusk-svm-programs-token, carregado pelo
// BPF Loader 2 com o id Tokenkeg...) é sBPF v0: ELF com relocações, chamadas internas resolvidas
// por hash e rodata em 0x1_0000_0000. Além dos casos de execução, `fixtures/solana/token.json`
// traz o resultado do carregador do agave (`Executable::load`): a região só leitura já relocada,
// o registro de funções (hash → pc) e o registro de syscalls, para conferir o carregador on-chain.

const TOKEN_ID: Pubkey = Pubkey::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const NATIVE_MINT: Pubkey = Pubkey::from_str_const("So11111111111111111111111111111111111111112");

fn copt(d: &mut Vec<u8>, k: Option<Pubkey>) {
    match k {
        Some(k) => {
            d.extend_from_slice(&[1, 0, 0, 0]);
            d.extend_from_slice(k.as_ref());
        }
        None => d.extend_from_slice(&[0; 36]),
    }
}

/// `spl_token::state::Mint` empacotado (82 bytes).
fn mint_data(authority: Option<Pubkey>, supply: u64, decimals: u8, freeze: Option<Pubkey>) -> Vec<u8> {
    let mut d = vec![];
    copt(&mut d, authority);
    d.extend_from_slice(&supply.to_le_bytes());
    d.push(decimals);
    d.push(1);
    copt(&mut d, freeze);
    d
}

/// `spl_token::state::Account` empacotado (165 bytes). state: 1 inicializada, 2 congelada.
fn token_data(mint: Pubkey, owner: Pubkey, amount: u64, delegate: Option<(Pubkey, u64)>, state: u8, native: Option<u64>) -> Vec<u8> {
    let mut d = vec![];
    d.extend_from_slice(mint.as_ref());
    d.extend_from_slice(owner.as_ref());
    d.extend_from_slice(&amount.to_le_bytes());
    copt(&mut d, delegate.map(|x| x.0));
    d.push(state);
    match native {
        Some(n) => {
            d.extend_from_slice(&[1, 0, 0, 0]);
            d.extend_from_slice(&n.to_le_bytes());
        }
        None => d.extend_from_slice(&[0; 12]),
    }
    d.extend_from_slice(&delegate.map(|x| x.1).unwrap_or(0).to_le_bytes());
    copt(&mut d, None);
    d
}

fn token_fixtures(dir: &Path, out_dir: &Path) {
    let rent = Rent::default();
    let mint_rent = rent.minimum_balance(82);
    let acc_rent = rent.minimum_balance(165);
    let tok = |data: Vec<u8>, lamports: u64| Account { lamports, data, owner: TOKEN_ID, executable: false, rent_epoch: 0 };
    let wallet = |lamports: u64| account(Pubkey::default(), lamports, vec![]);

    let mint = key(0x20);
    let auth = key(0x21);
    let freeze = key(0x22);
    let alice = key(0x23);
    let bob = key(0x24);
    let a = key(0x25);
    let b = key(0x26);
    let other_mint = key(0x27);
    let delegate = key(0x28);
    let c = key(0x29);
    let fresh = key(0x2a);

    let mint_ok = tok(mint_data(Some(auth), 1_000_000, 6, Some(freeze)), mint_rent);
    let mint_uninit = tok(vec![0; 82], mint_rent);
    let acc_a = |amount: u64| tok(token_data(mint, alice, amount, None, 1, None), acc_rent);
    let acc_b = tok(token_data(mint, bob, 0, None, 1, None), acc_rent);
    let acc_uninit = tok(vec![0; 165], acc_rent);
    let w = |k: Pubkey| AccountMeta::new(k, false);
    let r = |k: Pubkey| AccountMeta::new_readonly(k, false);
    let s = |k: Pubkey| AccountMeta::new_readonly(k, true);
    let amt = |op: u8, v: u64| [vec![op], v.to_le_bytes().to_vec()].concat();
    let init_mint2 = |decimals: u8, fr: Option<Pubkey>| {
        let mut d = vec![20, decimals];
        d.extend_from_slice(auth.as_ref());
        match fr {
            Some(f) => {
                d.push(1);
                d.extend_from_slice(f.as_ref());
            }
            None => d.push(0),
        }
        d
    };
    let mollusk = Mollusk::default();
    let rent_sysvar = mollusk.sysvars.keyed_account_for_rent_sysvar();

    let t = |name: &'static str, accounts: Vec<(Pubkey, Account)>, metas: Vec<AccountMeta>, data: Vec<u8>| Case { name, program: "spl_token", accounts, metas, data };
    let transfer = |accts: Vec<(Pubkey, Account)>, signer: Pubkey, _lamports: u64| {
        let mut v = accts;
        v.push((signer, wallet(0)));
        v
    };
    let mut cases = vec![
        t("token_initialize_mint2", vec![(mint, mint_uninit.clone())], vec![w(mint)], init_mint2(6, None)),
        t("token_initialize_mint2_freeze", vec![(mint, mint_uninit.clone())], vec![w(mint)], init_mint2(9, Some(freeze))),
        t("token_initialize_mint2_twice", vec![(mint, mint_ok.clone())], vec![w(mint)], init_mint2(6, None)),
        t("token_initialize_mint2_not_rent_exempt", vec![(mint, tok(vec![0; 82], mint_rent - 1))], vec![w(mint)], init_mint2(6, None)),
        t("token_initialize_mint_rent_account", vec![(mint, mint_uninit.clone()), rent_sysvar.clone()], vec![w(mint), r(rent_sysvar.0)], {
            let mut d = init_mint2(6, None);
            d[0] = 0;
            d
        }),
        t("token_initialize_account3", vec![(fresh, acc_uninit.clone()), (mint, mint_ok.clone())], vec![w(fresh), r(mint)], [vec![18], alice.to_bytes().to_vec()].concat()),
        t("token_initialize_account3_bad_mint", vec![(fresh, acc_uninit.clone()), (mint, mint_uninit.clone())], vec![w(fresh), r(mint)], [vec![18], alice.to_bytes().to_vec()].concat()),
        t("token_initialize_account", vec![(fresh, acc_uninit.clone()), (mint, mint_ok.clone()), (alice, wallet(1_000_000)), rent_sysvar.clone()], vec![w(fresh), r(mint), r(alice), r(rent_sysvar.0)], vec![1]),
        t("token_initialize_immutable_owner", vec![(fresh, acc_uninit.clone())], vec![w(fresh)], vec![22]),
        t("token_mint_to", transfer(vec![(mint, mint_ok.clone()), (a, acc_a(500_000))], auth, 0), vec![w(mint), w(a), s(auth)], amt(7, 250_000)),
        t("token_mint_to_wrong_authority", transfer(vec![(mint, mint_ok.clone()), (a, acc_a(500_000))], bob, 0), vec![w(mint), w(a), s(bob)], amt(7, 250_000)),
        t("token_mint_to_not_signer", transfer(vec![(mint, mint_ok.clone()), (a, acc_a(500_000))], auth, 0), vec![w(mint), w(a), r(auth)], amt(7, 250_000)),
        t("token_mint_to_overflow", transfer(vec![(mint, mint_ok.clone()), (a, acc_a(500_000))], auth, 0), vec![w(mint), w(a), s(auth)], amt(7, u64::MAX)),
        t("token_transfer", transfer(vec![(a, acc_a(500_000)), (b, acc_b.clone())], alice, 0), vec![w(a), w(b), s(alice)], amt(3, 100_000)),
        t("token_transfer_all", transfer(vec![(a, acc_a(500_000)), (b, acc_b.clone())], alice, 0), vec![w(a), w(b), s(alice)], amt(3, 500_000)),
        t("token_transfer_insufficient", transfer(vec![(a, acc_a(500_000)), (b, acc_b.clone())], alice, 0), vec![w(a), w(b), s(alice)], amt(3, 500_001)),
        t("token_transfer_wrong_owner", transfer(vec![(a, acc_a(500_000)), (b, acc_b.clone())], bob, 0), vec![w(a), w(b), s(bob)], amt(3, 1)),
        t("token_transfer_not_signer", transfer(vec![(a, acc_a(500_000)), (b, acc_b.clone())], alice, 0), vec![w(a), w(b), r(alice)], amt(3, 1)),
        t("token_transfer_mint_mismatch", transfer(vec![(a, acc_a(500_000)), (c, tok(token_data(other_mint, bob, 0, None, 1, None), acc_rent))], alice, 0), vec![w(a), w(c), s(alice)], amt(3, 1)),
        t("token_transfer_to_self", transfer(vec![(a, acc_a(500_000))], alice, 0), vec![w(a), w(a), s(alice)], amt(3, 7)),
        t("token_transfer_readonly_destination", transfer(vec![(a, acc_a(500_000)), (b, acc_b.clone())], alice, 0), vec![w(a), r(b), s(alice)], amt(3, 1)),
        t("token_transfer_missing_accounts", vec![(a, acc_a(500_000)), (b, acc_b.clone())], vec![w(a), w(b)], amt(3, 1)),
        t("token_transfer_frozen", transfer(vec![(a, tok(token_data(mint, alice, 500_000, None, 2, None), acc_rent)), (b, acc_b.clone())], alice, 0), vec![w(a), w(b), s(alice)], amt(3, 1)),
        t("token_transfer_checked", transfer(vec![(a, acc_a(500_000)), (mint, mint_ok.clone()), (b, acc_b.clone())], alice, 0), vec![w(a), r(mint), w(b), s(alice)], [amt(12, 42_000), vec![6]].concat()),
        t("token_transfer_checked_bad_decimals", transfer(vec![(a, acc_a(500_000)), (mint, mint_ok.clone()), (b, acc_b.clone())], alice, 0), vec![w(a), r(mint), w(b), s(alice)], [amt(12, 42_000), vec![7]].concat()),
        t("token_approve", transfer(vec![(a, acc_a(500_000)), (delegate, wallet(0))], alice, 0), vec![w(a), r(delegate), s(alice)], amt(4, 1_000)),
        t("token_revoke", transfer(vec![(a, tok(token_data(mint, alice, 500_000, Some((delegate, 1_000)), 1, None), acc_rent))], alice, 0), vec![w(a), s(alice)], vec![5]),
        t("token_transfer_by_delegate", transfer(vec![(a, tok(token_data(mint, alice, 500_000, Some((delegate, 1_000)), 1, None), acc_rent)), (b, acc_b.clone())], delegate, 0), vec![w(a), w(b), s(delegate)], amt(3, 600)),
        t("token_transfer_delegate_exceeds", transfer(vec![(a, tok(token_data(mint, alice, 500_000, Some((delegate, 1_000)), 1, None), acc_rent)), (b, acc_b.clone())], delegate, 0), vec![w(a), w(b), s(delegate)], amt(3, 1_500)),
        t("token_burn", transfer(vec![(a, acc_a(500_000)), (mint, mint_ok.clone())], alice, 0), vec![w(a), w(mint), s(alice)], amt(8, 123)),
        t("token_close_account", vec![(b, acc_b.clone()), (alice, wallet(1_000_000)), (bob, wallet(0))], vec![w(b), w(alice), s(bob)], vec![9]),
        t("token_close_account_with_balance", transfer(vec![(a, acc_a(500_000)), (bob, wallet(1_000_000))], alice, 0), vec![w(a), w(bob), s(alice)], vec![9]),
        t("token_freeze_account", transfer(vec![(a, acc_a(500_000)), (mint, mint_ok.clone())], freeze, 0), vec![w(a), r(mint), s(freeze)], vec![10]),
        t("token_set_authority", transfer(vec![(mint, mint_ok.clone())], auth, 0), vec![w(mint), s(auth)], [vec![6, 0, 1], bob.to_bytes().to_vec()].concat()),
        t("token_get_account_data_size", vec![(mint, mint_ok.clone())], vec![r(mint)], vec![21]),
        t("token_amount_to_ui_amount", vec![(mint, mint_ok.clone())], vec![r(mint)], amt(23, 1_234_567)),
        t("token_ui_amount_to_amount", vec![(mint, mint_ok.clone())], vec![r(mint)], [vec![24], b"12.5".to_vec()].concat()),
        t("token_sync_native", vec![(fresh, tok(token_data(NATIVE_MINT, alice, 0, None, 1, Some(acc_rent)), acc_rent + 5_000))], vec![w(fresh)], vec![17]),
        t("token_invalid_instruction", vec![(a, acc_a(1))], vec![w(a)], vec![99]),
        t("token_empty_data", vec![], vec![], vec![]),
    ];
    let _ = &mut cases;

    let mut out = vec![];
    for c in &cases {
        let v = run_case_with(dir, c, TOKEN_ID, mollusk_svm::program::loader_keys::LOADER_V2, true);
        println!("{:<40} {:<46} cu={:<6} logs={}", c.name, v["expect"]["error"].to_string(), v["expect"]["cu"], v["expect"]["logs"].as_array().map(|l| l.len()).unwrap_or(0));
        out.push(v);
    }

    // o carregador do agave (mesmo ambiente do Mollusk: features todas ativas, sem labels de depuração)
    let elf = fs::read(dir.join("spl_token.so")).unwrap();
    let env = solana_syscalls::create_program_runtime_environment(&mollusk.feature_set, &mollusk.compute_budget.to_budget(), false, false).unwrap();
    let exe = solana_sbpf::elf::Executable::<solana_program_runtime::invoke_context::InvokeContext>::load(&elf, (*env).clone()).unwrap();
    exe.verify::<solana_sbpf::verifier::RequisiteVerifier>().unwrap();
    let (text_vaddr, text) = exe.get_text_bytes();
    let mut functions: Vec<(u32, usize)> = exe.get_function_registry().iter().map(|(k, (_, pc))| (k, pc)).collect();
    functions.sort();
    let mut syscalls: Vec<(u32, String)> = env.get_function_registry().iter().map(|(k, (name, _))| (k, String::from_utf8_lossy(name).to_string())).collect();
    syscalls.sort();
    let loaded = json!({
        "sbpfVersion": format!("{:?}", exe.get_sbpf_version()),
        "roVaddr": exe.get_ro_region().vm_addr_range().start,
        "ro": hex(exe.get_ro_section()),
        "textVaddr": text_vaddr,
        "textLen": text.len(),
        "entryPc": exe.get_entrypoint_instruction_offset(),
        "functions": functions.iter().map(|(k, pc)| json!([k, pc])).collect::<Vec<_>>(),
        "syscalls": syscalls.iter().map(|(k, n)| json!([k, n])).collect::<Vec<_>>(),
    });
    println!("spl_token.so: {:?}, ro {} bytes em 0x{:x}, texto em 0x{:x} ({} instruções), entrada {}, {} funções",
        exe.get_sbpf_version(), exe.get_ro_section().len(), exe.get_ro_region().vm_addr_range().start, text_vaddr, text.len() / 8,
        exe.get_entrypoint_instruction_offset(), functions.len());

    let body = json!({ "programs": { "spl_token": hex(&elf) }, "loaded": { "spl_token": loaded }, "fixtures": out });
    fs::write(out_dir.join("token.json"), serde_json::to_string_pretty(&body).unwrap() + "\n").unwrap();
    println!("fixtures/solana/token.json: {} casos", out.len());
}

fn main() {
    let dir = std::env::args().nth(1).expect("uso: sbpf-runtime-reference <dir com os .so>");
    let dir = Path::new(&dir);
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let out_dir = root.join("fixtures").join("solana");
    fs::create_dir_all(&out_dir).unwrap();

    let program_id = key(0xee);
    let target = key(0x01);
    let other = key(0x02);
    let incin = incinerator::id();
    let w = |k: Pubkey| AccountMeta::new(k, false);
    let r = |k: Pubkey| AccountMeta::new_readonly(k, false);
    let mut cases: Vec<Case> = vec![
        Case { name: "noop", program: "noop", accounts: vec![], metas: vec![], data: vec![] },
        Case { name: "sbpfv3_return_ok", program: "sbpfv3_return_ok", accounts: vec![], metas: vec![], data: vec![] },
        Case { name: "sbpfv3_return_err", program: "sbpfv3_return_err", accounts: vec![], metas: vec![], data: vec![] },
        Case { name: "hello", program: "hello_solana_program", accounts: vec![], metas: vec![], data: vec![] },
        Case { name: "hello_with_data_and_account", program: "hello_solana_program", accounts: vec![(target, account(program_id, 5, vec![1, 2, 3]))], metas: vec![w(target)], data: vec![9, 9, 9] },
        Case { name: "clock", program: "clock_sysvar_program", accounts: vec![], metas: vec![], data: vec![] },
        Case { name: "write_log_size", program: "write_to_account_program", accounts: vec![(target, account(program_id, 1_000_000_000, vec![0; 16]))], metas: vec![w(target)], data: vec![0] },
        Case { name: "write_data0", program: "write_to_account_program", accounts: vec![(target, account(program_id, 1_000_000_000, vec![7; 16]))], metas: vec![w(target)], data: vec![1] },
        Case { name: "write_data0_empty_account", program: "write_to_account_program", accounts: vec![(target, account(program_id, 1_000_000_000, vec![]))], metas: vec![w(target)], data: vec![1] },
        Case { name: "write_data0_not_owned", program: "write_to_account_program", accounts: vec![(target, account(other, 1_000_000_000, vec![7; 16]))], metas: vec![w(target)], data: vec![1] },
        Case { name: "write_data0_readonly", program: "write_to_account_program", accounts: vec![(target, account(program_id, 1_000_000_000, vec![7; 16]))], metas: vec![r(target)], data: vec![1] },
        Case { name: "write_burn", program: "write_to_account_program", accounts: vec![(target, account(program_id, 1_000_000_000, vec![0; 8])), (incin, account(Pubkey::default(), 10, vec![]))], metas: vec![w(target), w(incin)], data: vec![2] },
        Case { name: "write_burn_wrong_incinerator", program: "write_to_account_program", accounts: vec![(target, account(program_id, 1_000_000_000, vec![0; 8])), (other, account(Pubkey::default(), 10, vec![]))], metas: vec![w(target), w(other)], data: vec![2] },
        Case { name: "write_burn_missing_account", program: "write_to_account_program", accounts: vec![(target, account(program_id, 1_000_000_000, vec![0; 8]))], metas: vec![w(target)], data: vec![2] },
        Case { name: "write_burn_readonly_incinerator", program: "write_to_account_program", accounts: vec![(target, account(program_id, 1_000_000_000, vec![0; 8])), (incin, account(Pubkey::default(), 10, vec![]))], metas: vec![w(target), r(incin)], data: vec![2] },
        Case { name: "write_realloc_grow", program: "write_to_account_program", accounts: vec![(target, account(program_id, 1_000_000_000, vec![7; 16]))], metas: vec![w(target)], data: [vec![3], 116u64.to_le_bytes().to_vec()].concat() },
        Case { name: "write_realloc_grow_max", program: "write_to_account_program", accounts: vec![(target, account(program_id, 1_000_000_000, vec![7; 16]))], metas: vec![w(target)], data: [vec![3], (16u64 + 10240).to_le_bytes().to_vec()].concat() },
        Case { name: "write_realloc_grow_too_much", program: "write_to_account_program", accounts: vec![(target, account(program_id, 1_000_000_000, vec![7; 16]))], metas: vec![w(target)], data: [vec![3], (16u64 + 10241).to_le_bytes().to_vec()].concat() },
        Case { name: "write_realloc_shrink", program: "write_to_account_program", accounts: vec![(target, account(program_id, 1_000_000_000, vec![7; 16]))], metas: vec![w(target)], data: [vec![3], 4u64.to_le_bytes().to_vec()].concat() },
        Case { name: "write_realloc_zero", program: "write_to_account_program", accounts: vec![(target, account(program_id, 1_000_000_000, vec![7; 16]))], metas: vec![w(target)], data: [vec![3], 0u64.to_le_bytes().to_vec()].concat() },
        Case { name: "write_realloc_not_owned", program: "write_to_account_program", accounts: vec![(target, account(other, 1_000_000_000, vec![7; 16]))], metas: vec![w(target)], data: [vec![3], 32u64.to_le_bytes().to_vec()].concat() },
        Case { name: "write_invalid_arg", program: "write_to_account_program", accounts: vec![(target, account(program_id, 1_000_000_000, vec![0; 16]))], metas: vec![w(target)], data: vec![9] },
        Case { name: "write_no_accounts", program: "write_to_account_program", accounts: vec![], metas: vec![], data: vec![1] },
        Case { name: "write_empty_data_panics", program: "write_to_account_program", accounts: vec![(target, account(program_id, 1_000_000_000, vec![0; 16]))], metas: vec![w(target)], data: vec![] },
        Case { name: "write_dup_account", program: "write_to_account_program", accounts: vec![(target, account(program_id, 1_000_000_000, vec![0; 16]))], metas: vec![w(target), w(target)], data: vec![0] },
        Case { name: "write_two_accounts_second_dup", program: "write_to_account_program", accounts: vec![(target, account(program_id, 1_000_000_000, vec![0; 16])), (other, account(other, 3, vec![1; 5]))], metas: vec![w(target), r(other), w(target)], data: vec![1] },
    ];
    let system = mollusk_svm::program::keyed_account_for_system_program();
    cases.push(Case { name: "simple_transfer_cpi", program: "simple_transfer_program", accounts: vec![(target, account(Pubkey::default(), 1_000_000, vec![])), (other, account(Pubkey::default(), 0, vec![])), system.clone()], metas: vec![AccountMeta::new(target, true), w(other), r(system.0)], data: 1_000_000u64.to_be_bytes().to_vec() });


    // --- erros da CPI com o programa real (ABI Rust, `invoke`)
    let st = |name: &'static str, t: Account, metas: Vec<AccountMeta>, amount: u64, third: (Pubkey, Account)| Case {
        name,
        program: "simple_transfer_program",
        accounts: vec![(target, t), (other, account(Pubkey::default(), 0, vec![])), third],
        metas,
        data: amount.to_be_bytes().to_vec(),
    };
    let sys_meta = r(system.0);
    cases.push(st("simple_transfer_insufficient", account(Pubkey::default(), 999_999, vec![]), vec![AccountMeta::new(target, true), w(other), sys_meta.clone()], 1_000_000, system.clone()));
    cases.push(st("simple_transfer_not_signer", account(Pubkey::default(), 1_000_000, vec![]), vec![w(target), w(other), sys_meta.clone()], 1_000_000, system.clone()));
    cases.push(st("simple_transfer_readonly_recipient", account(Pubkey::default(), 1_000_000, vec![]), vec![AccountMeta::new(target, true), r(other), sys_meta.clone()], 1_000_000, system.clone()));
    cases.push(st("simple_transfer_wrong_program", account(Pubkey::default(), 1_000_000, vec![]), vec![AccountMeta::new(target, true), w(other), r(key(0x03))], 1_000_000, (key(0x03), account(Pubkey::default(), 0, vec![]))));
    cases.push(st("simple_transfer_payer_with_data", account(Pubkey::default(), 1_000_000, vec![1, 2, 3]), vec![AccountMeta::new(target, true), w(other), sys_meta.clone()], 1_000_000, system.clone()));
    cases.push(st("simple_transfer_zero", account(Pubkey::default(), 1_000_000, vec![]), vec![AccountMeta::new(target, true), w(other), sys_meta.clone()], 0, system.clone()));

    // --- PDAs (programa de teste em assembly)
    fs::write(dir.join("pda_program.so"), pda_program()).unwrap();
    let (vault, vbump) = Pubkey::find_program_address(&[b"vault"], &program_id);
    let vseeds = vec![b"vault".to_vec(), vec![vbump]];
    let pda_case = |name: &'static str, op: u64, seeds: Vec<Vec<u8>>, bump_overlap: bool| {
        let mut h = Heap::default();
        let sa = h.seeds(&seeds);
        let pa = h.put(program_id.as_ref());
        let out = h.put(&[0u8; 32]);
        let bump = if op == 1 {
            if bump_overlap { out + 5 } else { h.put(&[0u8; 8]) }
        } else {
            0
        };
        Case { name, program: "pda_program", accounts: vec![], metas: vec![], data: pda_ix(op, [sa, seeds.len() as u64, pa, out, bump], 0, &h) }
    };
    let on_curve = (0u8..=255).find(|i| Pubkey::create_program_address(&[&[*i]], &program_id).is_err()).unwrap();
    let slow = (0u8..=255).find(|i| Pubkey::find_program_address(&[b"slow", &[*i]], &program_id).1 <= 250).unwrap();
    cases.push(pda_case("pda_create", 0, vseeds.clone(), false));
    cases.push(pda_case("pda_create_on_curve", 0, vec![vec![on_curve]], false));
    cases.push(pda_case("pda_create_no_seeds", 0, vec![], false));
    cases.push(pda_case("pda_create_seed_too_long", 0, vec![vec![7; 33]], false));
    cases.push(pda_case("pda_create_too_many_seeds", 0, vec![vec![1]; 17], false));
    cases.push(pda_case("pda_find", 1, vec![b"vault".to_vec()], false));
    cases.push(pda_case("pda_find_many_bumps", 1, vec![b"slow".to_vec(), vec![slow]], false));
    cases.push(pda_case("pda_find_overlapping_bump", 1, vec![b"vault".to_vec()], true));

    // --- CPI ao system program assinando com o PDA (ABI C e Rust)
    let sysk = Pubkey::default();
    let pda_tx = |vault_lamports: u64, vault_data: Vec<u8>| {
        (vec![(vault, account(sysk, vault_lamports, vault_data)), (other, account(sysk, 0, vec![])), system.clone()], vec![w(vault), w(other), sys_meta.clone()])
    };
    let tr = |signers: Vec<Vec<Vec<u8>>>| CpiSpec { watch: Some((vault, 72)), ..CpiSpec::new(vec![(vault, true, true), (other, false, true)], vec![vault, other], sys_transfer(1000), signers) };
    let (a, m) = pda_tx(5000, vec![]);
    cases.push(cpi_case("cpi_c_transfer_pda", &program_id, a.clone(), m.clone(), tr(vec![vseeds.clone()])));
    cases.push(cpi_case("cpi_rust_transfer_pda", &program_id, a.clone(), m.clone(), CpiSpec { rust: true, ..tr(vec![vseeds.clone()]) }));
    cases.push(cpi_case("cpi_c_transfer_pda_no_seeds", &program_id, a.clone(), m.clone(), tr(vec![])));
    cases.push(cpi_case("cpi_c_transfer_pda_wrong_seeds", &program_id, a.clone(), m.clone(), tr(vec![vec![b"vault".to_vec(), vec![vbump.wrapping_add(1)]]])));
    cases.push(cpi_case("cpi_c_infos_in_input", &program_id, a.clone(), m.clone(), CpiSpec { infos_in_input: true, ..tr(vec![vseeds.clone()]) }));
    cases.push(cpi_case("cpi_c_bad_key_pointer", &program_id, a.clone(), m.clone(), CpiSpec { bad_key_ptr: true, ..tr(vec![vseeds.clone()]) }));
    cases.push(cpi_case("cpi_c_bad_meta_bool", &program_id, a.clone(), m.clone(), CpiSpec { bad_bool: true, ..tr(vec![vseeds.clone()]) }));
    cases.push(cpi_case("cpi_c_too_many_signers", &program_id, a.clone(), m.clone(), tr(vec![vec![b"x".to_vec()]; 17])));
    cases.push(cpi_case("cpi_c_signer_too_many_seeds", &program_id, a.clone(), m.clone(), tr(vec![vec![vec![1]; 17]])));
    cases.push(cpi_case("cpi_c_signer_seed_too_long", &program_id, a.clone(), m.clone(), tr(vec![vec![vec![1; 33]]])));
    cases.push(cpi_case("cpi_c_unknown_account", &program_id, a.clone(), m.clone(), CpiSpec::new(vec![(vault, true, true), (key(0x33), false, true)], vec![vault], sys_transfer(1000), vec![vseeds.clone()])));
    cases.push(cpi_case("cpi_c_missing_info", &program_id, a.clone(), m.clone(), CpiSpec::new(vec![(vault, true, true), (other, false, true)], vec![vault], sys_transfer(1000), vec![vseeds.clone()])));
    cases.push(cpi_case("cpi_c_transfer_to_self", &program_id, a.clone(), m.clone(), CpiSpec { watch: Some((vault, 72)), ..CpiSpec::new(vec![(vault, true, true), (vault, true, true)], vec![vault], sys_transfer(1000), vec![vseeds.clone()]) }));
    let (a2, _) = pda_tx(5000, vec![]);
    cases.push(cpi_case("cpi_c_readonly_escalation", &program_id, a2, vec![w(vault), r(other), sys_meta.clone()], tr(vec![vseeds.clone()])));
    let (a, m) = pda_tx(500, vec![]);
    cases.push(cpi_case("cpi_c_insufficient", &program_id, a, m, tr(vec![vseeds.clone()])));
    let (a, m) = pda_tx(5000, vec![1, 2, 3]);
    cases.push(cpi_case("cpi_c_from_with_data", &program_id, a, m, tr(vec![vseeds.clone()])));

    // CreateAccount / Allocate / Assign no PDA (dados e dono mudam dentro da CPI)
    let create = |space: u64| [vec![0, 0, 0, 0], 500_000u64.to_le_bytes().to_vec(), space.to_le_bytes().to_vec(), program_id.to_bytes().to_vec()].concat();
    let ca_tx = |vault_lamports: u64| {
        (
            vec![(target, account(sysk, 1_000_000, vec![])), (vault, account(sysk, vault_lamports, vec![])), system.clone()],
            vec![AccountMeta::new(target, true), w(vault), sys_meta.clone()],
        )
    };
    let ca = |data: Vec<u8>| CpiSpec { watch: Some((vault, 80)), ..CpiSpec::new(vec![(target, true, true), (vault, true, true)], vec![target, vault], data, vec![vseeds.clone()]) };
    let (a, m) = ca_tx(0);
    cases.push(cpi_case("cpi_c_create_account_pda", &program_id, a.clone(), m.clone(), ca(create(16))));
    cases.push(cpi_case("cpi_rust_create_account_pda", &program_id, a.clone(), m.clone(), CpiSpec { rust: true, ..ca(create(16)) }));
    cases.push(cpi_case("cpi_c_create_account_too_big", &program_id, a.clone(), m.clone(), ca(create(10 * 1024 * 1024 + 1))));
    let (a, m) = ca_tx(1);
    cases.push(cpi_case("cpi_c_create_account_in_use", &program_id, a, m, ca(create(16))));
    let one = |data: Vec<u8>, off: u64| CpiSpec { watch: Some((vault, off)), ..CpiSpec::new(vec![(vault, true, true)], vec![vault], data, vec![vseeds.clone()]) };
    let solo = vec![(vault, account(sysk, 1000, vec![])), system.clone()];
    let solo_m = vec![w(vault), sys_meta.clone()];
    cases.push(cpi_case("cpi_c_allocate_pda", &program_id, solo.clone(), solo_m.clone(), one([vec![8, 0, 0, 0], 64u64.to_le_bytes().to_vec()].concat(), 80)));
    cases.push(cpi_case("cpi_c_assign_pda", &program_id, solo.clone(), solo_m.clone(), one([vec![1, 0, 0, 0], program_id.to_bytes().to_vec()].concat(), 40)));
    cases.push(cpi_case("cpi_c_assign_without_seeds", &program_id, solo.clone(), solo_m.clone(), CpiSpec { signers: vec![], ..one([vec![1, 0, 0, 0], program_id.to_bytes().to_vec()].concat(), 40) }));
    cases.push(cpi_case("cpi_c_bad_system_instruction", &program_id, solo.clone(), solo_m.clone(), one(vec![2, 0], 72)));

    let mut out = vec![];
    for c in &cases {
        let v = run_case(dir, c);
        println!("{:<34} {:<40} cu={:<7} logs={}", c.name, v["expect"]["error"].to_string(), v["expect"]["cu"], v["expect"]["logs"].as_array().map(|l| l.len()).unwrap_or(0));
        out.push(v);
    }
    // ELF de cada programa uma vez só (os casos apontam por `program`)
    let mut programs = serde_json::Map::new();
    for c in &cases {
        if !programs.contains_key(c.program) {
            let elf = fs::read(dir.join(format!("{}.so", c.program))).unwrap();
            programs.insert(c.program.to_string(), json!(hex(&elf)));
        }
    }
    let body = json!({ "programs": programs, "fixtures": out });
    fs::write(out_dir.join("programs.json"), serde_json::to_string_pretty(&body).unwrap() + "\n").unwrap();
    println!("fixtures/solana/programs.json: {} casos", out.len());

    token_fixtures(dir, &out_dir);
}
