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
use std::{fs, path::Path};

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
    let program_id = key(0xee);
    let elf = fs::read(dir.join(format!("{}.so", c.program))).unwrap_or_else(|_| panic!("faltando {}.so", c.program));
    let mut mollusk = Mollusk::default();
    mollusk.add_program_with_loader_and_elf(&program_id, &bpf_loader_upgradeable::id(), &elf);
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
    json!({
        "name": c.name,
        "program": c.program,
        "programId": hex(program_id.as_ref()),
        "programIdBase58": program_id.to_string(),
        "loader": hex(bpf_loader_upgradeable::id().as_ref()),
        "maxCu": mollusk.compute_budget.compute_unit_limit,
        "accounts": c.accounts.iter().map(|(k, a)| account_json(k, a)).collect::<Vec<_>>(),
        "metas": c.metas.iter().map(|m| json!({ "key": hex(m.pubkey.as_ref()), "isSigner": m.is_signer, "isWritable": m.is_writable })).collect::<Vec<_>>(),
        "data": hex(&c.data),
        "regions": regions,
        "ixDataOffset": ix_off,
        "sysvars": { "clock": hex(&clock_bytes) },
        "expect": {
            "error": err,
            "cu": result.compute_units_consumed,
            "returnData": hex(&result.return_data),
            "logs": logs,
            "accounts": result.resulting_accounts.iter().map(|(k, a)| account_json(k, a)).collect::<Vec<_>>(),
        }
    })
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
}
