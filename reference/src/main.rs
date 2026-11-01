//! Harness de referência: executa programas sBPF v0 na VM oficial (crate `solana-sbpf`)
//! e grava os resultados em `fixtures/*.json`. Esses arquivos são a fonte da verdade
//! do teste diferencial do `SbpfVM.sol`.
//!
//! Uso: `cargo run --release` (de dentro de `reference/`).
//!
//! Configuração da VM (igual à do contrato):
//!   - sBPF v0, sem syscalls, sem funções registradas, verificador `RequisiteVerifier`;
//!   - pilha de 4 KiB em 0x2_0000_0000 (max_call_depth = 1, um único frame);
//!   - input somente leitura em 0x4_0000_0000;
//!   - nenhuma outra região (nem rodata/bytecode, nem heap);
//!   - medidor de instruções ligado: 1 CU por instrução executada.

#![allow(clippy::arithmetic_side_effects)]

use serde_json::{json, Value};
use solana_sbpf::{
    aligned_memory::AlignedMemory,
    assembler::assemble,
    ebpf,
    elf::Executable,
    error::{EbpfError, ProgramResult},
    memory_region::{MemoryMapping, MemoryRegion},
    program::{BuiltinProgram, FunctionRegistry, SBPFVersion},
    verifier::RequisiteVerifier,
    vm::{CallFrame, Config, ContextObject, EbpfVm, ExecutionMode},
};
use std::{cell::RefCell, fs, path::Path, ptr::NonNull, sync::Arc};

mod v3;

// ------------------------------------------------------------------ VM de referência

struct Ctx {
    remaining: u64,
    mapping: MemoryMapping,
}

impl ContextObject for Ctx {
    fn consume(&mut self, amount: u64) {
        self.remaining = self.remaining.saturating_sub(amount);
    }
    fn get_remaining(&self) -> u64 {
        self.remaining
    }
    fn active_mapping_ptr(&mut self) -> NonNull<MemoryMapping> {
        NonNull::from(&mut self.mapping)
    }
}

fn config() -> Config {
    Config {
        max_call_depth: 1,
        stack_frame_size: 4096,
        enable_stack_frame_gaps: true,
        enable_instruction_meter: true,
        enabled_sbpf_versions: SBPFVersion::V0..=SBPFVersion::V0,
        ..Config::default()
    }
}

fn loader() -> Arc<BuiltinProgram<Ctx>> {
    Arc::new(BuiltinProgram::new_loader(config()))
}

#[derive(Clone, Debug)]
struct Outcome {
    status: &'static str,
    r0: u64,
    cu: u64,
}

/// Status do contrato: Ok, Invalid, DivideByZero, AccessViolation, CuExceeded.
fn map_error(e: &EbpfError) -> &'static str {
    match e {
        EbpfError::DivideByZero => "DivideByZero",
        EbpfError::AccessViolation(..) | EbpfError::StackAccessViolation(..) => "AccessViolation",
        EbpfError::ExceededMaxInstructions => "CuExceeded",
        // Fora do subconjunto (call/callx), execução passando do fim do programa etc.
        _ => "Invalid",
    }
}

fn run(prog: &[u8], input: &[u8], max_cu: u64) -> Outcome {
    let invalid = Outcome { status: "Invalid", r0: 0, cu: 0 };
    let loader = loader();
    let exe = match Executable::<Ctx>::from_text_bytes(prog, loader.clone(), SBPFVersion::V0, FunctionRegistry::default()) {
        Ok(e) => e,
        Err(_) => return invalid,
    };
    if let Err(e) = exe.verify::<RequisiteVerifier>() {
        if std::env::var("DEBUG_INVALID").is_ok() {
            eprintln!("verifier: {e}");
        }
        return invalid;
    }
    let cfg = exe.get_config();
    let mut stack = AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(cfg.stack_size());
    let stack_len = stack.len();
    let input_copy: Vec<u8> = input.to_vec();
    let regions = vec![
        MemoryRegion::new(&mut stack, ebpf::MM_STACK_START),
        MemoryRegion::new(input_copy.as_slice() as *const [u8], ebpf::MM_INPUT_START),
    ];
    let mapping = unsafe { MemoryMapping::new(regions, cfg, SBPFVersion::V0) }.expect("mapping");
    let mut ctx = Ctx { remaining: max_cu, mapping };
    let mut vm = EbpfVm::new(loader.clone(), SBPFVersion::V0, &mut ctx, stack_len);
    vm.registers[1] = ebpf::MM_INPUT_START;
    let mut frames = vec![CallFrame::default(); cfg.max_call_depth];
    let (cu, res) = vm.execute_program(&exe, &mut ExecutionMode::Interpreted, &mut frames);
    match res {
        ProgramResult::Ok(r0) => Outcome { status: "Ok", r0, cu },
        ProgramResult::Err(e) => {
            if std::env::var("DEBUG_INVALID").is_ok() && map_error(&e) != "DivideByZero" {
                eprintln!("runtime: {e:?}");
            }
            Outcome { status: map_error(&e), r0: 0, cu }
        }
    }
}

/// Monta com o assembler do próprio solana-sbpf. Ele não aceita comentários, então
/// linhas/trechos após `;` são removidos antes (é o único açúcar que adicionamos).
fn asm(src: &str) -> Vec<u8> {
    try_asm(src).unwrap_or_else(|e| panic!("assembler: {e}\n{src}"))
}

thread_local! {
    /// Todo texto que passa pelo assembler oficial vira um caso de fixtures/asm.json (para validar
    /// o assembler em JS da página web).
    static ASM_LOG: RefCell<Vec<Value>> = const { RefCell::new(vec![]) };
}

fn try_asm(src: &str) -> Result<Vec<u8>, String> {
    let r = try_asm_raw(src);
    ASM_LOG.with(|l| {
        l.borrow_mut().push(match &r {
            Ok(b) => json!({ "src": src, "program": format!("0x{}", hex(b)) }),
            Err(e) => json!({ "src": src, "error": e }),
        })
    });
    r
}

fn try_asm_raw(src: &str) -> Result<Vec<u8>, String> {
    let clean: String = src
        .lines()
        .map(|l| l.split(';').next().unwrap_or("").trim_end())
        .filter(|l| !l.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    let exe = assemble::<Ctx>(&clean, loader())?;
    Ok(exe.get_text_bytes().1.to_vec())
}

fn fixture(name: &str, prog: &[u8], input: &[u8], max_cu: u64) -> Value {
    let o = run(prog, input, max_cu);
    json!({
        "name": name,
        "program": format!("0x{}", hex(prog)),
        "input": format!("0x{}", hex(input)),
        "maxCu": max_cu,
        "expect": { "status": o.status, "r0": format!("0x{:x}", o.r0), "cu": o.cu }
    })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn le64s(vals: &[u64]) -> Vec<u8> {
    vals.iter().flat_map(|v| v.to_le_bytes()).collect()
}

fn insn(opc: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0] = opc;
    b[1] = (src << 4) | (dst & 0x0f);
    b[2..4].copy_from_slice(&off.to_le_bytes());
    b[4..8].copy_from_slice(&imm.to_le_bytes());
    b
}

fn lddw(dst: u8, v: u64) -> Vec<u8> {
    let mut out = insn(0x18, dst, 0, 0, v as u32 as i32).to_vec();
    out.extend_from_slice(&insn(0, 0, 0, 0, (v >> 32) as u32 as i32));
    out
}

// ------------------------------------------------------------------ casos por opcode (M1/M2)

const EDGE64: &[u64] = &[
    0, 1, 2, 7, 31, 32, 63, 64, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff, 0x1_0000_0000,
    0x7fff_ffff_ffff_ffff, 0x8000_0000_0000_0000, u64::MAX, u64::MAX - 1, 0x0123_4567_89ab_cdef,
];
const EDGE_IMM: &[i64] = &[0, 1, -1, 2, 7, 31, 32, 63, i32::MAX as i64, i32::MIN as i64, -256, 0x1234];

fn opcode_cases() -> Vec<Value> {
    let mut out = vec![];
    let alu = ["add", "sub", "mul", "div", "or", "and", "lsh", "rsh", "mod", "xor", "mov", "arsh"];
    for op in alu {
        for w in ["64", "32"] {
            // registrador
            let pairs = [(0usize, 1usize), (12, 5), (14, 3), (11, 10), (16, 16), (13, 12), (9, 6), (15, 0), (4, 15)];
            for (i, (a, b)) in pairs.iter().enumerate() {
                let src = format!("lddw r0, {}\nlddw r2, {}\n{op}{w} r0, r2\nexit", EDGE64[*a], EDGE64[*b]);
                out.push(fixture(&format!("{op}{w}_reg_{i}"), &asm(&src), &[], 100));
            }
            // imediato
            for (i, imm) in EDGE_IMM.iter().enumerate() {
                let a = EDGE64[(i * 5 + 3) % EDGE64.len()];
                let src = format!("lddw r0, {a}\n{op}{w} r0, {imm}\nexit");
                // div/mod por imediato 0 e shifts grandes são rejeitados pelo verificador:
                // o assembler monta, a referência devolve Invalid.
                out.push(fixture(&format!("{op}{w}_imm_{i}"), &asm(&src), &[], 100));
            }
        }
    }
    for w in ["64", "32"] {
        for (i, a) in EDGE64.iter().enumerate() {
            out.push(fixture(&format!("neg{w}_{i}"), &asm(&format!("lddw r0, {a}\nneg{w} r0\nexit")), &[], 100));
        }
    }
    for e in ["le", "be"] {
        for bits in ["16", "32", "64"] {
            for (i, a) in [0x0123_4567_89ab_cdefu64, u64::MAX, 0x80, 0].iter().enumerate() {
                out.push(fixture(&format!("{e}{bits}_{i}"), &asm(&format!("lddw r0, {a}\n{e}{bits} r0\nexit")), &[], 100));
            }
        }
    }
    // lddw e mov
    for (i, a) in EDGE64.iter().enumerate() {
        out.push(fixture(&format!("lddw_{i}"), &asm(&format!("lddw r0, {a}\nexit")), &[], 100));
    }
    // saltos: r0 = 1 se o salto foi tomado
    let jmps = ["jeq", "jgt", "jge", "jset", "jne", "jsgt", "jsge", "jlt", "jle", "jslt", "jsle"];
    let jpairs = [(0usize, 0usize), (1, 0), (0, 1), (14, 13), (13, 14), (14, 14), (12, 9), (15, 6), (8, 7)];
    for j in jmps {
        for (i, (a, b)) in jpairs.iter().enumerate() {
            let src = format!(
                "lddw r1, {}\nlddw r2, {}\nmov64 r0, 0\n{j} r1, r2, +1\nja +1\nmov64 r0, 1\nexit",
                EDGE64[*a], EDGE64[*b]
            );
            out.push(fixture(&format!("{j}_reg_{i}"), &asm(&src), &[], 100));
        }
        for (i, imm) in EDGE_IMM.iter().enumerate() {
            let a = EDGE64[(i * 7 + 1) % EDGE64.len()];
            let src = format!("lddw r1, {a}\nmov64 r0, 0\n{j} r1, {imm}, +1\nja +1\nmov64 r0, 1\nexit");
            out.push(fixture(&format!("{j}_imm_{i}"), &asm(&src), &[], 100));
        }
    }
    out.push(fixture("ja_forward", &asm("mov64 r0, 1\nja +1\nmov64 r0, 2\nexit"), &[], 100));
    out.push(fixture("ja_loop_cu", &asm("mov64 r0, 0\nmov64 r1, 10\nadd64 r0, 3\nsub64 r1, 1\njne r1, 0, -3\nexit"), &[], 1000));
    out.push(fixture("exit_r0_default", &asm("exit"), &[], 100));
    // compute units
    out.push(fixture("cu_exact", &asm("mov64 r0, 1\nmov64 r0, 2\nexit"), &[], 3));
    out.push(fixture("cu_exceeded_by_one", &asm("mov64 r0, 1\nmov64 r0, 2\nexit"), &[], 2));
    out.push(fixture("cu_lddw_counts_once", &asm("lddw r0, 0x1122334455667788\nexit"), &[], 2));
    out.push(fixture("cu_zero_budget", &asm("exit"), &[], 0));
    out.push(fixture("cu_infinite_loop", &asm("mov64 r0, 0\nja -1\nexit"), &[], 5000));
    out
}

fn memory_cases() -> Vec<Value> {
    let mut out = vec![];
    let input: Vec<u8> = (0u8..32).map(|i| i.wrapping_mul(37).wrapping_add(11)).collect();
    for (sz, s) in [("b", 1i64), ("h", 2), ("w", 4), ("dw", 8)] {
        for off in [0i64, 1, 3, 8, 32 - s, 32 - s + 1, -1, 4096] {
            out.push(fixture(&format!("ldx{sz}_input_{off}"), &asm(&format!("ldx{sz} r0, [r1{off:+}]\nexit")), &input, 100));
        }
        for off in [-8i64, -1, -s, -4096, -4097, -4096 + 1, 0, 1] {
            let src = format!("lddw r2, 0xf1e2d3c4b5a69788\nstx{sz} [r10{off:+}], r2\nldx{sz} r0, [r10{off:+}]\nexit");
            out.push(fixture(&format!("stx{sz}_stack_{off}"), &asm(&src), &[], 100));
            let src = format!("st{sz} [r10{off:+}], -2\nldx{sz} r0, [r10{off:+}]\nexit");
            out.push(fixture(&format!("st{sz}_stack_{off}"), &asm(&src), &[], 100));
        }
        out.push(fixture(&format!("st{sz}_input_readonly"), &asm(&format!("st{sz} [r1+0], 1\nexit")), &input, 100));
        out.push(fixture(&format!("stx{sz}_input_readonly"), &asm(&format!("stx{sz} [r1+0], r1\nexit")), &input, 100));
    }
    out.push(fixture("stack_zero_init", &asm("ldxdw r0, [r10-8]\nexit"), &[], 100));
    out.push(fixture("stack_little_endian", &asm("lddw r2, 0x1122334455667788\nstxdw [r10-8], r2\nldxb r0, [r10-8]\nexit"), &[], 100));
    out.push(fixture("stack_unaligned", &asm("lddw r2, 0x1122334455667788\nstxdw [r10-11], r2\nldxw r0, [r10-9]\nexit"), &[], 100));
    out.push(fixture("rodata_unmapped", &asm("lddw r2, 0x100000000\nldxb r0, [r2+0]\nexit"), &[], 100));
    out.push(fixture("heap_unmapped", &asm("lddw r2, 0x300000000\nldxb r0, [r2+0]\nexit"), &[], 100));
    out.push(fixture("null_unmapped", &asm("mov64 r2, 0\nldxb r0, [r2+0]\nexit"), &[], 100));
    out.push(fixture("input_empty", &asm("ldxb r0, [r1+0]\nexit"), &[], 100));
    out.push(fixture("r1_points_to_input", &asm("mov64 r0, r1\nexit"), &[], 100));
    out.push(fixture("r10_frame_pointer", &asm("mov64 r0, r10\nexit"), &[], 100));
    out.push(fixture("addr_wraparound", &asm("lddw r2, 0xffffffffffffffff\nldxb r0, [r2+1]\nexit"), &[], 100));
    out
}

/// Programas rejeitados (verificador) ou fora do subconjunto. Montados à mão em bytes.
fn invalid_cases() -> Vec<Value> {
    let exit = insn(0x95, 0, 0, 0, 0);
    let mut out = vec![];
    let mut push = |name: &str, parts: Vec<Vec<u8>>| {
        let p: Vec<u8> = parts.concat();
        out.push(fixture(name, &p, &[1, 2, 3, 4, 5, 6, 7, 8], 100));
    };
    push("empty_program", vec![]);
    push("length_not_multiple", vec![exit.to_vec(), vec![0, 0, 0]]);
    push("unknown_opcode_0x00", vec![insn(0x00, 0, 0, 0, 0).to_vec(), exit.to_vec()]);
    push("unknown_opcode_0xff", vec![insn(0xff, 0, 0, 0, 0).to_vec(), exit.to_vec()]);
    push("unknown_opcode_0x06", vec![insn(0x06, 0, 0, 0, 0).to_vec(), exit.to_vec()]);
    push("unknown_opcode_ld_abs", vec![insn(0x20, 0, 0, 0, 0).to_vec(), exit.to_vec()]);
    push("le64_alu64_class", vec![insn(0xd7, 0, 0, 0, 64).to_vec(), exit.to_vec()]);
    push("div64_imm_zero", vec![insn(0x37, 0, 0, 0, 0).to_vec(), exit.to_vec()]);
    push("div32_imm_zero", vec![insn(0x34, 0, 0, 0, 0).to_vec(), exit.to_vec()]);
    push("mod64_imm_zero", vec![insn(0x97, 0, 0, 0, 0).to_vec(), exit.to_vec()]);
    push("mod32_imm_zero", vec![insn(0x94, 0, 0, 0, 0).to_vec(), exit.to_vec()]);
    push("lsh64_imm_64", vec![insn(0x67, 0, 0, 0, 64).to_vec(), exit.to_vec()]);
    push("lsh64_imm_63_ok", vec![insn(0x67, 0, 0, 0, 63).to_vec(), exit.to_vec()]);
    push("rsh64_imm_neg", vec![insn(0x77, 0, 0, 0, -1).to_vec(), exit.to_vec()]);
    push("arsh64_imm_64", vec![insn(0xc7, 0, 0, 0, 64).to_vec(), exit.to_vec()]);
    push("lsh32_imm_32", vec![insn(0x64, 0, 0, 0, 32).to_vec(), exit.to_vec()]);
    push("rsh32_imm_32", vec![insn(0x74, 0, 0, 0, 32).to_vec(), exit.to_vec()]);
    push("arsh32_imm_32", vec![insn(0xc4, 0, 0, 0, 32).to_vec(), exit.to_vec()]);
    push("lsh32_imm_31_ok", vec![insn(0x64, 0, 0, 0, 31).to_vec(), exit.to_vec()]);
    push("be_imm_8", vec![insn(0xdc, 0, 0, 0, 8).to_vec(), exit.to_vec()]);
    push("le_imm_0", vec![insn(0xd4, 0, 0, 0, 0).to_vec(), exit.to_vec()]);
    push("lddw_last", vec![exit.to_vec(), insn(0x18, 0, 0, 0, 1).to_vec()]);
    push("lddw_incomplete", vec![insn(0x18, 0, 0, 0, 1).to_vec(), exit.to_vec(), exit.to_vec()]);
    push("lddw_second_slot_garbage_ok", vec![insn(0x18, 0, 0, 0, 1).to_vec(), insn(0x00, 7, 9, 99, 2).to_vec(), exit.to_vec()]);
    push("jump_out_forward", vec![insn(0x05, 0, 0, 1, 0).to_vec(), exit.to_vec()]);
    push("jump_out_backward", vec![insn(0x05, 0, 0, -2, 0).to_vec(), exit.to_vec()]);
    push("jump_to_self_ok", vec![insn(0x05, 0, 0, -1, 0).to_vec(), exit.to_vec()]);
    push("jump_into_lddw", vec![insn(0x15, 0, 0, 1, 0).to_vec(), lddw(0, 5), exit.to_vec()]);
    push("jump_over_lddw_ok", vec![insn(0x15, 0, 0, 2, 0).to_vec(), lddw(0, 5), exit.to_vec()]);
    push("write_r10_mov", vec![insn(0xb7, 10, 0, 0, 0).to_vec(), exit.to_vec()]);
    push("write_r10_add", vec![insn(0x07, 10, 0, 0, 8).to_vec(), exit.to_vec()]);
    push("write_r10_ldx", vec![insn(0x79, 10, 10, -8, 0).to_vec(), exit.to_vec()]);
    push("write_r10_lddw", vec![lddw(10, 1), exit.to_vec()]);
    push("store_via_r10_ok", vec![insn(0x7a, 10, 0, -8, 1).to_vec(), exit.to_vec()]);
    push("jump_dst_r10", vec![insn(0x15, 10, 0, 0, 0).to_vec(), exit.to_vec()]);
    push("exit_dst_r10", vec![insn(0x95, 10, 0, 0, 0).to_vec()]);
    push("dst_r11", vec![insn(0xb7, 11, 0, 0, 0).to_vec(), exit.to_vec()]);
    push("src_r11", vec![insn(0xbf, 0, 11, 0, 0).to_vec(), exit.to_vec()]);
    push("src_r11_imm_form", vec![insn(0xb7, 0, 11, 0, 0).to_vec(), exit.to_vec()]);
    push("src_r10_read_ok", vec![insn(0xbf, 0, 10, 0, 0).to_vec(), exit.to_vec()]);
    push("dst_r15", vec![insn(0xb7, 15, 0, 0, 0).to_vec(), exit.to_vec()]);
    push("call_imm_unsupported", vec![insn(0x85, 0, 0, 0, 0x2075_59bd).to_vec(), exit.to_vec()]);
    push("callx_unsupported", vec![insn(0x8d, 0, 0, 0, 2).to_vec(), exit.to_vec()]);
    push("callx_bad_register", vec![insn(0x8d, 0, 0, 0, 10).to_vec(), exit.to_vec()]);
    push("no_exit_overrun", vec![insn(0xb7, 0, 0, 0, 1).to_vec()]);
    push("exit_not_reached_ok", vec![insn(0xb7, 0, 0, 0, 7).to_vec(), exit.to_vec(), insn(0xb7, 0, 0, 0, 1).to_vec()]);
    push("div64_reg_zero", vec![insn(0xb7, 2, 0, 0, 0).to_vec(), insn(0x3f, 0, 2, 0, 0).to_vec(), exit.to_vec()]);
    push("mod32_reg_zero_low_bits", vec![lddw(2, 0x1_0000_0000), insn(0x9c, 0, 2, 0, 0).to_vec(), exit.to_vec()]);
    push("div64_reg_high_bits_ok", vec![lddw(2, 0x1_0000_0000), insn(0x3f, 0, 2, 0, 0).to_vec(), exit.to_vec()]);
    push("neg64_reg_form", vec![insn(0x8f, 0, 0, 0, 0).to_vec(), exit.to_vec()]);
    push("ja_reg_form", vec![insn(0x0d, 0, 0, 0, 0).to_vec(), exit.to_vec()]);
    push("exit_reg_form", vec![insn(0x9d, 0, 0, 0, 0).to_vec()]);
    out
}

// ------------------------------------------------------------------ programas demo (M4)

fn demo_cases(programs_dir: &Path) -> Vec<Value> {
    let mut out = vec![];
    let inputs: &[(&str, &[&[u64]])] = &[
        ("fib", &[&[0], &[1], &[2], &[10], &[50], &[93], &[94], &[200], &[255]]),
        ("popcount", &[&[0], &[1], &[u64::MAX], &[0x8000_0000_0000_0001], &[0x0123_4567_89ab_cdef], &[0xf0f0]]),
        ("isqrt", &[&[0], &[1], &[2], &[3], &[4], &[15], &[16], &[1_000_000], &[u64::MAX], &[(1 << 62) - 1], &[0xffff_fffe_0000_0001]]),
        ("max8", &[&[1, 2, 3, 4, 5, 6, 7, 8], &[8, 7, 6, 5, 4, 3, 2, 1], &[0; 8], &[u64::MAX, 0, 0, 0, 0, 0, 0, 1], &[3, 9, 2, 9, 1, 0, 9, 4]]),
        ("gcd", &[&[0, 0], &[0, 7], &[7, 0], &[12, 18], &[17, 5], &[u64::MAX, u64::MAX - 1], &[1 << 40, 1 << 20], &[832040, 514229]]),
        ("hello", &[&[]]),
    ];
    for (name, ins) in inputs {
        let path = programs_dir.join(format!("{name}.s"));
        let src = fs::read_to_string(&path).unwrap_or_else(|_| panic!("faltando {}", path.display()));
        let prog = asm(&src);
        for (i, v) in ins.iter().enumerate() {
            out.push(fixture(&format!("{name}_{i}"), &prog, &le64s(v), 5000));
        }
    }
    out
}

// ------------------------------------------------------------------ fuzz (M3)

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // splitmix64
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
    /// probabilidade em por mil (para defeitos raros, cujo efeito se acumula por instrução)
    fn rare(&mut self, permille: u64) -> bool {
        self.below(1000) < permille
    }
    fn pick<T: Copy>(&mut self, a: &[T]) -> T {
        a[self.below(a.len() as u64) as usize]
    }
}

/// Uma "unidade" do programa: 1 slot, ou 2 no caso do lddw. Saltos são resolvidos depois.
enum Item {
    Raw(Vec<u8>),
    Jump { opc: u8, dst: u8, src: u8, imm: i32, target: isize },
}

fn rand_imm(r: &mut Rng) -> i32 {
    if r.chance(60) {
        r.pick(&[0, 1, -1, 2, 7, 8, 31, 32, 63, 64, i32::MAX, i32::MIN, -4096, 4096, 255, -256])
    } else {
        r.next() as i32
    }
}

fn rand_u64(r: &mut Rng) -> u64 {
    if r.chance(50) {
        r.pick(EDGE64)
    } else {
        r.next()
    }
}

fn rand_program(r: &mut Rng) -> (Vec<u8>, Vec<u8>, u64) {
    let mut items: Vec<Item> = vec![];
    // r1 (ponteiro do input) fica preservado na maior parte dos programas, senão quase todo
    // acesso ao input vira AccessViolation e o fuzz perde variedade.
    let reg = |r: &mut Rng| { let x = r.below(10) as u8; if x == 1 && !r.rare(50) { 0 } else { x } };
    let bad = 3; // por mil: chance de cada instrução sair "estragada" para exercitar o verificador

    for i in 2..10u8 {
        if r.chance(60) {
            items.push(Item::Raw(lddw(i, rand_u64(r))));
        }
    }
    let body = 5 + r.below(55);
    let alu_ops: [u8; 12] = [0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x90, 0xa0, 0xb0, 0xc0];
    let jmp_ops: [u8; 11] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0xa0, 0xb0, 0xc0, 0xd0];
    for _ in 0..body {
        let k = r.below(100);
        let mut dst = reg(r);
        let mut src = reg(r);
        if r.rare(bad) {
            dst = r.pick(&[10, 11, 15]);
        }
        if r.rare(bad) {
            src = r.pick(&[11, 12]);
        }
        if k < 45 {
            let cls = if r.chance(50) { 0x07 } else { 0x04 };
            let op = r.pick(&alu_ops);
            let is_reg = r.chance(45);
            let mut imm = rand_imm(r);
            let shift = matches!(op, 0x60 | 0x70 | 0xc0);
            if !is_reg && shift && !r.rare(bad) {
                imm = (r.below(if cls == 0x07 { 64 } else { 32 })) as i32;
            }
            if !is_reg && matches!(op, 0x30 | 0x90) && imm == 0 && !r.rare(bad * 2) {
                imm = 3;
            }
            let opc = op | cls | if is_reg { 0x08 } else { 0 };
            items.push(Item::Raw(insn(opc, dst, if is_reg { src } else if r.rare(bad) { src } else { 0 }, 0, imm).to_vec()));
        } else if k < 50 {
            let cls = if r.chance(50) { 0x07 } else { 0x04 };
            items.push(Item::Raw(insn(0x80 | cls, dst, 0, 0, 0).to_vec()));
        } else if k < 55 {
            let opc = r.pick(&[0xd4u8, 0xdc]);
            let imm = if r.rare(bad) { r.pick(&[0, 8, 128]) } else { r.pick(&[16, 32, 64]) };
            items.push(Item::Raw(insn(opc, dst, 0, 0, imm).to_vec()));
        } else if k < 60 {
            items.push(Item::Raw(lddw(dst, rand_u64(r))));
        } else if k < 80 {
            // memória: base r10 (pilha) ou r1 (input), às vezes fora das regiões
            let sz = r.pick(&[0x00u8, 0x08, 0x10, 0x18]);
            let width = match sz { 0x00 => 4, 0x08 => 2, 0x10 => 1, _ => 8 } as i64;
            let class = r.pick(&[0x61u8, 0x62, 0x63]); // ldx, st, stx
            // input é somente leitura: stores quase sempre miram a pilha
            let use_stack = if class == 0x61 { r.chance(60) } else { r.chance(97) };
            let off: i64 = if use_stack {
                if r.chance(96) { -(1 + r.below(4096 - width as u64 + 1) as i64) } else { r.pick(&[0, 1, -4097, -4100, -5000, 8]) }
            } else if r.chance(96) {
                r.below(24) as i64
            } else {
                r.pick(&[-1, 4096, 100, 40])
            };
            let off = if use_stack && off < 0 && off > -width { -width } else { off };
            let base = if use_stack { 10 } else { 1 };
            let raw = match class {
                0x61 => insn(0x61 | sz, if dst == 10 && !r.rare(bad) { 0 } else { dst }, base, off as i16, 0),
                0x62 => insn(0x62 | sz, base, 0, off as i16, rand_imm(r)),
                _ => insn(0x63 | sz, base, src, off as i16, 0),
            };
            items.push(Item::Raw(raw.to_vec()));
        } else if k < 99 || !r.rare(500) {
            let ja = r.chance(15);
            let is_reg = r.chance(45);
            let opc = if ja { 0x05 } else { r.pick(&jmp_ops) | 0x05 | if is_reg { 0x08 } else { 0 } };
            let here = items.len() as isize;
            // alvo: item à frente (o epílogo também conta); raramente para trás/fora
            let target = if r.rare(bad) { r.pick(&[-1isize, here, 10_000]) } else { here + 1 + r.below(8) as isize };
            items.push(Item::Jump { opc, dst: if ja { 0 } else { dst }, src: if is_reg { src } else { 0 }, imm: rand_imm(r), target });
        } else {
            // raridades: opcode inválido, call, callx, salto para o meio de um lddw
            let v = r.below(4);
            let raw = match v {
                0 => insn(r.pick(&[0x00u8, 0x06, 0x0e, 0x20, 0xd7, 0xe7, 0xff]), dst, 0, 0, 0),
                1 => insn(0x85, 0, 0, 0, rand_imm(r)),
                2 => insn(0x8d, 0, 0, 0, r.below(11) as i32),
                _ => insn(0xb7, dst, 0, 0, rand_imm(r)),
            };
            items.push(Item::Raw(raw.to_vec()));
        }
    }
    // epílogo: dobra todos os registradores em r0, depois exit
    for i in 1..10u8 {
        items.push(Item::Raw(insn(0xaf, 0, i, 0, 0).to_vec())); // xor64 r0, ri
        items.push(Item::Raw(insn(0x67, 0, 0, 0, 7).to_vec())); // lsh64 r0, 7
        items.push(Item::Raw(insn(0x0f, 0, i, 0, 0).to_vec())); // add64 r0, ri
    }
    if !r.rare(bad) {
        items.push(Item::Raw(insn(0x95, 0, 0, 0, 0).to_vec()));
    }

    // layout: slot inicial de cada item
    let mut slot = vec![0isize; items.len() + 1];
    for (i, it) in items.iter().enumerate() {
        let n = match it { Item::Raw(b) => (b.len() / 8) as isize, Item::Jump { .. } => 1 };
        slot[i + 1] = slot[i] + n;
    }
    let mut prog = vec![];
    for (i, it) in items.iter().enumerate() {
        match it {
            Item::Raw(b) => prog.extend_from_slice(b),
            Item::Jump { opc, dst, src, imm, target } => {
                let t = if *target < 0 {
                    -1
                } else if *target as usize >= items.len() {
                    slot[items.len()] + 3
                } else {
                    slot[*target as usize]
                };
                // às vezes mira o segundo slot de um lddw (deve ser rejeitado)
                let t = if r.rare(bad) { t + 1 } else { t };
                let off = t - (slot[i] + 1);
                prog.extend_from_slice(&insn(*opc, *dst, *src, off.clamp(i16::MIN as isize, i16::MAX as isize) as i16, *imm));
            }
        }
    }
    let input: Vec<u8> = (0..(if r.chance(70) { 32 + r.below(17) } else { r.below(32) })).map(|_| r.next() as u8).collect();
    let max_cu = if r.chance(10) { r.below(slot[items.len()] as u64 + 1) } else { 10_000 };
    (prog, input, max_cu)
}

fn random_cases(n: usize) -> Vec<Value> {
    let mut r = Rng(0x5bf0_b5c0_ffee);
    (0..n)
        .map(|i| {
            let (p, inp, cu) = rand_program(&mut r);
            fixture(&format!("random_{i}"), &p, &inp, cu)
        })
        .collect()
}

// ------------------------------------------------------------------ corpus do assembler

/// Sintaxe "difícil" (espaços, hex, sinais, rótulos, erros). O resultado oficial, sucesso ou erro,
/// é o esperado do assembler em JS.
const ASM_EXTRA: &[&str] = &[
    "mov r0, 1\nexit", "mov32 r0, -1\nexit", "add r0, 0x7fffffff\nexit", "add r0, 0x80000000\nexit",
    "add r0, -0x80000000\nexit", "add r0, - 5\nexit", "add r0, +5\nexit", "mov r0,1\nexit",
    "mov r0 , 1\nexit", "mov\tr0, 1\nexit", "  \n\n  mov r0, 1   \n\n exit  \n", "exit exit",
    "add64 r10, 8\nexit", "add r10, -8\nexit", "sub64 r10, 8\nexit", "mov r11, 1\nexit", "mov r16, 1\nexit",
    "mov r0, r10\nexit", "ldxdw r0, [r10-8]\nexit", "ldxdw r0, [r10 - 8]\nexit", "ldxdw r0, [r10 -8]\nexit",
    "ldxdw r0, [r10- 8]\nexit", "ldxdw r0, [r1]\nexit", "ldxdw r0, [r1 8]\nexit", "ldxdw r0, [ r1+8]\nexit",
    "ldxdw r0, [r1+8 ]\nexit", "ldxdw r0, [r1+0x10]\nexit", "ldxdw r0, [r1+32767]\nexit", "ldxdw r0, [r1+32768]\nexit",
    "ldxdw r0, [r1-32768]\nexit", "stxb [r10-1], r1\nexit", "sth [r10-2], 0x7fff\nexit", "stw [r10-4], -1\nexit",
    "lddw r0, 0xffffffffffffffff\nexit", "lddw r0, 0x1ffffffffffffffff\nexit", "lddw r0, -1\nexit",
    "lddw r0, 9223372036854775807\nexit", "lddw r0, 9223372036854775808\nexit", "lddw r0, -9223372036854775808\nexit",
    "lddw r0, 0x8000000000000000\nexit", "lddw r0, -0x8000000000000000\nexit", "lddw r0, 0x\nexit", "lddw r0, 0xg\nexit",
    "ja +0\nexit", "ja 0\nexit", "ja -1\nexit", "ja +32767\nexit", "ja +32768\nexit", "ja end\nend:\nexit",
    "ja end\nexit", "start:\nja start\nexit", "a:b:\nexit", "l1: l2: mov r0, 1\nja l1\nexit", "x_1:\nja x_1\nexit",
    "retry:\nja retry\nexit", "loop:\njne r0, 0, loop\nexit", "jeq r0, r1, +1\nexit\nexit", "jeq32 r0, 1, +1\nexit\nexit",
    "jsgt64 r0, -1, +0\nexit", "jset r1, 0x80, done\ndone: exit", "jeq r0, 1\nexit", "jeq r0, 1, 2, 3\nexit",
    "neg r0\nexit", "neg32 r0\nexit", "neg64 r0\nexit", "neg r0, 1\nexit", "be16 r0\nexit", "le64 r0\nexit", "be32 r1\nexit",
    "lmul r0, r1\nexit", "udiv32 r0, 3\nexit", "urem r0, 0\nexit", "sdiv64 r0, r1\nexit", "srem32 r0, -7\nexit",
    "uhmul r0, r1\nexit", "shmul64 r0, 2\nexit", "hor64 r0, 1\nexit", "hor r0, r1\nexit", "arsh32 r0, 3\nexit",
    "call 1\nexit", "call fn\nexit\nfn:\nexit", "callx r2\nexit", "syscall sol_log_\nexit", "syscall 5\nexit",
    "syscall abort\nexit", "function_foo:\nexit", "entrypoint:\nexit", "nop\nexit", "MOV r0, 1\nexit", "Mov64 r0, 1\nexit",
    "mov R0, 1\nexit", "mov r0, 1 ; comentário\nexit", "; só comentário\nexit", ".fill 2, 0x95\nexit", ".fill 1, 0\nexit",
    ".text\nexit", ".fill 1\nexit", "", "   ", "mov r0, 1", "mov r0, 99999999999999999999\nexit", "mov r0, 0x123456789\nexit",
    "mov r0, 2147483648\nexit", "mov r0, -2147483649\nexit", "mov r0, r1, r2\nexit", "mov r0\nexit", "mov 1, r0\nexit",
    "ldxb r0, r1\nexit", "stxdw [r10-8], 5\nexit", "stdw [r10-8], r1\nexit", "exit 1", "exit,", "mov r0, 1,\nexit",
    "mov r0, [r1+1]\nexit", "jeq r0, 0, +1\n  done:   exit", "lbl:mov r0, 1\nexit", "lbl :\nexit", "_x:\nja _x",
    "9a:\nja 9a", "mov r00, 1\nexit", "mov r01, 1\nexit", "add r0, 00012\nexit", "add r0, 0X10\nexit",
    "ldxh r0, [r1+-2]\nexit", "ldxh r0, [r1--2]\nexit", "ja +1 \nexit\nexit", "ja\nexit", "lddw r0\nexit",
    "lddw r0, r1\nexit", "lddw r0, label\nlabel: exit", "mov r0, label\nlabel: exit", "jeq r0, label, +1\nlabel: exit\nexit",
];

/// Corpus do assembler: tudo o que já foi montado acima, os extras e os programas aleatórios
/// desmontados pelo disassembler oficial (com rótulos `lbb_N`) e montados de volta.
fn asm_cases(n_random: usize) -> Vec<Value> {
    for src in ASM_EXTRA {
        let _ = try_asm(src);
    }
    let mut r = Rng(0x5bf0_b5c0_ffee);
    for _ in 0..n_random {
        let (p, _, _) = rand_program(&mut r);
        if p.is_empty() || p.len() % 8 != 0 {
            continue;
        }
        let Ok(exe) = Executable::<Ctx>::from_text_bytes(&p, loader(), SBPFVersion::V0, FunctionRegistry::default()) else {
            continue;
        };
        let Ok(analysis) = solana_sbpf::static_analysis::Analysis::from_executable(&exe) else { continue };
        let mut out = vec![];
        if analysis.disassemble(&mut out).is_ok() {
            let _ = try_asm(&String::from_utf8_lossy(&out));
        }
    }
    let mut seen = std::collections::HashSet::new();
    ASM_LOG.with(|l| l.borrow().iter().filter(|c| seen.insert(c["src"].as_str().unwrap().to_string())).cloned().collect())
}

fn write_asm(dir: &Path, cases: Vec<Value>) {
    let ok = cases.iter().filter(|c| c.get("program").is_some()).count();
    let body = json!({ "cases": cases });
    fs::write(dir.join("asm.json"), serde_json::to_string_pretty(&body).unwrap() + "\n").unwrap();
    println!("asm.json: {} casos ({ok} montam, {} erros)", cases.len(), cases.len() - ok);
}

// ------------------------------------------------------------------ main

fn write(dir: &Path, name: &str, cases: Vec<Value>) {
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for c in &cases {
        *counts.entry(c["expect"]["status"].as_str().unwrap().to_string()).or_default() += 1;
    }
    let body = json!({ "fixtures": cases });
    fs::write(dir.join(name), serde_json::to_string_pretty(&body).unwrap() + "\n").unwrap();
    println!("{name}: {} casos {:?}", cases.len(), counts);
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let fixtures = root.join("fixtures");
    fs::create_dir_all(&fixtures).unwrap();
    let n_random: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(1000);

    write(&fixtures, "opcodes.json", opcode_cases());
    write(&fixtures, "memory.json", memory_cases());
    write(&fixtures, "invalid.json", invalid_cases());
    write(&fixtures, "programs.json", demo_cases(&root.join("programs")));
    write(&fixtures, "random.json", random_cases(n_random));
    write_asm(&fixtures, asm_cases(n_random));

    // sBPF v3 (ISA da mainnet atual)
    let v3dir = fixtures.join("v3");
    fs::create_dir_all(&v3dir).unwrap();
    write(&v3dir, "isa.json", v3::cases());
    write(&v3dir, "random.json", v3::random_cases(n_random));
}
