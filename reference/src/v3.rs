//! Fixtures da ISA sBPF v3 (a versão que a mainnet executa hoje): chamadas internas com frames
//! fixos de 4 KiB, `callx`, saltos de 32 bits, syscalls estáticas (por hash do nome) e as
//! regiões de memória do runtime (pilha de 256 KiB, heap de 32 KiB, input gravável).
//!
//! Configuração igual à do agave (`solana-syscalls::create_program_runtime_environment_v1`):
//! max_call_depth 64, stack_frame_size 4096, sem gaps, medidor de instruções ligado.
//!
//! As syscalls aqui são "stubs" com a mesma mecânica das reais (custo em CU cobrado pelo
//! `consume_checked`, tradução de memória, erros): servem para testar o mecanismo. A semântica
//! das syscalls reais fica para os fixtures do Mollusk (reference-runtime/).

use super::{hex, insn, lddw, le64s};
use serde_json::{json, Value};
use solana_sbpf::{
    aligned_memory::AlignedMemory,
    assembler::assemble,
    declare_builtin_function, ebpf,
    elf::Executable,
    error::{EbpfError, ProgramResult},
    memory_region::{AccessType, MemoryMapping, MemoryRegion},
    program::{BuiltinFunctionDefinition, BuiltinProgram, FunctionRegistry, SBPFVersion},
    verifier::RequisiteVerifier,
    vm::{CallFrame, Config, ContextObject, EbpfVm, ExecutionMode},
};
use std::{fmt, ptr::NonNull, sync::Arc};

pub const STACK_SIZE: usize = 64 * 4096;
pub const HEAP_SIZE: usize = 32 * 1024;

// ------------------------------------------------------------------ contexto e syscalls

pub struct Ctx {
    remaining: u64,
    mapping: MemoryMapping,
    logs: Vec<String>,
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

/// Erros das syscalls (nomes = status no fixture).
#[derive(Debug)]
enum SysErr {
    ComputationalBudgetExceeded,
    Abort,
    Panic,
    InvalidString,
    CopyOverlapping,
}
impl fmt::Display for SysErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for SysErr {}

type Err = Box<dyn std::error::Error>;

/// Igual ao `ComputeMeter::consume_checked` do agave: desconta (saturando em 0) e erra se faltou.
fn consume_checked(ctx: &mut Ctx, amount: u64) -> Result<(), Err> {
    let exceeded = ctx.remaining < amount;
    ctx.remaining = ctx.remaining.saturating_sub(amount);
    if exceeded {
        return Err(Box::new(SysErr::ComputationalBudgetExceeded));
    }
    Ok(())
}

fn slice(ctx: &Ctx, addr: u64, len: u64) -> Result<&[u8], Err> {
    match ctx.mapping.map(AccessType::Load, addr, len) {
        solana_sbpf::error::StableResult::Ok(buf) => Ok(unsafe { &*buf.ptr() }),
        solana_sbpf::error::StableResult::Err(e) => Err(Box::new(e)),
    }
}

fn slice_mut(ctx: &Ctx, addr: u64, len: u64) -> Result<&mut [u8], Err> {
    match ctx.mapping.map(AccessType::Store, addr, len) {
        solana_sbpf::error::StableResult::Ok(buf) => Ok(unsafe { &mut *buf.ptr_mut() }),
        solana_sbpf::error::StableResult::Err(e) => Err(Box::new(e)),
    }
}

const SYSCALL_BASE_COST: u64 = 100;
const MEM_OP_BASE_COST: u64 = 10;
const CPI_BYTES_PER_UNIT: u64 = 250;

declare_builtin_function!(
    /// sol_get_stack_height: custo 100, devolve 1 (instrução de nível superior)
    SyscallStackHeight,
    fn rust(ctx: &mut Ctx, _a: u64, _b: u64, _c: u64, _d: u64, _e: u64,) -> Result<u64, Err> {
        consume_checked(ctx, SYSCALL_BASE_COST)?;
        Ok(1)
    }
);

declare_builtin_function!(
    /// sol_log_64_: custo 100, registra os 5 argumentos
    SyscallLog64,
    fn rust(ctx: &mut Ctx, a: u64, b: u64, c: u64, d: u64, e: u64,) -> Result<u64, Err> {
        consume_checked(ctx, SYSCALL_BASE_COST)?;
        ctx.logs.push(format!("{a:#x}, {b:#x}, {c:#x}, {d:#x}, {e:#x}"));
        Ok(0)
    }
);

declare_builtin_function!(
    /// sol_log_: custo max(100, len), string UTF-8 em [r1, r1+r2)
    SyscallLog,
    fn rust(ctx: &mut Ctx, addr: u64, len: u64, _c: u64, _d: u64, _e: u64,) -> Result<u64, Err> {
        consume_checked(ctx, SYSCALL_BASE_COST.max(len))?;
        let s: &[u8] = if len == 0 { &[] } else { slice(ctx, addr, len)? };
        match std::str::from_utf8(s) {
            Ok(m) => ctx.logs.push(m.to_string()),
            Err(_) => return Err(Box::new(SysErr::InvalidString)),
        }
        Ok(0)
    }
);

fn mem_op_consume(ctx: &mut Ctx, n: u64) -> Result<(), Err> {
    consume_checked(ctx, MEM_OP_BASE_COST.max(n / CPI_BYTES_PER_UNIT))
}

declare_builtin_function!(
    /// sol_memset_(dst, c, n)
    SyscallMemset,
    fn rust(ctx: &mut Ctx, dst: u64, c: u64, n: u64, _d: u64, _e: u64,) -> Result<u64, Err> {
        mem_op_consume(ctx, n)?;
        if n > 0 {
            slice_mut(ctx, dst, n)?.fill(c as u8);
        }
        Ok(0)
    }
);

declare_builtin_function!(
    /// sol_memcpy_(dst, src, n): erro se sobrepõe
    SyscallMemcpy,
    fn rust(ctx: &mut Ctx, dst: u64, src: u64, n: u64, _d: u64, _e: u64,) -> Result<u64, Err> {
        mem_op_consume(ctx, n)?;
        let nonoverlapping = if src > dst { src.saturating_sub(dst) >= n } else { dst.saturating_sub(src) >= n };
        if !nonoverlapping {
            return Err(Box::new(SysErr::CopyOverlapping));
        }
        if n > 0 {
            let d = slice_mut(ctx, dst, n)?;
            let s = slice(ctx, src, n)?.to_vec();
            d.copy_from_slice(&s);
        }
        Ok(0)
    }
);

declare_builtin_function!(
    /// sol_remaining_compute_units: custo 100, devolve o que sobrou
    SyscallRemaining,
    fn rust(ctx: &mut Ctx, _a: u64, _b: u64, _c: u64, _d: u64, _e: u64,) -> Result<u64, Err> {
        consume_checked(ctx, SYSCALL_BASE_COST)?;
        Ok(ctx.remaining)
    }
);

declare_builtin_function!(
    /// sol_panic_(msg, len, line, col): custo len, sempre erra
    SyscallPanic,
    fn rust(ctx: &mut Ctx, addr: u64, len: u64, _c: u64, _d: u64, _e: u64,) -> Result<u64, Err> {
        consume_checked(ctx, len)?;
        let s: &[u8] = if len == 0 { &[] } else { slice(ctx, addr, len)? };
        if std::str::from_utf8(s).is_err() {
            return Err(Box::new(SysErr::InvalidString));
        }
        Err(Box::new(SysErr::Panic))
    }
);

declare_builtin_function!(
    /// abort
    SyscallAbort,
    fn rust(_ctx: &mut Ctx, _a: u64, _b: u64, _c: u64, _d: u64, _e: u64,) -> Result<u64, Err> {
        Err(Box::new(SysErr::Abort))
    }
);

pub fn config() -> Config {
    Config {
        max_call_depth: 64,
        stack_frame_size: 4096,
        enable_stack_frame_gaps: false,
        enable_instruction_meter: true,
        enabled_sbpf_versions: SBPFVersion::V3..=SBPFVersion::V3,
        aligned_memory_mapping: false,
        ..Config::default()
    }
}

pub fn loader() -> Arc<BuiltinProgram<Ctx>> {
    let mut l = BuiltinProgram::new_loader(config());
    SyscallStackHeight::register(&mut l, "sol_get_stack_height").unwrap();
    SyscallLog64::register(&mut l, "sol_log_64_").unwrap();
    SyscallLog::register(&mut l, "sol_log_").unwrap();
    SyscallMemset::register(&mut l, "sol_memset_").unwrap();
    SyscallMemcpy::register(&mut l, "sol_memcpy_").unwrap();
    SyscallRemaining::register(&mut l, "sol_remaining_compute_units").unwrap();
    SyscallPanic::register(&mut l, "sol_panic_").unwrap();
    SyscallAbort::register(&mut l, "abort").unwrap();
    Arc::new(l)
}

// ------------------------------------------------------------------ execução

struct Outcome {
    status: String,
    r0: u64,
    cu: u64,
    input: Vec<u8>,
    logs: Vec<String>,
}

fn map_error(e: &EbpfError) -> String {
    match e {
        EbpfError::DivideByZero => "DivideByZero".into(),
        EbpfError::AccessViolation(..) | EbpfError::StackAccessViolation(..) => "AccessViolation".into(),
        EbpfError::ExceededMaxInstructions => "CuExceeded".into(),
        EbpfError::CallDepthExceeded => "CallDepthExceeded".into(),
        EbpfError::CallOutsideTextSegment => "CallOutsideTextSegment".into(),
        EbpfError::SyscallError(inner) => {
            if let Some(s) = inner.downcast_ref::<SysErr>() {
                match s {
                    SysErr::ComputationalBudgetExceeded => "CuExceeded".into(),
                    other => format!("{other:?}"),
                }
            } else if let Some(e) = inner.downcast_ref::<EbpfError>() {
                map_error(e)
            } else {
                "SyscallError".into()
            }
        }
        _ => "Invalid".into(),
    }
}

pub fn run(prog: &[u8], input: &[u8], max_cu: u64) -> (String, u64, u64, Vec<u8>, Vec<String>) {
    let o = run_inner(prog, input, max_cu);
    (o.status, o.r0, o.cu, o.input, o.logs)
}

fn run_inner(prog: &[u8], input: &[u8], max_cu: u64) -> Outcome {
    let invalid = |inp: &[u8]| Outcome { status: "Invalid".into(), r0: 0, cu: 0, input: inp.to_vec(), logs: vec![] };
    let loader = loader();
    let exe = match Executable::<Ctx>::from_text_bytes(prog, loader.clone(), SBPFVersion::V3, FunctionRegistry::default()) {
        Ok(e) => e,
        Err(_) => return invalid(input),
    };
    if let Err(e) = exe.verify::<RequisiteVerifier>() {
        if std::env::var("DEBUG_INVALID").is_ok() {
            eprintln!("verifier v3: {e}");
        }
        return invalid(input);
    }
    let cfg = exe.get_config();
    let mut stack = AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(STACK_SIZE);
    let mut heap = AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(HEAP_SIZE);
    let mut input_copy: Vec<u8> = input.to_vec();
    let regions = vec![
        MemoryRegion::new(&mut stack, ebpf::MM_STACK_START),
        MemoryRegion::new(&mut heap, ebpf::MM_HEAP_START),
        MemoryRegion::new(input_copy.as_mut_slice() as *mut [u8], ebpf::MM_INPUT_START),
    ];
    let mapping = unsafe { MemoryMapping::new(regions, cfg, SBPFVersion::V3) }.expect("mapping");
    let mut ctx = Ctx { remaining: max_cu, mapping, logs: vec![] };
    let mut vm = EbpfVm::new(loader.clone(), SBPFVersion::V3, &mut ctx, STACK_SIZE);
    vm.registers[1] = ebpf::MM_INPUT_START;
    let mut frames = vec![CallFrame::default(); cfg.max_call_depth];
    let (cu, res) = vm.execute_program(&exe, &mut ExecutionMode::Interpreted, &mut frames);
    let logs = std::mem::take(&mut ctx.logs);
    match res {
        ProgramResult::Ok(r0) => Outcome { status: "Ok".into(), r0, cu, input: input_copy, logs },
        ProgramResult::Err(e) => {
            if std::env::var("DEBUG_INVALID").is_ok() {
                eprintln!("runtime v3: {e:?}");
            }
            Outcome { status: map_error(&e), r0: 0, cu, input: input_copy, logs }
        }
    }
}

/// Monta com o assembler oficial na configuração v3 (comentários após `;` são removidos).
pub fn asm(src: &str) -> Vec<u8> {
    let clean: String = src
        .lines()
        .map(|l| l.split(';').next().unwrap_or("").trim_end())
        .filter(|l| !l.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    let exe = assemble::<Ctx>(&clean, loader()).unwrap_or_else(|e| panic!("assembler v3: {e}\n{src}"));
    exe.get_text_bytes().1.to_vec()
}

fn fixture(name: &str, prog: &[u8], input: &[u8], max_cu: u64) -> Value {
    let o = run_inner(prog, input, max_cu);
    let mut expect = json!({ "status": o.status, "r0": format!("0x{:x}", o.r0), "cu": o.cu });
    if o.input != input {
        expect["input"] = json!(format!("0x{}", hex(&o.input)));
    }
    if !o.logs.is_empty() {
        expect["logs"] = json!(o.logs);
    }
    json!({
        "name": name,
        "program": format!("0x{}", hex(prog)),
        "input": format!("0x{}", hex(input)),
        "maxCu": max_cu,
        "expect": expect
    })
}

// ------------------------------------------------------------------ casos

const EDGE64: &[u64] = &[
    0, 1, 2, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff, 0x1_0000_0000, 0x1_0000_0001, 0x7fff_ffff_ffff_ffff,
    0x8000_0000_0000_0000, u64::MAX, 0x0123_4567_89ab_cdef, 0xffff_ffff_0000_0005, 0x0000_0001_ffff_fffb,
];
const EDGE_IMM: &[i64] = &[0, 1, -1, 5, -5, i32::MAX as i64, i32::MIN as i64, 0x1234];

pub fn cases() -> Vec<Value> {
    let mut out = vec![];
    let mut push = |name: &str, src: &str, input: &[u8], max_cu: u64| out.push(fixture(name, &asm(src), input, max_cu));

    // ---------------- chamadas internas e frames
    push("call_basic", "mov64 r0, 1\ncall f\nadd64 r0, 1\nexit\nf:\nmov64 r0, 42\nexit", &[], 100);
    push(
        "call_saves_r6_r9",
        "mov64 r6, 0x1\nmov64 r7, 0x20\nmov64 r8, 0x300\nmov64 r9, 0x4000\ncall f\nmov64 r0, r6\nor64 r0, r7\nor64 r0, r8\nor64 r0, r9\nexit\nf:\nmov64 r6, 0\nmov64 r7, 0\nmov64 r8, 0\nmov64 r9, 0\nmov64 r0, 7\nexit",
        &[],
        100,
    );
    push("call_r1_r5_not_saved", "mov64 r1, 1\nmov64 r5, 5\ncall f\nadd64 r0, r1\nadd64 r0, r5\nexit\nf:\nmov64 r1, 10\nmov64 r5, 50\nmov64 r0, 100\nexit", &[], 100);
    push("call_r10_bump", "mov64 r6, r10\ncall f\nexit\nf:\nmov64 r0, r10\nsub64 r0, r6\nexit", &[], 100);
    push("call_r10_restored", "mov64 r6, r10\ncall f\nmov64 r0, r10\nsub64 r0, r6\nexit\nf:\nmov64 r0, 9\nexit", &[], 100);
    push("call_frame_isolated", "mov64 r2, 7\nstxdw [r10-8], r2\ncall f\nldxdw r0, [r10-8]\nexit\nf:\nmov64 r2, 9\nstxdw [r10-8], r2\nexit", &[], 100);
    push("call_callee_reads_caller_frame", "mov64 r2, 7\nstxdw [r10-8], r2\ncall f\nexit\nf:\nldxdw r0, [r10-4104]\nexit", &[], 100);
    push("call_nested_two", "call f\nadd64 r0, 1\nexit\nf:\ncall g\nadd64 r0, 10\nexit\ng:\nmov64 r0, 100\nexit", &[], 100);
    push("call_backward", "ja main\nf:\nmov64 r0, 5\nexit\nmain:\ncall f\nadd64 r0, 1\nexit", &[], 100);
    push("call_self_recursion_r10", "ldxb r1, [r1]\ncall f\nexit\nf:\njeq r1, 0, done\nsub64 r1, 1\ncall f\nadd64 r0, 1\nexit\ndone:\nmov64 r0, r10\nexit", &[3], 1000);
    // profundidade: n chamadas aninhadas a partir do input; 63 ok, 64 estoura
    let depth_src = "ldxb r1, [r1]\ncall f\nexit\nf:\njeq r1, 0, done\nsub64 r1, 1\ncall f\nexit\ndone:\nmov64 r0, r10\nexit";
    for n in [1u8, 2, 62, 63, 64, 65, 200] {
        push(&format!("call_depth_{n}"), depth_src, &[n], 10_000);
    }
    push("call_depth_cu_limit", depth_src, &[200], 300);
    push("call_cu_counts", "call f\nexit\nf:\nexit", &[], 3);
    push("call_cu_counts_short", "call f\nexit\nf:\nexit", &[], 2);
    push("exit_at_depth0_r0", "mov64 r0, 3\ncall f\nexit\nf:\nexit", &[], 100);
    push("call_imm_positive_relative", "call 1\nexit\nmov64 r0, 8\nexit", &[], 100);
    push("call_imm_zero", "call 0\nmov64 r0, 6\nexit", &[], 100); // chama a instrução seguinte: volta e continua
    push("stack_deep_frames_write", "ldxb r1, [r1]\ncall f\nexit\nf:\njeq r1, 0, done\nsub64 r1, 1\nstxdw [r10-8], r1\ncall f\nexit\ndone:\nldxdw r0, [r10-4104]\nexit", &[5], 1000);

    // ---------------- callx
    push("callx_basic", "mov64 r0, 0\nmov64 r8, 1\nlsh64 r8, 32\nor64 r8, 0x30\ncallx r8\nexit\nf:\nmov64 r0, 42\nexit", &[], 100);
    push("callx_unaligned_truncates", "mov64 r0, 0\nmov64 r8, 1\nlsh64 r8, 32\nor64 r8, 0x33\ncallx r8\nexit\nf:\nmov64 r0, 42\nexit", &[], 100);
    push("callx_last_insn", "mov64 r8, 1\nlsh64 r8, 32\nor64 r8, 0x28\ncallx r8\nexit\nmov64 r0, 1\nexit", &[], 100);
    push("callx_oob_past_end", "mov64 r8, 1\nlsh64 r8, 32\nor64 r8, 0x30\ncallx r8\nexit", &[], 100);
    push("callx_oob_below", "mov64 r8, 1\nlsh64 r8, 32\nsub64 r8, 1\ncallx r8\nexit", &[], 100);
    push("callx_oob_low", "mov64 r0, 8\ncallx r0\nexit", &[], 100);
    push("callx_oob_high", "lddw r0, 0x200000000\ncallx r0\nexit", &[], 100);
    push("callx_oob_max", "lddw r0, 0xFFFFFFFFFFFFFFF8\ncallx r0\nexit", &[], 100);
    push("callx_saves_regs", "mov64 r6, 11\nmov64 r8, 1\nlsh64 r8, 32\nor64 r8, 0x40\ncallx r8\nmov64 r0, r6\nadd64 r0, r9\nexit\nf:\nmov64 r6, 0\nmov64 r9, 5\nexit", &[], 100);
    push("callx_depth", "mov64 r8, 1\nlsh64 r8, 32\nor64 r8, 0x18\ncallx r8\nexit\nf:\ncallx r8\nexit", &[], 1000);
    push("callx_cu_short", "mov64 r8, 1\nlsh64 r8, 32\nor64 r8, 0x28\ncallx r8\nexit\nf:\nmov64 r0, 1\nexit", &[], 4);

    // ---------------- syscalls estáticas
    push("syscall_stack_height", "syscall sol_get_stack_height\nexit", &[], 200);
    push("syscall_cu_exact", "mov64 r1, 6\nsyscall sol_get_stack_height\nexit", &[], 103);
    push("syscall_cu_short_by_one", "mov64 r1, 6\nsyscall sol_get_stack_height\nexit", &[], 102);
    push("syscall_cu_short_insn", "mov64 r1, 6\nsyscall sol_get_stack_height\nexit", &[], 1);
    push("syscall_cu_result_dropped", "syscall sol_get_stack_height\nmov64 r1, r0\nmov64 r0, 0\nexit", &[], 103);
    push("syscall_meter_after", "syscall sol_get_stack_height\nmov64 r1, 1\nmov64 r1, 2\nmov64 r1, 3\nexit", &[], 105);
    push("syscall_meter_after_short", "syscall sol_get_stack_height\nmov64 r1, 1\nmov64 r1, 2\nmov64 r1, 3\nexit", &[], 104);
    push("syscall_r1_r5_preserved", "mov64 r1, 1\nmov64 r2, 2\nmov64 r3, 3\nmov64 r4, 4\nmov64 r5, 5\nsyscall sol_get_stack_height\nadd64 r0, r1\nadd64 r0, r2\nadd64 r0, r3\nadd64 r0, r4\nadd64 r0, r5\nexit", &[], 200);
    push("syscall_r6_r9_preserved", "mov64 r6, 6\nmov64 r9, 9\nsyscall sol_get_stack_height\nadd64 r0, r6\nadd64 r0, r9\nexit", &[], 200);
    push("syscall_log_64", "mov64 r1, 1\nmov64 r2, 2\nmov64 r3, 3\nmov64 r4, 4\nlddw r5, 0xffffffff\nsyscall sol_log_64_\nexit", &[], 200);
    push("syscall_log_64_cu", "syscall sol_log_64_\nexit", &[], 101);
    push("syscall_log_64_cu_short", "syscall sol_log_64_\nexit", &[], 100);
    push("syscall_log_string", "mov64 r2, 5\nsyscall sol_log_\nexit", b"Hello", 200);
    push("syscall_log_string_long", "mov64 r2, 150\nsyscall sol_log_\nexit", &[b'a'; 150], 400);
    push("syscall_log_string_long_cu", "mov64 r2, 150\nsyscall sol_log_\nexit", &[b'a'; 150], 152);
    push("syscall_log_string_long_cu_short", "mov64 r2, 150\nsyscall sol_log_\nexit", &[b'a'; 150], 151);
    push("syscall_log_invalid_utf8", "mov64 r2, 2\nsyscall sol_log_\nexit", &[0xff, 0xfe], 200);
    push("syscall_log_unmapped", "mov64 r2, 6\nsyscall sol_log_\nexit", b"Hello", 200);
    push("syscall_log_null", "mov64 r1, 0\nmov64 r2, 1\nsyscall sol_log_\nexit", b"Hello", 200);
    push("syscall_log_stack", "mov64 r2, 0x4142\nstxh [r10-2], r2\nmov64 r1, r10\nsub64 r1, 2\nmov64 r2, 2\nsyscall sol_log_\nexit", &[], 200);
    push("syscall_unknown_hash", "syscall 0x12345678\nexit", &[], 100);
    push("syscall_unknown_name", "syscall sol_nope_\nexit", &[], 100);
    push("syscall_abort", "mov64 r0, 5\nsyscall abort\nexit", &[], 100);
    push("syscall_panic", "mov64 r2, 5\nsyscall sol_panic_\nexit", b"oops!", 100);
    push("syscall_panic_cu_short", "mov64 r2, 5\nsyscall sol_panic_\nexit", b"oops!", 5);
    push("syscall_remaining", "syscall sol_remaining_compute_units\nexit", &[], 1000);
    push("syscall_remaining_twice", "syscall sol_remaining_compute_units\nmov64 r6, r0\nsyscall sol_remaining_compute_units\nsub64 r6, r0\nmov64 r0, r6\nexit", &[], 1000);
    push("syscall_memset_stack", "mov64 r1, r10\nsub64 r1, 16\nmov64 r2, 0xab\nmov64 r3, 16\nsyscall sol_memset_\nldxdw r0, [r10-8]\nexit", &[], 100);
    push("syscall_memset_input", "mov64 r2, 0x5a\nmov64 r3, 3\nsyscall sol_memset_\nldxw r0, [r1+0]\nexit", &[1, 2, 3, 4, 5], 100);
    push("syscall_memset_input_oob", "mov64 r2, 0x5a\nmov64 r3, 6\nsyscall sol_memset_\nexit", &[1, 2, 3, 4, 5], 100);
    push("syscall_memset_heap", "lddw r1, 0x300000000\nmov64 r2, 0x11\nmov64 r3, 32768\nsyscall sol_memset_\nlddw r1, 0x300007ff8\nldxdw r0, [r1+0]\nexit", &[], 1000);
    push("syscall_memset_heap_oob", "lddw r1, 0x300000000\nmov64 r2, 0x11\nmov64 r3, 32769\nsyscall sol_memset_\nexit", &[], 1000);
    push("syscall_memset_big_cu", "lddw r1, 0x200000000\nmov64 r2, 1\nmov64 r3, 262144\nsyscall sol_memset_\nexit", &[], 2000);
    push("syscall_memset_big_cu_short", "lddw r1, 0x200000000\nmov64 r2, 1\nmov64 r3, 262144\nsyscall sol_memset_\nexit", &[], 1052);
    push("syscall_memset_zero_len_unmapped", "mov64 r1, 0\nmov64 r2, 1\nmov64 r3, 0\nsyscall sol_memset_\nexit", &[], 100);
    push("syscall_memcpy_input_to_stack", "mov64 r2, r1\nmov64 r1, r10\nsub64 r1, 8\nmov64 r3, 8\nsyscall sol_memcpy_\nldxdw r0, [r10-8]\nexit", &le64s(&[0x1122334455667788]), 100);
    push("syscall_memcpy_overlap", "mov64 r2, r1\nadd64 r1, 1\nmov64 r3, 4\nsyscall sol_memcpy_\nexit", &[1, 2, 3, 4, 5, 6], 100);
    push("syscall_memcpy_adjacent_ok", "mov64 r2, r1\nadd64 r1, 3\nmov64 r3, 3\nsyscall sol_memcpy_\nldxw r0, [r2+2]\nexit", &[1, 2, 3, 4, 5, 6], 100);
    push("syscall_memcpy_src_unmapped", "mov64 r2, 0\nmov64 r1, r10\nsub64 r1, 8\nmov64 r3, 8\nsyscall sol_memcpy_\nexit", &[], 100);
    push("syscall_in_function", "call f\nadd64 r0, 1\nexit\nf:\nsyscall sol_get_stack_height\nexit", &[], 200);

    // ---------------- memória do runtime
    push("stack_other_frame_read_zero", "ldxdw r0, [r10+100]\nexit", &[], 100);
    push("stack_other_frame_write", "mov64 r2, 5\nstxdw [r10+4088], r2\ncall f\nexit\nf:\nldxdw r0, [r10-8]\nexit", &[], 100);
    push("stack_below_start", "ldxdw r0, [r10-4104]\nexit", &[], 100);
    push("stack_below_start_by_one", "ldxb r0, [r10-4097]\nexit", &[], 100);
    push("stack_first_byte", "ldxb r0, [r10-4096]\nexit", &[], 100);
    push("stack_last_byte", "lddw r2, 0x20003ffff\nldxb r0, [r2+0]\nexit", &[], 100);
    push("stack_past_end", "lddw r2, 0x200040000\nldxb r0, [r2+0]\nexit", &[], 100);
    push("stack_straddle_end", "lddw r2, 0x20003fffc\nldxdw r0, [r2+0]\nexit", &[], 100);
    push("heap_rw", "lddw r2, 0x300000000\nlddw r3, 0x1122334455667788\nstxdw [r2+0], r3\nldxdw r0, [r2+0]\nexit", &[], 100);
    push("heap_last_word", "lddw r2, 0x300007ff8\nmov64 r3, 7\nstxdw [r2+0], r3\nldxdw r0, [r2+0]\nexit", &[], 100);
    push("heap_past_end", "lddw r2, 0x300008000\nldxb r0, [r2+0]\nexit", &[], 100);
    push("heap_zero_init", "lddw r2, 0x300001000\nldxdw r0, [r2+0]\nexit", &[], 100);
    push("input_write", "mov64 r2, 0x99\nstxb [r1+0], r2\nldxb r0, [r1+0]\nexit", &[1, 2, 3], 100);
    push("input_write_dw", "lddw r2, 0x1122334455667788\nstxdw [r1+0], r2\nldxw r0, [r1+4]\nexit", &[0; 8], 100);
    push("input_write_oob", "mov64 r2, 0x99\nstxb [r1+3], r2\nexit", &[1, 2, 3], 100);
    push("input_st_imm", "stw [r1+0], -1\nldxdw r0, [r1+0]\nexit", &[0; 8], 100);
    push("bytecode_unreadable", "lddw r2, 0x100000000\nldxb r0, [r2+0]\nexit", &[], 100);
    push("rodata_unmapped", "mov64 r2, 0\nldxb r0, [r2+0]\nexit", &[], 100);

    // ---------------- jmp32
    let jmps = ["jeq32", "jgt32", "jge32", "jset32", "jne32", "jsgt32", "jsge32", "jlt32", "jle32", "jslt32", "jsle32"];
    let pairs: Vec<(usize, usize)> = (0..EDGE64.len()).flat_map(|a| [(a, (a + 3) % EDGE64.len()), (a, a)]).collect();
    for j in jmps {
        for (i, (a, b)) in pairs.iter().enumerate() {
            let src = format!("lddw r1, {}\nlddw r2, {}\nmov64 r0, 0\n{j} r1, r2, +1\nja +1\nmov64 r0, 1\nexit", EDGE64[*a], EDGE64[*b]);
            push(&format!("{j}_reg_{i}"), &src, &[], 100);
        }
        for (i, imm) in EDGE_IMM.iter().enumerate() {
            let a = EDGE64[(i * 5 + 1) % EDGE64.len()];
            push(&format!("{j}_imm_{i}"), &format!("lddw r1, {a}\nmov64 r0, 0\n{j} r1, {imm}, +1\nja +1\nmov64 r0, 1\nexit"), &[], 100);
        }
    }
    push("jmp32_loop", "mov64 r0, 0\nlddw r1, 0x100000005\nloop:\nadd64 r0, 2\nsub64 r1, 1\njne32 r1, 0, loop\nexit", &[], 100);
    push("jmp32_label_backward", "mov64 r0, 0\nmov64 r1, 3\nl:\nadd64 r0, 1\nsub32 r1, 1\njgt32 r1, 0, l\nexit", &[], 100);

    // ---------------- ainda válidos em v3 (ao contrário de v2)
    push("v3_lddw_ok", "lddw r0, 0x1122334455667788\nexit", &[], 100);
    push("v3_neg_ok", "mov64 r0, 5\nneg64 r0\nexit", &[], 100);
    push("v3_le_ok", "lddw r0, 0x1122334455667788\nle16 r0\nexit", &[], 100);
    push("v3_be_ok", "lddw r0, 0x1122334455667788\nbe32 r0\nexit", &[], 100);
    push("v3_mod_ok", "mov64 r0, 7\nmod64 r0, 3\nexit", &[], 100);

    // ---------------- montados à mão: rejeitados pelo verificador ou inválidos em execução
    let exit = insn(0x95, 0, 0, 0, 0).to_vec();
    let mut raw = |name: &str, parts: Vec<Vec<u8>>, input: &[u8]| out.push(fixture(name, &parts.concat(), input, 100));
    raw("add64_r10_imm_rejected", vec![insn(0x07, 10, 0, 0, 8).to_vec(), exit.clone()], &[]);
    raw("callx_r10_rejected", vec![insn(0x8d, 10, 0, 0, 0).to_vec(), exit.clone()], &[]);
    raw("callx_r11_rejected", vec![insn(0x8d, 11, 0, 0, 0).to_vec(), exit.clone()], &[]);
    raw("callx_imm_ignored", vec![insn(0xb7, 3, 0, 0, 0x28).to_vec(), lddw(2, 0x1_0000_0028), insn(0x8d, 2, 0, 0, 3).to_vec(), exit.clone(), insn(0xb7, 0, 0, 0, 9).to_vec(), exit.clone()], &[]);
    raw("callx_src_ignored", vec![lddw(2, 0x1_0000_0020), insn(0x8d, 2, 5, 0, 0).to_vec(), exit.clone(), insn(0xb7, 0, 0, 0, 9).to_vec(), exit.clone()], &[]);
    raw("call_src2_unsupported", vec![insn(0x85, 0, 2, 0, 0).to_vec(), exit.clone(), insn(0xb7, 0, 0, 0, 9).to_vec(), exit.clone()], &[]);
    raw("call_src1_out_of_code", vec![insn(0x85, 0, 1, 0, 5).to_vec(), exit.clone()], &[]);
    raw("call_src1_negative_out", vec![insn(0x85, 0, 1, 0, -2).to_vec(), exit.clone()], &[]);
    raw("call_src1_to_self", vec![insn(0x85, 0, 1, 0, -1).to_vec(), exit.clone()], &[]);
    raw("call_src1_to_lddw_middle", vec![insn(0x85, 0, 1, 0, 1).to_vec(), lddw(0, 7), exit.clone()], &[]);
    raw("call_src1_dst_reg_ignored", vec![insn(0x85, 3, 1, 0, 1).to_vec(), exit.clone(), insn(0xb7, 0, 0, 0, 9).to_vec(), exit.clone()], &[]);
    raw("call_src0_hash_as_internal_target", vec![insn(0x85, 0, 0, 0, 1).to_vec(), exit.clone(), insn(0xb7, 0, 0, 0, 9).to_vec(), exit.clone()], &[]);
    raw("call_offset_ignored", vec![insn(0x85, 0, 1, 7, 1).to_vec(), exit.clone(), insn(0xb7, 0, 0, 0, 9).to_vec(), exit.clone()], &[]);
    raw("jmp32_out_of_code", vec![insn(0x16, 0, 0, 1, 0).to_vec(), exit.clone()], &[]);
    raw("jmp32_into_lddw", vec![insn(0x16, 0, 0, 1, 0).to_vec(), lddw(0, 5), exit.clone()], &[]);
    raw("jmp32_ja_form_invalid", vec![insn(0x06, 0, 0, 0, 0).to_vec(), exit.clone()], &[]);
    raw("jmp32_0xe6_invalid", vec![insn(0xe6, 0, 0, 0, 0).to_vec(), exit.clone()], &[]);
    raw("jmp32_dst_r10_rejected", vec![insn(0x16, 10, 0, 0, 0).to_vec(), exit.clone()], &[]);
    raw("pqr_0x36_invalid", vec![insn(0x36, 0, 0, 0, 1).to_vec(), exit.clone()], &[]);
    raw("hor64_invalid", vec![insn(0xf7, 0, 0, 0, 1).to_vec(), exit.clone()], &[]);
    raw("exit_with_frames_pending_ok", vec![insn(0x85, 0, 1, 0, 1).to_vec(), exit.clone(), insn(0xb7, 0, 0, 0, 9).to_vec(), exit.clone()], &[]);
    raw("overrun_after_call", vec![insn(0x85, 0, 1, 0, 1).to_vec(), exit.clone(), insn(0xb7, 0, 0, 0, 9).to_vec()], &[]);
    out
}

// ------------------------------------------------------------------ fuzz v3

/// Programas aleatórios com chamadas, callx, jmp32 e syscalls, além do subconjunto v0.
pub fn random_cases(n: usize) -> Vec<Value> {
    let mut r = super::Rng(0x5bf0_b5c0_ffee_0003);
    (0..n)
        .map(|i| {
            let (p, inp, cu) = rand_program(&mut r);
            fixture(&format!("random_v3_{i}"), &p, &inp, cu)
        })
        .collect()
}

enum Item {
    Raw(Vec<u8>),
    Jump { opc: u8, dst: u8, src: u8, imm: i32, target: isize },
    Call { target: isize },
}

fn rand_program(r: &mut super::Rng) -> (Vec<u8>, Vec<u8>, u64) {
    use super::Rng;
    let reg = |r: &mut Rng| { let x = r.below(10) as u8; if x == 1 && !r.rare(50) { 0 } else { x } };
    let bad = 3;
    let n_funcs = 1 + r.below(3) as usize; // função 0 = main
    let mut funcs: Vec<Vec<Item>> = vec![];
    for f in 0..n_funcs {
        let mut items: Vec<Item> = vec![];
        if f == 0 {
            for i in 2..10u8 {
                if r.chance(60) {
                    items.push(Item::Raw(lddw(i, super::rand_u64(r))));
                }
            }
        }
        let body = 4 + r.below(if f == 0 { 40 } else { 16 });
        let alu_ops: [u8; 12] = [0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x90, 0xa0, 0xb0, 0xc0];
        let jmp_ops: [u8; 11] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0xa0, 0xb0, 0xc0, 0xd0];
        for _ in 0..body {
            let k = r.below(100);
            let mut dst = reg(r);
            let mut src = reg(r);
            if r.rare(bad) { dst = r.pick(&[10, 11, 15]); }
            if r.rare(bad) { src = r.pick(&[11, 12]); }
            if k < 40 {
                let cls = if r.chance(50) { 0x07 } else { 0x04 };
                let op = r.pick(&alu_ops);
                let is_reg = r.chance(45);
                let mut imm = super::rand_imm(r);
                let shift = matches!(op, 0x60 | 0x70 | 0xc0);
                if !is_reg && shift && !r.rare(bad) {
                    imm = (r.below(if cls == 0x07 { 64 } else { 32 })) as i32;
                }
                if !is_reg && matches!(op, 0x30 | 0x90) && imm == 0 && !r.rare(bad * 2) { imm = 3; }
                let opc = op | cls | if is_reg { 0x08 } else { 0 };
                items.push(Item::Raw(insn(opc, dst, if is_reg { src } else { 0 }, 0, imm).to_vec()));
            } else if k < 43 {
                items.push(Item::Raw(lddw(dst, super::rand_u64(r))));
            } else if k < 60 {
                // memória: pilha do frame atual, heap, input
                let sz = r.pick(&[0x00u8, 0x08, 0x10, 0x18]);
                let width = match sz { 0x00 => 4, 0x08 => 2, 0x10 => 1, _ => 8 } as i64;
                let class = r.pick(&[0x61u8, 0x62, 0x63]);
                let where_ = r.below(10);
                let (base, off): (u8, i64) = if where_ < 6 {
                    (10, if r.chance(94) { -(1 + r.below(4096 - width as u64 + 1) as i64) } else { r.pick(&[0, 100, 4000, -4097, -4104, 8000]) })
                } else if where_ < 8 {
                    (1, if r.chance(94) { r.below(24) as i64 } else { r.pick(&[-1, 40, 100, 4096]) })
                } else {
                    // heap: r9 recebe a base
                    items.push(Item::Raw(lddw(9, 0x3_0000_0000 + if r.chance(90) { r.below(32768 - 8) & !7 } else { r.pick(&[32760, 32768, 40000]) })));
                    (9, r.below(16) as i64)
                };
                let off = if base == 10 && off < 0 && off > -width { -width } else { off };
                let raw = match class {
                    0x61 => insn(0x61 | sz, if dst == 10 && !r.rare(bad) { 0 } else { dst }, base, off as i16, 0),
                    0x62 => insn(0x62 | sz, base, 0, off as i16, super::rand_imm(r)),
                    _ => insn(0x63 | sz, base, src, off as i16, 0),
                };
                items.push(Item::Raw(raw.to_vec()));
            } else if k < 72 {
                // syscall com argumentos aleatórios (quase sempre mul_add ou log_64, que não leem memória)
                let name = if r.chance(85) { r.pick(&["sol_get_stack_height", "sol_log_64_", "sol_remaining_compute_units"]) } else { r.pick(&["sol_memset_", "sol_memcpy_", "sol_log_", "abort", "sol_panic_", "nope"]) };
                items.push(Item::Raw(insn(0x85, 0, 0, 0, ebpf::hash_symbol_name(name.as_bytes()) as i32).to_vec()));
            } else if k < 80 && n_funcs > 1 {
                let target = r.below(n_funcs as u64) as isize;
                items.push(Item::Call { target });
            } else if k < 83 {
                // callx para o começo de uma função (endereço em r8) ou lixo
                let target = r.below(n_funcs as u64) as isize;
                items.push(Item::Call { target: -1 - target }); // negativo: via callx
            } else if k < 99 || !r.rare(500) {
                let ja = r.chance(15);
                let is_reg = r.chance(45);
                let j32 = r.chance(40);
                let opc = if ja { 0x05 } else { r.pick(&jmp_ops) | if j32 { 0x06 } else { 0x05 } | if is_reg { 0x08 } else { 0 } };
                let here = items.len() as isize;
                let target = if r.rare(bad) { r.pick(&[-1isize, here, 10_000]) } else { here + 1 + r.below(8) as isize };
                items.push(Item::Jump { opc, dst: if ja { 0 } else { dst }, src: if is_reg { src } else { 0 }, imm: super::rand_imm(r), target });
            } else {
                let v = r.below(4);
                let raw = match v {
                    0 => insn(r.pick(&[0x00u8, 0x0e, 0x20, 0x36, 0xd7, 0xe7, 0xf7, 0xff]), dst, 0, 0, 0),
                    1 => insn(0x85, 0, r.pick(&[0u8, 1, 2]), 0, super::rand_imm(r)),
                    2 => insn(0x8d, r.below(12) as u8, 0, 0, 0),
                    _ => insn(0x07, 10, 0, 0, 8),
                };
                items.push(Item::Raw(raw.to_vec()));
            }
        }
        if f == 0 {
            for i in 1..10u8 {
                items.push(Item::Raw(insn(0xaf, 0, i, 0, 0).to_vec()));
                items.push(Item::Raw(insn(0x67, 0, 0, 0, 7).to_vec()));
                items.push(Item::Raw(insn(0x0f, 0, i, 0, 0).to_vec()));
            }
        }
        if !r.rare(bad) {
            items.push(Item::Raw(insn(0x95, 0, 0, 0, 0).to_vec()));
        }
        funcs.push(items);
    }
    // layout: funções em sequência; slot inicial de cada item
    let mut func_start = vec![0isize; n_funcs + 1];
    let mut slots: Vec<Vec<isize>> = vec![];
    for (f, items) in funcs.iter().enumerate() {
        let mut slot = vec![func_start[f]; items.len() + 1];
        for (i, it) in items.iter().enumerate() {
            let n = match it { Item::Raw(b) => (b.len() / 8) as isize, Item::Jump { .. } => 1, Item::Call { target } => if *target < 0 { 3 } else { 1 } };
            slot[i + 1] = slot[i] + n;
        }
        func_start[f + 1] = slot[items.len()];
        slots.push(slot);
    }
    let total = func_start[n_funcs];
    let mut prog = vec![];
    for (f, items) in funcs.iter().enumerate() {
        let slot = &slots[f];
        for (i, it) in items.iter().enumerate() {
            match it {
                Item::Raw(b) => prog.extend_from_slice(b),
                Item::Jump { opc, dst, src, imm, target } => {
                    let t = if *target < 0 { -1 } else if *target as usize >= items.len() { total + 3 } else { slot[*target as usize] };
                    let t = if r.rare(bad) { t + 1 } else { t };
                    let off = t - (slot[i] + 1);
                    prog.extend_from_slice(&insn(*opc, *dst, *src, off.clamp(i16::MIN as isize, i16::MAX as isize) as i16, *imm));
                }
                Item::Call { target } => {
                    if *target >= 0 {
                        let t = func_start[*target as usize];
                        let t = if r.rare(bad * 3) { t + 50_000 } else { t };
                        let imm = t - (slot[i] + 1);
                        prog.extend_from_slice(&insn(0x85, 0, 1, 0, imm as i32));
                    } else {
                        let fi = (-1 - *target) as usize;
                        let mut addr = 0x1_0000_0000u64 + (func_start[fi] as u64) * 8;
                        if r.rare(30) { addr = r.pick(&[0, 0x1_0000_0000 + total as u64 * 8, 0x2_0000_0000, u64::MAX]); }
                        prog.extend_from_slice(&lddw(8, addr));
                        prog.extend_from_slice(&insn(0x8d, 8, 0, 0, 0));
                    }
                }
            }
        }
    }
    let input: Vec<u8> = (0..(if r.chance(70) { 32 + r.below(17) } else { r.below(32) })).map(|_| r.next() as u8).collect();
    let max_cu = if r.chance(15) { r.below(300) } else { 20_000 };
    (prog, input, max_cu)
}
