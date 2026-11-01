// Camada de runtime em JS (protótipo do que o contrato SolanaRuntime faz on-chain):
// mapeia o resultado da VM para InstructionError, aplica as regras de desserialização das
// contas (ABIv1, agave 4.3) e monta o log no formato do agave. Serve de especificação
// executável: o teste compara isto com o Mollusk.
const { ethers } = require("hardhat");
const { INPUT_START, statusName, parseLogs, formatLogs, base58 } = require("./solanaHelpers");

const MAX_PERMITTED_DATA_INCREASE = 10240;
const MAX_ACCOUNT_DATA_LEN = 10 * 1024 * 1024;
const MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION = 2 * MAX_ACCOUNT_DATA_LEN;

// ProgramError (código << 32) → InstructionError
const BUILTIN = [null, "Custom(0)", "InvalidArgument", "InvalidInstructionData", "InvalidAccountData", "AccountDataTooSmall",
  "InsufficientFunds", "IncorrectProgramId", "MissingRequiredSignature", "AccountAlreadyInitialized", "UninitializedAccount",
  "NotEnoughAccountKeys", "AccountBorrowFailed", "MaxSeedLengthExceeded", "InvalidSeeds", "BorshIoError", "AccountNotRentExempt",
  "UnsupportedSysvar", "IllegalOwner", "MaxAccountsDataAllocationsExceeded", "InvalidRealloc", "MaxInstructionTraceLengthExceeded",
  "BuiltinProgramsMustConsumeComputeUnits", "InvalidAccountOwner", "ArithmeticOverflow", "Immutable", "IncorrectAuthority"];

function errorFromU64(code) {
  const hi = code >> 32n;
  if (hi === 0n) return `Custom(${code})`;
  return BUILTIN[Number(hi)] || "InvalidError";
}

const DISPLAY = {
  InvalidArgument: "invalid program argument", InvalidInstructionData: "invalid instruction data",
  InvalidAccountData: "invalid account data for instruction", AccountDataTooSmall: "account data too small for instruction",
  InsufficientFunds: "insufficient funds for instruction", IncorrectProgramId: "incorrect program id for instruction",
  MissingRequiredSignature: "missing required signature for instruction", AccountAlreadyInitialized: "instruction requires an uninitialized account",
  UninitializedAccount: "instruction requires an initialized account", UnbalancedInstruction: "sum of account balances before and after instruction do not match",
  ModifiedProgramId: "instruction illegally modified the program id of an account", ExternalAccountLamportSpend: "instruction spent from the balance of an account it does not own",
  ExternalAccountDataModified: "instruction modified data of an account it does not own", ReadonlyLamportChange: "instruction changed the balance of a read-only account",
  ReadonlyDataModified: "instruction modified data of a read-only account", NotEnoughAccountKeys: "insufficient account keys for instruction",
  AccountDataSizeChanged: "program other than the account's owner changed the size of the account data", InvalidError: "program returned invalid error code",
  InvalidRealloc: "Failed to reallocate account data", ComputationalBudgetExceeded: "Computational budget exceeded",
  ProgramFailedToComplete: "Program failed to complete", UnsupportedSysvar: "Unsupported sysvar", ArithmeticOverflow: "Program arithmetic overflowed",
  MaxAccountsDataAllocationsExceeded: "Accounts data allocations exceeded the maximum allowed per transaction",
};
function display(err) {
  const m = /^Custom\((\d+)\)$/.exec(err);
  if (m) return `custom program error: 0x${BigInt(m[1]).toString(16)}`;
  return DISPLAY[err] || err;
}

/// Memória final: lê bytes de um endereço virtual nas regiões devolvidas pela VM.
function memory(fixture, finalRegions) {
  const regs = fixture.regions.map((rg, i) => {
    const bytes = ethers.getBytes(finalRegions[i]);
    const next = i + 1 < fixture.regions.length ? BigInt(fixture.regions[i + 1].vaddr) : 1n << 64n;
    return { start: BigInt(rg.vaddr), bytes, reserved: Number(next - BigInt(rg.vaddr)) };
  });
  return {
    regs,
    read(vaddr, len) {
      vaddr = BigInt(vaddr);
      const rg = regs.filter((r) => r.start <= vaddr).pop();
      const off = Number(vaddr - rg.start);
      const out = new Uint8Array(len);
      out.set(rg.bytes.slice(off, off + len));
      return out;
    },
    u64(vaddr) { return new DataView(this.read(vaddr, 8).buffer).getBigUint64(0, true); },
    regionLen(vaddr) { return regs.find((r) => r.start === BigInt(vaddr)).bytes.length; },
  };
}

/// Percorre a serialização ABIv1 (direct mapping + ajustes de espaço de endereços) e devolve os
/// endereços dos campos de cada conta da instrução.
function layout(fixture) {
  const accounts = [];
  const seen = new Map();
  let v = INPUT_START + 8n;
  for (const m of fixture.metas) {
    if (seen.has(m.key)) {
      accounts.push({ dup: seen.get(m.key), key: m.key });
      v += 8n;
      continue;
    }
    const acct = fixture.accounts.find((a) => a.key === m.key);
    const preLen = ethers.getBytes(acct.data).length;
    const a = {
      dup: null, key: m.key, isSigner: m.isSigner, isWritable: m.isWritable, pre: acct,
      ownerAddr: v + 40n, lamportsAddr: v + 72n, dataLenAddr: v + 80n, dataAddr: v + 88n, preLen,
    };
    seen.set(m.key, accounts.length);
    accounts.push(a);
    const align = (8 - (preLen % 8)) % 8;
    v = a.dataAddr + BigInt(preLen + MAX_PERMITTED_DATA_INCREASE + align) + 8n; // rent_epoch
  }
  return accounts;
}

/// Pós-processamento do agave (`execute` + `deserialize_parameters` + verificação de saldo).
/// Devolve { error, consumed, accounts (finais, por chave, na ordem), failure (mensagem) }.
function finish(fixture, r) {
  const status = statusName(r);
  const maxCu = Number(fixture.maxCu);
  let consumed = Number(r.cu);
  const vmConsumed = consumed;
  const accts = layout(fixture);
  const mem = memory(fixture, r.regions);
  const programId = fixture.programId;
  let error = null;
  let failure = null;
  const owned = (a) => a.pre.owner === programId;
  const canDataBeChanged = (a) => (!a.isWritable ? "ReadonlyDataModified" : !owned(a) ? "ExternalAccountDataModified" : null);

  // estado final das contas (começa igual ao inicial)
  const final = new Map(fixture.accounts.map((a) => [a.key, { ...a }]));

  if (status === "Ok") {
    if (r.r0 !== 0n) {
      error = errorFromU64(r.r0);
    } else {
      // deserialize_parameters_for_abiv1
      let lamportsDelta = 0n;
      let resizeDelta = 0;
      for (const a of accts) {
        if (a.dup !== null) continue;
        const f = final.get(a.key);
        const owner = ethers.hexlify(mem.read(a.ownerAddr, 32));
        const lamports = mem.u64(a.lamportsAddr);
        if (BigInt(f.lamports) !== lamports) {
          if (!owned(a) && lamports < BigInt(f.lamports)) { error = "ExternalAccountLamportSpend"; break; }
          if (!a.isWritable) { error = "ReadonlyLamportChange"; break; }
          lamportsDelta += lamports - BigInt(f.lamports);
          f.lamports = Number(lamports);
        }
        const postLen = Number(mem.u64(a.dataLenAddr));
        if (postLen - a.preLen > MAX_PERMITTED_DATA_INCREASE || postLen > MAX_ACCOUNT_DATA_LEN) { error = "InvalidRealloc"; break; }
        const curLen = mem.regionLen(a.dataAddr); // pode ter crescido durante a execução
        if (curLen !== postLen) {
          // set_data_length: can_data_be_resized + can_data_be_changed
          if (postLen > MAX_ACCOUNT_DATA_LEN) { error = "InvalidRealloc"; break; }
          if (resizeDelta + (postLen - curLen) > MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION) { error = "MaxAccountsDataAllocationsExceeded"; break; }
          const e = canDataBeChanged(a);
          if (e) { error = e; break; }
          resizeDelta += postLen - curLen;
        }
        f.data = ethers.hexlify(mem.read(a.dataAddr, postLen));
        if (f.owner !== owner) {
          if (!owned(a) || !a.isWritable || !ethers.getBytes(f.data).every((b) => b === 0)) { error = "ModifiedProgramId"; break; }
          f.owner = owner;
        }
      }
      if (!error && lamportsDelta !== 0n) error = "UnbalancedInstruction";
    }
    if (error) failure = display(error);
  } else {
    const inSyscall = (r.fault >> 129n) & 1n;
    const syscallErr = ["Abort", "Panic", "InvalidString", "CopyOverlapping", "InvalidPointer", "ReturnDataTooLarge", "UnalignedPointer",
      "InvalidLength", "Unimplemented", "ArithmeticOverflow", "TooManySlices", "UnsupportedSysvar"].includes(status);
    if (!syscallErr && !(status === "AccessViolation" && inSyscall)) consumed = maxCu; // deplete_cu_meter_on_vm_failure
    if (status === "CuExceeded") { error = "ComputationalBudgetExceeded"; failure = display(error); }
    else if (status === "UnsupportedSysvar" || status === "ArithmeticOverflow") { error = status; failure = display(error); }
    else if (status === "AccessViolation") {
      const vaddr = r.fault & ((1n << 64n) - 1n);
      const len = (r.fault >> 64n) & ((1n << 64n) - 1n);
      const isStore = ((r.fault >> 128n) & 1n) === 1n;
      const hit = accts.find((a) => (a.dup === null ? a : accts[a.dup]) && vaddr >= acctOf(a).dataAddr && vaddr < acctOf(a).dataAddr + BigInt(acctOf(a).preLen + MAX_PERMITTED_DATA_INCREASE));
      function acctOf(a) { return a.dup === null ? a : accts[a.dup]; }
      if (hit && vaddr + len <= acctOf(hit).dataAddr + BigInt(acctOf(hit).preLen + MAX_PERMITTED_DATA_INCREASE)) {
        const a = acctOf(hit);
        const e = canDataBeChanged(a);
        error = isStore ? (e || "InvalidRealloc") : (e ? "AccountDataTooSmall" : "InvalidRealloc");
        failure = display(error);
      } else {
        error = "ProgramFailedToComplete";
        failure = `Access violation in unknown section at address 0x${vaddr.toString(16)} of size ${len}`;
      }
    } else if (status === "Panic") {
      const p = parseLogs(r.logs).find((l) => l.kind === 3);
      error = "ProgramFailedToComplete";
      failure = `SBF program Panicked in ${p.file} at ${p.line}:${p.column}`;
    } else if (status === "Abort") { error = "ProgramFailedToComplete"; failure = "SBF program panicked"; }
    else { error = "ProgramFailedToComplete"; failure = status; }
  }

  // log no formato do agave
  const pid = base58(ethers.getBytes(programId));
  const logs = [`Program ${pid} invoke [1]`, ...formatLogs(parseLogs(r.logs)), `Program ${pid} consumed ${vmConsumed} of ${maxCu} compute units`];
  if (r.returnData !== "0x") logs.push(`Program return: ${pid} ${Buffer.from(ethers.getBytes(r.returnData)).toString("base64")}`);
  logs.push(error === null ? `Program ${pid} success` : `Program ${pid} failed: ${failure}`);

  const accounts = error === null ? [...final.values()] : fixture.accounts;
  return { error, consumed, accounts, logs, returnData: r.returnData };
}

module.exports = { finish, layout, errorFromU64, display, MAX_PERMITTED_DATA_INCREASE };
