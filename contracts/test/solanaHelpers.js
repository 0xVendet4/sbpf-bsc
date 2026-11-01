// Ajudantes dos testes diferenciais do SolanaVM (sBPF v3 + runtime).
const fs = require("fs");
const path = require("path");
const { ethers } = require("hardhat");

const STATUS = ["Ok", "Invalid", "DivideByZero", "AccessViolation", "CuExceeded", "CallDepthExceeded", "CallOutsideTextSegment", "SyscallError"];
const SYSCALL_ERR = {
  1: "Abort", 2: "Panic", 3: "InvalidString", 4: "CopyOverlapping", 5: "InvalidPointer", 6: "ReturnDataTooLarge",
  7: "UnalignedPointer", 8: "InvalidLength", 9: "Unimplemented", 10: "ArithmeticOverflow", 11: "TooManySlices", 12: "UnsupportedSysvar",
};
const INPUT_START = 0x400000000n;
const SV_CLOCK = "0x06a7d51718c774c928566398691d5eb68b5eb8a39b4b6d5c73555b2100000000";

function loadJson(rel) {
  const j = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "fixtures", rel), "utf8"));
  if (j.programs) for (const f of j.fixtures) f.elf = j.programs[f.program]; // ELF guardado uma vez por programa
  return j.fixtures;
}

async function deploySolanaVM() {
  const F = await ethers.getContractFactory("SolanaVM");
  const vm = await F.deploy();
  await vm.waitForDeployment();
  return vm;
}

/// Nome do status como nos fixtures (SyscallError vira o nome do erro).
function statusName(r) {
  const s = STATUS[Number(r.status)];
  if (s === "SyscallError") return SYSCALL_ERR[Number(r.err)] || `SyscallError(${r.err})`;
  return s;
}

/// Decodifica o buffer de logs: [tipo:1][tamanho:4][payload]
function parseLogs(hex) {
  const b = ethers.getBytes(hex);
  const out = [];
  let i = 0;
  while (i < b.length) {
    const kind = b[i];
    const len = (b[i + 1] << 24 | b[i + 2] << 16 | b[i + 3] << 8 | b[i + 4]) >>> 0;
    const payload = b.slice(i + 5, i + 5 + len);
    i += 5 + len;
    if (kind === 0) out.push({ kind, text: Buffer.from(payload).toString("utf8") });
    else if (kind === 1) out.push({ kind, pubkey: payload });
    else if (kind === 2) {
      const fields = [];
      let j = 0;
      while (j < payload.length) {
        const fl = (payload[j] << 24 | payload[j + 1] << 16 | payload[j + 2] << 8 | payload[j + 3]) >>> 0;
        fields.push(payload.slice(j + 4, j + 4 + fl));
        j += 4 + fl;
      }
      out.push({ kind, fields });
    } else if (kind === 3) {
      const dv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
      out.push({ kind, line: dv.getBigUint64(0), column: dv.getBigUint64(8), file: Buffer.from(payload.slice(16)).toString("utf8") });
    } else out.push({ kind, payload });
  }
  return out;
}

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58(bytes) {
  let n = BigInt("0x" + Buffer.from(bytes).toString("hex").padStart(2, "0"));
  let s = "";
  while (n > 0n) {
    s = B58[Number(n % 58n)] + s;
    n /= 58n;
  }
  for (const x of bytes) {
    if (x !== 0) break;
    s = "1" + s;
  }
  return s;
}

/// Formata as entradas do log como o agave ("Program log: ...", "Program data: ...").
function formatLogs(entries) {
  return entries.map((e) => {
    if (e.kind === 0) return `Program log: ${e.text}`;
    if (e.kind === 1) return `Program log: ${base58(e.pubkey)}`;
    if (e.kind === 2) return `Program data: ${e.fields.map((f) => Buffer.from(f).toString("base64")).join(" ")}`;
    return null;
  }).filter((x) => x !== null);
}

module.exports = { STATUS, SYSCALL_ERR, INPUT_START, SV_CLOCK, loadJson, deploySolanaVM, statusName, parseLogs, formatLogs, base58 };
