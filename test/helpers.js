const fs = require("fs");
const path = require("path");
const { ethers } = require("hardhat");
const { assemble } = require("../js/assembler");

const prog = (name) => assemble(fs.readFileSync(path.join(__dirname, "..", "programs", name + ".s"), "utf8"));
const u64le = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt.asUintN(64, BigInt(v))); return b; };
const hex = (b) => "0x" + Buffer.from(b).toString("hex");

/// Executa via SolanaRuntime.execute (eth_call). Retorna {ok, r0, steps, input, logs} ou {ok:false, kind}.
async function execSol(runtime, code, input, budget = 100000) {
  try {
    const res = await runtime.execute(hex(code), hex(input), budget);
    return { ok: true, r0: res.r0, steps: Number(res.steps), input: Buffer.from(res.input.slice(2), "hex"), logs: res.logs };
  } catch (e) {
    const data = e.data || e?.error?.data;
    if (!data) throw e;
    const parsed = runtime.interface.parseError(data);
    if (!parsed) throw e;
    return { ok: false, kind: parsed.name, args: parsed.args };
  }
}

async function deployRuntime() {
  const F = await ethers.getContractFactory("SolanaRuntime");
  const c = await F.deploy();
  await c.waitForDeployment();
  return c;
}

module.exports = { prog, u64le, hex, execSol, deployRuntime, assemble };
