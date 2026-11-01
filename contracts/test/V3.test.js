const { expect } = require("chai");
const { INPUT_START, loadJson, deploySolanaVM, statusName, parseLogs } = require("./solanaHelpers");

// Fixtures gerados pela VM oficial (solana-sbpf 0.26, SBPFVersion::V3) em reference/src/v3.rs:
// programa como bytecode cru, uma região de input gravável em 0x400000000, sem rodata.
const ENV = { programId: "0x" + "00".repeat(32), maxCu: 0, r2: 0, sysvars: [] };

async function check(vm, f) {
  const regions = [{ vaddr: INPUT_START, writable: true, reserved: 0, data: f.input }];
  const r = await vm.run(f.program, 0, "0x", regions, { ...ENV, maxCu: f.maxCu });
  const got = statusName(r);
  const e = f.expect;
  if (got !== e.status) return `${f.name}: status ${got}, esperado ${e.status} (pc ${r.pc}, cu ${r.cu}, fault 0x${r.fault.toString(16)})`;
  if (Number(r.cu) !== e.cu) return `${f.name}: cu ${r.cu}, esperado ${e.cu}`;
  if (e.status === "Ok" && r.r0 !== BigInt(e.r0)) return `${f.name}: r0 0x${r.r0.toString(16)}, esperado ${e.r0}`;
  if (e.input !== undefined && r.regions[0] !== e.input) return `${f.name}: input final ${r.regions[0]}, esperado ${e.input}`;
  if (e.logs !== undefined) {
    const logs = parseLogs(r.logs).filter((l) => l.kind === 0).map((l) => l.text);
    if (JSON.stringify(logs) !== JSON.stringify(e.logs)) return `${f.name}: logs ${JSON.stringify(logs)}, esperado ${JSON.stringify(e.logs)}`;
  }
  return null;
}

async function checkAll(vm, fixtures, batch = 32) {
  const bad = [];
  for (let i = 0; i < fixtures.length; i += batch) {
    const res = await Promise.all(fixtures.slice(i, i + batch).map((f) => check(vm, f)));
    for (const x of res) if (x) bad.push(x);
  }
  return bad;
}

describe("SolanaVM — ISA sBPF v3 (diferencial contra a VM oficial)", function () {
  let vm;
  before(async () => {
    vm = await deploySolanaVM();
  });

  it("casos dirigidos: chamadas, frames, callx, syscalls, memória, jmp32, inválidos", async () => {
    const fx = loadJson("v3/isa.json");
    const bad = await checkAll(vm, fx);
    if (bad.length) console.log(bad.slice(0, 40).join("\n"));
    expect(bad, `${bad.length} de ${fx.length} divergem`).to.deep.equal([]);
    console.log(`      ${fx.length} casos iguais à referência`);
  });

  it("programas aleatórios (fuzz) com funções, callx, syscalls e heap", async function () {
    const fx = loadJson("v3/random.json");
    const bad = await checkAll(vm, fx);
    if (bad.length) console.log(bad.slice(0, 40).join("\n"));
    expect(bad, `${bad.length} de ${fx.length} divergem`).to.deep.equal([]);
    console.log(`      ${fx.length} casos iguais à referência`);
  });
});
