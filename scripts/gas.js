// Benchmark de gás: npm run gas  (USE_SOLCJS=1 se não houver acesso ao solc binário)
// Mede eth_estimateGas de SbpfVM.run para os programas demo (fixtures/programs.json) e para
// loops longos, e imprime a tabela que vai no README.
const fs = require("fs");
const { ethers } = require("hardhat");

async function main() {
  const vm = await (await ethers.getContractFactory("SbpfVM")).deploy();
  await vm.waitForDeployment();
  const programs = JSON.parse(fs.readFileSync("fixtures/programs.json", "utf8")).fixtures;

  // custo fixo: transação + verificador + setup da VM, com o menor programa possível
  const base = Number(await vm.run.estimateGas("0x9500000000000000", "0x", 10));
  console.log(`custo fixo (programa "exit"): ${base} gas (inclui 21k da tx e ~calldata)\n`);

  console.log("| Programa | Input | CU | Gás total | Gás/instrução |");
  console.log("|---|---|---|---|---|");
  const rows = {};
  for (const f of programs) {
    const name = f.name.replace(/_\d+$/, "");
    const [status, r0, cu] = await vm.run(f.program, f.input, f.maxCu);
    const gas = Number(await vm.run.estimateGas(f.program, f.input, f.maxCu));
    rows[name] = rows[name] || [];
    rows[name].push({ input: f.input, cu: Number(cu), gas, r0, status: Number(status) });
  }
  for (const [name, rs] of Object.entries(rows)) {
    const r = rs.reduce((a, b) => (b.cu > a.cu ? b : a));
    const per = ((r.gas - base) / Math.max(r.cu - 1, 1)).toFixed(0);
    const inp = r.input.length > 22 ? r.input.slice(0, 20) + "…" : r.input;
    console.log(`| ${name} | ${inp} | ${r.cu} | ${r.gas} | ~${per} |`);
  }

  console.log("\nLoops longos (sub64 + jne por iteração):");
  for (const iters of [1000, 10000, 50000]) {
    // mov64 r1, iters ; sub64 r1, 1 ; jne r1, 0, -2 ; exit
    const prog = Buffer.concat([
      insn(0xb7, 1, 0, 0, iters), insn(0x17, 1, 0, 0, 1), insn(0x55, 1, 0, -2, 0), insn(0x95, 0, 0, 0, 0),
    ]);
    const [, , cu] = await vm.run(prog, "0x", 1_000_000);
    const gas = Number(await vm.run.estimateGas(prog, "0x", 1_000_000));
    console.log(`  ${Number(cu)} instruções: ${gas} gas  (~${((gas - base) / Number(cu)).toFixed(0)} gas/instrução)`);
  }
}

function insn(opc, dst, src, off, imm) {
  const b = Buffer.alloc(8);
  b[0] = opc; b[1] = (src << 4) | dst; b.writeInt16LE(off, 2); b.writeInt32LE(imm, 4);
  return b;
}

main().catch((e) => { console.error(e); process.exit(1); });
