const { expect } = require("chai");
const { ethers } = require("hardhat");
const { SV_CLOCK, loadJson, deploySolanaVM, statusName } = require("./solanaHelpers");
const { finish } = require("./solanaRuntime");

// Programas Solana reais (ELF .so do repositório do agave, compilados para sBPF v3), executados
// pelo Mollusk (agave 4.3) em reference-runtime/. O fixture traz a serialização das contas já
// pronta (as regiões de memória), o clock e o resultado esperado: erro, CU, logs, return data e
// contas finais.

function regionsOf(f) {
  return f.regions.map((rg, i) => {
    // o espaço reservado de uma região vai até o começo da próxima (realloc de contas); a última não cresce
    const reserved = i + 1 < f.regions.length ? BigInt(f.regions[i + 1].vaddr) - BigInt(rg.vaddr) : 0n;
    return { vaddr: BigInt(rg.vaddr), writable: rg.writable, reserved, data: rg.bytes };
  });
}

function envOf(f) {
  return { programId: f.programId, maxCu: f.maxCu, r2: BigInt(f.ixDataOffset), sysvars: [{ id: SV_CLOCK, data: f.sysvars.clock }] };
}

// Programas que fazem CPI: a VM suspende-se na syscall e quem continua é o SolanaRuntime (com o
// SolanaCpi); esses casos são conferidos em Runtime.test.js.
const usesCpi = (f) => f.name.startsWith("cpi_") || f.program === "simple_transfer_program";

describe("SolanaVM — programas Solana reais (diferencial contra o Mollusk/agave)", function () {
  let vm;
  const fixtures = loadJson("solana/programs.json");
  before(async () => {
    vm = await deploySolanaVM();
  });

  it("carregador ELF: aceita os .so v3 e rejeita cabeçalhos errados", async () => {
    const elf = fixtures[0].elf;
    const p = await vm.parseElf(elf);
    expect(p.ok).to.equal(true);
    expect(p.entry).to.equal(0n);
    const bad = ethers.getBytes(elf);
    bad[48] = 2; // e_flags: versão 2
    expect((await vm.parseElf(bad)).ok).to.equal(false);
    const bad2 = ethers.getBytes(elf);
    bad2[4] = 1; // ELFCLASS32
    expect((await vm.parseElf(bad2)).ok).to.equal(false);
    expect((await vm.parseElf("0x7f454c46")).ok).to.equal(false);
  });

  for (const f of fixtures.filter((x) => !usesCpi(x))) {
    it(`${f.name} (${f.program})`, async () => {
      const r = await vm.runElf(f.elf, regionsOf(f), envOf(f));
      const got = finish(f, r);
      const e = f.expect;
      const ctx = `status ${statusName(r)} pc ${r.pc} cu ${r.cu} r0 0x${r.r0.toString(16)} fault 0x${r.fault.toString(16)}`;
      expect(got.error, `erro (${ctx})`).to.equal(e.error);
      expect(got.consumed, "compute units").to.equal(e.cu);
      expect(got.returnData, "return data").to.equal(e.returnData);
      expect(got.logs, "log").to.deep.equal(e.logs);
      const norm = (a) => ({ key: a.key, owner: a.owner, lamports: Number(a.lamports), data: a.data, executable: a.executable });
      expect(got.accounts.map(norm), "contas finais").to.deep.equal(e.accounts.map(norm));
    });
  }
});
