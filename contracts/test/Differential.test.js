// Teste diferencial: cada fixture foi gerado pela VM oficial (solana-sbpf 0.26.0, reference/).
// Status, r0 e CU precisam bater. Em caso de erro, só o status é comparado.
const { expect } = require("chai");
const { loadFixtures, deployVM, checkAll } = require("./helpers");

describe("Diferencial contra o solana-sbpf", function () {
  let vm;
  before(async () => { vm = await deployVM(); });

  for (const set of ["opcodes", "memory", "invalid", "programs", "random"]) {
    it(`fixtures/${set}.json`, async () => {
      const fixtures = loadFixtures(set);
      const bad = await checkAll(vm, fixtures);
      const byStatus = {};
      for (const f of fixtures) byStatus[f.expect.status] = (byStatus[f.expect.status] || 0) + 1;
      console.log(`      ${fixtures.length - bad.length}/${fixtures.length} iguais  ${JSON.stringify(byStatus)}`);
      expect(bad, bad.slice(0, 15).join("\n")).to.deep.equal([]);
    });
  }
});
