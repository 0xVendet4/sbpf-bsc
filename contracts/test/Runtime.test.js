const { expect } = require("chai");
const { ethers } = require("hardhat");
const { SV_CLOCK, loadJson, deploySolanaRuntime, errorName } = require("./solanaHelpers");

// SolanaRuntime.sol recebe a instrução como o agave recebe (programa, contas, metas, dados, sysvars),
// serializa as contas ele mesmo (ABIv1 com direct mapping), roda o SolanaVM e aplica as regras do
// loader. O teste compara erro, CU, return data, log e contas finais com o Mollusk (agave 4.3).

/// Monta a chamada a partir do fixture: as metas referenciam as contas pelo índice.
function callOf(f) {
  const accounts = f.accounts.map((a) => ({ key: a.key, owner: a.owner, lamports: BigInt(a.lamports), executable: a.executable, data: a.data }));
  const metas = f.metas.map((m) => {
    const idx = f.accounts.findIndex((a) => a.key === m.key);
    if (idx < 0) throw new Error(`meta sem conta: ${m.key}`);
    return { account: idx, isSigner: m.isSigner, isWritable: m.isWritable };
  });
  return { programId: f.programId, maxCu: BigInt(f.maxCu), accounts, metas, data: f.data, sysvars: [{ id: SV_CLOCK, data: f.sysvars.clock }] };
}

const deployRuntime = deploySolanaRuntime;

const CPI = new Set(); // CPI para o system program já é suportada

describe("SolanaRuntime — instruções completas (diferencial contra o Mollusk/agave)", function () {
  let rt;
  const fixtures = loadJson("solana/programs.json");
  before(async () => {
    ({ rt } = await deployRuntime());
  });

  for (const f of fixtures) {
    const it_ = CPI.has(f.name) ? it.skip : it;
    it_(`${f.name} (${f.program})`, async () => {
      const o = await rt.invoke(f.elf, callOf(f));
      const e = f.expect;
      expect(errorName(o), `erro (log: ${o.logs})`).to.equal(e.error);
      expect(Number(o.cu), "compute units").to.equal(e.cu);
      expect(o.returnData, "return data").to.equal(e.returnData);
      expect(o.logs.split("\n"), "log").to.deep.equal(e.logs);
      const norm = (a) => ({ key: a.key, owner: a.owner, lamports: Number(a.lamports), data: a.data, executable: a.executable });
      expect(o.accounts.map(norm), "contas finais").to.deep.equal(e.accounts.map(norm));
    });
  }

  it("serialização: bate com a região de input que o Mollusk montou", async () => {
    // o fixture traz a memória de input que o agave serializou; a nossa tem de ser byte a byte igual
    for (const f of fixtures) {
      const s = await rt.serialize(callOf(f));
      const ours = s.regions.map((r) => ({ vaddr: r.vaddr, writable: r.writable, data: r.data }));
      const theirs = f.regions.map((r) => ({ vaddr: BigInt(r.vaddr), writable: r.writable, data: r.bytes }));
      expect(ours, f.name).to.deep.equal(theirs);
      expect(s.ixDataAddr, `${f.name}: endereço dos dados da instrução`).to.equal(BigInt(f.ixDataOffset));
    }
  });

  it("rejeita metas que apontam para contas inexistentes", async () => {
    const f = fixtures.find((x) => x.name === "hello");
    const c = callOf(f);
    c.metas = [{ account: 200, isSigner: false, isWritable: false }];
    await expect(rt.invoke(f.elf, c)).to.be.revertedWithCustomError(rt, "BadMeta");
  });
});
