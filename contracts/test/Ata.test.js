const { expect } = require("chai");
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");
const { SV_CLOCK, deploySolanaRuntime, errorName } = require("./solanaHelpers");

// CPI entre programas sBPF: o Associated Token Account oficial (sBPF v0) chama o SPL Token
// (GetAccountDataSize, InitializeImmutableOwner, InitializeAccount3) e o system program
// (CreateAccount, ou Transfer + Allocate + Assign assinados pelo PDA). Cada caso compara erro, CU,
// return data, log (com as linhas "invoke [2]" do programa chamado) e contas finais com o Mollusk.

const SV_RENT = "0x06a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44e3dbd98a00000000";
const dir = path.join(__dirname, "..", "..", "fixtures", "solana");
const ata = JSON.parse(fs.readFileSync(path.join(dir, "ata.json"), "utf8"));
const token = JSON.parse(fs.readFileSync(path.join(dir, "token.json"), "utf8"));
const ELF = { spl_token: token.programs.spl_token, associated_token: ata.programs.associated_token };
const data = (d) => (d.startsWith("elf:") ? ELF[d.slice(4)] : d);

function callOf(f) {
  const accounts = f.accounts.map((a) => ({ key: a.key, owner: a.owner, lamports: BigInt(a.lamports), executable: a.executable, data: data(a.data) }));
  const metas = f.metas.map((m) => ({ account: f.accounts.findIndex((a) => a.key === m.key), isSigner: m.isSigner, isWritable: m.isWritable }));
  const sysvars = [{ id: SV_CLOCK, data: f.sysvars.clock }, { id: SV_RENT, data: f.sysvars.rent }];
  return { programId: f.programId, maxCu: BigInt(f.maxCu), accounts, metas, data: f.data, sysvars };
}

describe("Associated Token Account → SPL Token por CPI (sBPF chamando sBPF) — diferencial contra o Mollusk/agave", function () {
  let rt;
  let image;
  let programs;
  before(async () => {
    ({ rt } = await deploySolanaRuntime());
    const loader = await (await ethers.getContractFactory("SolanaLoader")).deploy();
    image = await loader.image(ELF.associated_token);
    programs = [{ id: token.fixtures[0].programId, image: await loader.image(ELF.spl_token) }];
  });

  for (const f of ata.fixtures) {
    it(f.name, async () => {
      const o = await rt.invokeWith(image, callOf(f), programs);
      const e = f.expect;
      expect(errorName(o), `erro (log: ${o.logs})`).to.equal(e.error);
      expect(o.logs.split("\n"), "log").to.deep.equal(e.logs);
      expect(Number(o.cu), "compute units").to.equal(e.cu);
      expect(o.returnData, "return data").to.equal(e.returnData);
      const norm = (a) => ({ key: a.key, owner: a.owner, lamports: Number(a.lamports), data: data(a.data), executable: a.executable });
      expect(o.accounts.map(norm), "contas finais").to.deep.equal(e.accounts.map(norm));
    });
  }

  it("sem o SPL Token no cache de programas: 'Program is not cached' como no agave", async () => {
    const f = ata.fixtures.find((x) => x.name === "ata_create");
    const o = await rt.invokeWith(image, callOf(f), []);
    expect(errorName(o)).to.equal("UnsupportedProgramId");
    const lines = o.logs.split("\n");
    expect(lines.slice(2, 5)).to.deep.equal([
      "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]",
      "Program is not cached",
      "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA failed: Unsupported program id",
    ]);
  });

  it("gás: criar uma conta de token associada (4 CPIs, 3 delas para o SPL Token)", async () => {
    const f = ata.fixtures.find((x) => x.name === "ata_create");
    const g = await rt.invokeWith.estimateGas(image, callOf(f), programs);
    console.log(`      ata_create: ${g} gás (${f.expect.cu} CU)`);
    expect(g < 16_000_000n).to.equal(true);
  });
});
