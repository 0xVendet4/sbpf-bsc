const { expect } = require("chai");
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");
const { SV_CLOCK, deploySolanaRuntime, errorName } = require("./solanaHelpers");

// O programa SPL Token oficial (sBPF v0, Tokenkeg...) rodando no SolanaRuntime: o ELF passa pelo
// SolanaLoader (relocações, como o agave) e a imagem resultante roda na mesma VM dos programas v3.
// Cada caso compara erro, CU, return data, log e contas finais com o Mollusk (agave 4.3).

const SV_RENT = "0x06a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44e3dbd98a00000000";
const token = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "fixtures", "solana", "token.json"), "utf8"));

function callOf(f) {
  const accounts = f.accounts.map((a) => ({ key: a.key, owner: a.owner, lamports: BigInt(a.lamports), executable: a.executable, data: a.data }));
  const metas = f.metas.map((m) => ({ account: f.accounts.findIndex((a) => a.key === m.key), isSigner: m.isSigner, isWritable: m.isWritable }));
  const sysvars = [{ id: SV_CLOCK, data: f.sysvars.clock }, { id: SV_RENT, data: f.sysvars.rent }];
  return { programId: f.programId, maxCu: BigInt(f.maxCu), accounts, metas, data: f.data, sysvars };
}

describe("SPL Token (sBPF v0) no SolanaRuntime — diferencial contra o Mollusk/agave", function () {
  let rt;
  let image;
  before(async () => {
    ({ rt } = await deploySolanaRuntime());
    const loader = await (await ethers.getContractFactory("SolanaLoader")).deploy();
    image = await loader.image(token.programs.spl_token);
  });

  for (const f of token.fixtures) {
    it(f.name, async () => {
      const o = await rt.invoke(image, callOf(f));
      const e = f.expect;
      expect(errorName(o), `erro (log: ${o.logs})`).to.equal(e.error);
      expect(Number(o.cu), "compute units").to.equal(e.cu);
      expect(o.returnData, "return data").to.equal(e.returnData);
      expect(o.logs.split("\n"), "log").to.deep.equal(e.logs);
      const norm = (a) => ({ key: a.key, owner: a.owner, lamports: Number(a.lamports), data: a.data, executable: a.executable });
      expect(o.accounts.map(norm), "contas finais").to.deep.equal(e.accounts.map(norm));
    });
  }

  it("gás: verificar a imagem (uma vez, ao publicar) e executar uma transferência", async () => {
    const f = token.fixtures.find((x) => x.name === "token_transfer");
    const withVerify = await rt.invoke.estimateGas(image, callOf(f));
    const verified = await rt.invokeVerified.estimateGas(image, callOf(f));
    const vm = await ethers.getContractAt("SolanaVM", await rt.vm());
    const verify = await vm.verifyElf.estimateGas(image);
    console.log(`      verifyElf ${verify} gás; transferência ${verified} gás (com verificação ${withVerify})`);
    expect(await vm.verifyElf(image)).to.equal(true);
    expect(verify < 16_000_000n).to.equal(true);
  });
});
