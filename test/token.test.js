const { expect } = require("chai");
const { ethers } = require("hardhat");
const { prog, hex } = require("./helpers");
const { mine } = require("../js/miner");

describe("ProofOfExecutionToken (mint exige executar sBPF)", function () {
  this.timeout(300000);
  let tok, miner, other, code;
  const EASY = (1n << 64n) / 64n; // ~64 tentativas por mint

  before(async () => {
    [miner, other] = await ethers.getSigners();
    code = prog("puzzle");
    const F = await ethers.getContractFactory("ProofOfExecutionToken");
    tok = await F.deploy(hex(code), EASY);
    await tok.waitForDeployment();
  });

  it("guarda o puzzle on-chain", async () => {
    expect(await tok.puzzleCode()).to.equal(hex(code));
    expect(await tok.puzzleHash()).to.equal(ethers.keccak256(code));
  });

  it("buildInput on-chain = buildInput do minerador", async () => {
    const { buildInput } = require("../js/miner");
    const ch = await tok.challenge();
    expect(await tok.buildInput(miner.address, 123)).to.equal(hex(buildInput(ch, miner.address, 123n, EASY)));
  });

  it("nonce errado é rejeitado", async () => {
    const ch = await tok.challenge();
    // acha um nonce que FALHA
    const { buildInput } = require("../js/miner");
    const jsvm = require("../js/vm");
    let n = 0n;
    while (jsvm.run(code, buildInput(ch, miner.address, n, EASY), 20000).r0 === 0n) n++;
    await expect(tok.mint(n)).to.be.revertedWithCustomError(tok, "InvalidProof").withArgs(1);
  });

  it("minera com a VM JS e faz mint verificado pela VM Solidity", async () => {
    const ch = await tok.challenge();
    const found = mine(code, ch, miner.address, EASY);
    expect(found).to.not.equal(null);
    const [r0, cu] = await tok.verify(miner.address, found.nonce);
    expect(r0).to.equal(0n);
    expect(Number(cu)).to.equal(found.steps);

    const tx = await tok.mint(found.nonce);
    const rc = await tx.wait();
    console.log(`      ${found.tries} tentativas, ${found.steps} compute units, gas do mint: ${rc.gasUsed}`);
    await expect(tx).to.emit(tok, "Mined");
    expect(await tok.balanceOf(miner.address)).to.equal(ethers.parseEther("50"));
    expect(await tok.challenge()).to.not.equal(ch);
  });

  it("prova é amarrada ao minerador (front-running não funciona)", async () => {
    const ch = await tok.challenge();
    const found = mine(code, ch, miner.address, EASY);
    const [r0] = await tok.verify(other.address, found.nonce);
    // muito provavelmente inválido para outro endereço
    if (r0 !== 0n) await expect(tok.connect(other).mint(found.nonce)).to.be.revertedWithCustomError(tok, "InvalidProof");
    await tok.mint(found.nonce);
    // nonce já usado: challenge mudou
    const [r0b] = await tok.verify(miner.address, found.nonce);
    if (r0b !== 0n) await expect(tok.mint(found.nonce)).to.be.revertedWithCustomError(tok, "InvalidProof");
  });

  it("reajusta a dificuldade a cada 32 mints", async () => {
    const before = await tok.difficultyTarget();
    while ((await tok.mintCount()) < 32n) {
      const found = mine(code, await tok.challenge(), miner.address, await tok.difficultyTarget());
      await tok.mint(found.nonce);
    }
    // mints muito rápidos (blocos de 1s) -> alvo cai 4x (fica mais difícil)
    expect(await tok.difficultyTarget()).to.equal(before / 4n);
  });
});
