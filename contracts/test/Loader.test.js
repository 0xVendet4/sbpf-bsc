const { expect } = require("chai");
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

// Carregador de ELF sBPF v0 on-chain (SolanaLoader) contra o carregador do agave
// (`Executable::load` do solana-sbpf 0.23, gravado em fixtures/solana/token.json pelo
// reference-runtime): mesma região só leitura byte a byte, mesmo registro de funções, mesma entrada.

const token = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "fixtures", "solana", "token.json"), "utf8"));
const REGION = 1n << 32n;

function parseImage(hex) {
  const b = ethers.getBytes(hex);
  const dv = new DataView(b.buffer, b.byteOffset);
  const nf = dv.getUint32(16);
  const functions = [];
  for (let i = 0; i < nf; i++) functions.push([dv.getUint32(20 + 8 * i), dv.getUint32(24 + 8 * i)]);
  return {
    magic: ethers.hexlify(b.slice(0, 4)),
    entry: dv.getUint32(4),
    textAddr: dv.getUint32(8),
    textLen: dv.getUint32(12),
    functions,
    ro: ethers.hexlify(b.slice(20 + 8 * nf)),
  };
}

describe("SolanaLoader — ELF sBPF v0 (diferencial contra o carregador do agave)", function () {
  let loader;
  const elf = token.programs.spl_token;
  const ref = token.loaded.spl_token;

  before(async () => {
    loader = await (await ethers.getContractFactory("SolanaLoader")).deploy();
  });

  it("murmur3 dos nomes das syscalls = registro de syscalls do agave", async () => {
    for (const [key, name] of ref.syscalls) {
      expect(await loader.hashSymbol(ethers.toUtf8Bytes(name)), name).to.equal(BigInt(key));
    }
    expect(await loader.hashSymbol(ethers.toUtf8Bytes("entrypoint"))).to.equal(await loader.ENTRYPOINT_KEY());
  });

  it("SPL Token: região só leitura, registro de funções e entrada iguais ao agave", async () => {
    const img = parseImage(await loader.image(elf));
    expect(img.magic).to.equal("0x7f534230");
    expect(BigInt(ref.roVaddr)).to.equal(REGION);
    expect(img.entry).to.equal(ref.entryPc);
    expect(BigInt(img.textAddr) + REGION).to.equal(BigInt(ref.textVaddr));
    expect(img.textLen).to.equal(ref.textLen);
    expect(img.functions).to.deep.equal(ref.functions);
    expect(img.ro.length).to.equal(ref.ro.length);
    expect(img.ro === ref.ro, "região só leitura").to.equal(true);
    const layout = ethers.getBytes(await loader.load(elf));
    const g = await loader.load.estimateGas(elf);
    console.log(`      layout ${layout.length} bytes (ELF ${ethers.getBytes(elf).length}), gás do carregamento ${g}`);
  });

  it("rejeita ELFs malformados", async () => {
    const base = ethers.getBytes(elf);
    const bad = (mut) => {
      const b = new Uint8Array(base);
      mut(b);
      return b;
    };
    const cases = {
      "mágica errada": bad((b) => (b[0] = 0)),
      "ELFCLASS32": bad((b) => (b[4] = 1)),
      "big-endian": bad((b) => (b[5] = 2)),
      "e_machine x86": bad((b) => (b[18] = 62)),
      "ET_EXEC": bad((b) => (b[16] = 2)),
      "entrada fora do .text": bad((b) => b.set([0, 0, 0, 0, 0, 0, 0, 0], 24)),
      "entrada desalinhada": bad((b) => (b[24] += 4)),
      "e_shstrndx inválido": bad((b) => (b[62] = 200)),
      truncado: base.slice(0, 1000),
    };
    for (const [name, b] of Object.entries(cases)) {
      await expect(loader.load(b), name).to.be.revertedWithCustomError(loader, "BadElf");
    }
  });
});
