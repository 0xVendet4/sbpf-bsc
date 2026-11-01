const { expect } = require("chai");
const { ethers } = require("hardhat");
const { loadJson, deploySolanaVM, base58 } = require("./solanaHelpers");

// SolanaStore: programas e contas Solana guardados na EVM, instruções processadas por transação.
// O fluxo é o de um cliente Solana: publicar o programa, criar a conta de dados pelo system
// program, mandar a instrução. As assinaturas vêm do msg.sender (20 últimos bytes da chave).

const fixtures = loadJson("solana/programs.json");
const elfOf = (program) => fixtures.find((f) => f.program === program).elf;
const INCINERATOR = "0x003390728d34116079bdc911bfff00dbd44d2ecdccf79ca6e10038e100000000"; // 1nc1nerator11111111111111111111111111111111
const le64 = (n) => ethers.toBeHex(n, 8).slice(2).match(/../g).reverse().join("");

/// Chave assinada por `addr` com um prefixo de 12 bytes (cada endereço controla 2^96 chaves).
function keyFor(addr, prefix = 0) {
  return ethers.zeroPadValue(ethers.concat([ethers.toBeHex(prefix, 12), addr]), 32);
}

const w = (key) => ({ key, isSigner: false, isWritable: true });
const r = (key) => ({ key, isSigner: false, isWritable: false });
const ws = (key) => ({ key, isSigner: true, isWritable: true });

async function deployStore() {
  const vm = await deploySolanaVM();
  const rt = await (await ethers.getContractFactory("SolanaRuntime")).deploy(await vm.getAddress());
  const store = await (await ethers.getContractFactory("SolanaStore")).deploy(await rt.getAddress());
  await store.waitForDeployment();
  return { vm, rt, store };
}

describe("SolanaStore — programas e contas Solana na EVM, instruções por transação", function () {
  let store, dev, alice, bob, programId, helloId;
  const gas = {};

  before(async () => {
    [dev, alice, bob] = await ethers.getSigners();
    ({ store } = await deployStore());
    programId = keyFor(dev.address, 1);
    helloId = keyFor(dev.address, 2);
  });

  it("publica programas (ELF em código de contrato) e rejeita ELF inválido ou chave de outro", async () => {
    const elf = elfOf("write_to_account_program");
    const tx = await store.connect(dev).deployProgram(programId, elf);
    gas.deploy = Number((await tx.wait()).gasUsed);
    await expect(tx).to.emit(store, "ProgramDeployed").withArgs(programId, dev.address, ethers.getBytes(elf).length);
    expect(await store.elf(programId)).to.equal(elf);
    const acct = await store.account(programId);
    expect(acct.executable).to.equal(true);
    expect(acct.owner).to.equal(await store.BPF_LOADER());
    await expect(store.connect(dev).deployProgram(programId, elf)).to.be.revertedWithCustomError(store, "AlreadyDeployed");
    await expect(store.connect(alice).deployProgram(keyFor(dev.address, 9), elf)).to.be.revertedWithCustomError(store, "NotSigner");
    await expect(store.connect(dev).deployProgram(keyFor(dev.address, 9), "0x7f454c46")).to.be.revertedWithCustomError(store, "InvalidElf");
    // programa grande (54 KB) é repartido em mais de um pedaço
    const big = elfOf("simple_transfer_program");
    await store.connect(dev).deployProgram(keyFor(dev.address, 3), big);
    expect(await store.elf(keyFor(dev.address, 3))).to.equal(big);
    await store.connect(dev).deployProgram(helloId, elfOf("hello_solana_program"));
  });

  it("hello: instrução sem contas, log no formato do agave no evento", async () => {
    const tx = await store.connect(alice).invoke(helloId, [], "0x", 0);
    const rc = await tx.wait();
    gas.hello = Number(rc.gasUsed);
    const ev = rc.logs.map((l) => { try { return store.interface.parseLog(l); } catch { return null; } }).find((l) => l && l.name === "Invoked");
    const pid = base58(ethers.getBytes(helloId));
    expect(ev.args.logs.split("\n")).to.deep.equal([
      `Program ${pid} invoke [1]`, "Program log: Hello, Solana!", `Program ${pid} consumed 136 of 200000 compute units`, `Program ${pid} success`,
    ]);
    expect(ev.args.cu).to.equal(136n);
  });

  it("lamports lastreados em wei: deposit, transfer e withdraw pelo system program", async () => {
    const wallet = keyFor(alice.address);
    await store.connect(alice).deposit(wallet, { value: 1_000_000_000n });
    expect((await store.account(wallet)).lamports).to.equal(1_000_000_000n);
    await store.connect(alice).transfer(wallet, keyFor(bob.address), 10n);
    expect((await store.account(keyFor(bob.address))).lamports).to.equal(10n);
    await expect(store.connect(bob).transfer(wallet, keyFor(bob.address), 1n)).to.be.revertedWithCustomError(store, "NotSigner");
    await expect(store.connect(alice).transfer(wallet, keyFor(bob.address), 10n ** 12n)).to.be.revertedWithCustomError(store, "InsufficientLamports");
    const before = await ethers.provider.getBalance(bob.address);
    await store.connect(bob).withdraw(keyFor(bob.address), 10n, bob.address);
    expect((await ethers.provider.getBalance(bob.address)) > before - 10n ** 15n).to.equal(true); // recebeu (menos o gás)
    expect(await ethers.provider.getBalance(await store.getAddress())).to.equal(1_000_000_000n - 10n);
  });

  it("createAccount + instrução que escreve na conta (write_to_account_program)", async () => {
    const wallet = keyFor(alice.address);
    const target = keyFor(alice.address, 7);
    await store.connect(alice).createAccount(wallet, target, 1_000_000n, 16n, programId);
    let a = await store.account(target);
    expect(a.owner).to.equal(programId);
    expect(a.data).to.equal("0x" + "00".repeat(16));
    await expect(store.connect(alice).createAccount(wallet, target, 1n, 16n, programId)).to.be.revertedWithCustomError(store, "AccountInUse");

    // opcode 0: só loga o tamanho; opcode 1: escreve 100 no primeiro byte
    const tx0 = await store.connect(bob).invoke(programId, [w(target)], "0x00", 0);
    const rc0 = await tx0.wait();
    const ev = rc0.logs.map((l) => { try { return store.interface.parseLog(l); } catch { return null; } }).find((l) => l && l.name === "Invoked");
    expect(ev.args.logs).to.include("Program log: account size 16");
    const tx1 = await store.connect(bob).invoke(programId, [w(target)], "0x01", 0);
    gas.write = Number((await tx1.wait()).gasUsed);
    a = await store.account(target);
    expect(a.data).to.equal("0x64" + "00".repeat(15));
    expect(a.lamports).to.equal(1_000_000n);

    // opcode 3: realloc para 116 bytes (zeros no fim), depois encolhe para 4
    await store.connect(bob).invoke(programId, [w(target)], "0x03" + le64(116), 0);
    expect((await store.account(target)).data).to.equal("0x64" + "00".repeat(115));
    await store.connect(bob).invoke(programId, [w(target)], "0x03" + le64(4), 0);
    expect((await store.account(target)).data).to.equal("0x64000000");
  });

  it("instrução que falha reverte com o InstructionError e o log, sem mudar nada", async () => {
    const target = keyFor(alice.address, 7);
    // conta só de leitura: ReadonlyDataModified (índice 15 → err 16)
    await expect(store.connect(bob).invoke(programId, [r(target)], "0x01", 0))
      .to.be.revertedWithCustomError(store, "ProgramFailed").withArgs(16, 0, (logs) => logs.includes("failed: instruction modified data of a read-only account"));
    // realloc além de +10240: InvalidRealloc (índice 36 → err 37)
    await expect(store.connect(bob).invoke(programId, [w(target)], "0x03" + le64(4 + 10241), 0))
      .to.be.revertedWithCustomError(store, "ProgramFailed").withArgs(37, 0, () => true);
    // opcode desconhecido: InvalidArgument (índice 1 → err 2)
    await expect(store.connect(bob).invoke(programId, [w(target)], "0x09", 0))
      .to.be.revertedWithCustomError(store, "ProgramFailed").withArgs(2, 0, () => true);
    // sem contas: NotEnoughAccountKeys (índice 19 → err 20)
    await expect(store.connect(bob).invoke(programId, [], "0x01", 0)).to.be.revertedWithCustomError(store, "ProgramFailed").withArgs(20, 0, () => true);
    // conta que não é do programa: ExternalAccountDataModified (índice 13 → err 14)
    const foreign = keyFor(bob.address, 1);
    await store.connect(bob).createAccount(keyFor(bob.address), foreign, 0n, 16n, keyFor(bob.address, 99));
    await expect(store.connect(bob).invoke(programId, [w(foreign)], "0x01", 0)).to.be.revertedWithCustomError(store, "ProgramFailed").withArgs(14, 0, () => true);
    expect((await store.account(target)).data).to.equal("0x64000000");
    // simulate devolve o mesmo resultado sem reverter
    const o = await store.simulate(programId, [r(target)], "0x01", 0, bob.address);
    expect(o.err).to.equal(16n);
    expect(o.cu).to.equal(200_000n); // a VM esgota o orçamento em falhas de acesso
  });

  it("burn: o programa move lamports entre contas e a soma se mantém", async () => {
    const target = keyFor(alice.address, 7);
    await store.connect(alice).invoke(programId, [w(target)], "0x03" + le64(8), 0); // o burn exige 8 bytes
    await store.connect(alice).deposit(INCINERATOR, { value: 10n });
    const tx = await store.connect(alice).invoke(programId, [w(target), w(INCINERATOR)], "0x02", 0);
    gas.burn = Number((await tx.wait()).gasUsed);
    expect((await store.account(target)).lamports).to.equal(0n);
    expect((await store.account(INCINERATOR)).lamports).to.equal(1_000_010n);
    // incinerador errado: InvalidAccountData (índice 3 → err 4); só leitura: ReadonlyLamportChange (14 → 15)
    await expect(store.connect(alice).invoke(programId, [w(target), w(keyFor(bob.address))], "0x02", 0))
      .to.be.revertedWithCustomError(store, "ProgramFailed").withArgs(4, 0, () => true);
    await store.connect(alice).deposit(target, { value: 5n }); // com saldo zero não haveria mudança de lamports
    await expect(store.connect(alice).invoke(programId, [w(target), r(INCINERATOR)], "0x02", 0))
      .to.be.revertedWithCustomError(store, "ProgramFailed").withArgs(15, 0, () => true);
  });

  it("assinaturas: isSigner exige que a chave seja do msg.sender; limite de CU", async () => {
    const target = keyFor(alice.address, 7);
    await expect(store.connect(bob).invoke(programId, [ws(target)], "0x00", 0)).to.be.revertedWithCustomError(store, "NotSigner");
    await store.connect(alice).invoke(programId, [ws(target)], "0x00", 0);
    await expect(store.connect(alice).invoke(programId, [w(target)], "0x00", 1_400_001)).to.be.revertedWithCustomError(store, "ComputeLimitTooHigh");
    await expect(store.connect(alice).invoke(programId, [w(target)], "0x00", 10)).to.be.revertedWithCustomError(store, "ProgramFailed").withArgs(38, 0, () => true); // ComputationalBudgetExceeded
    await expect(store.connect(alice).invoke(keyFor(dev.address, 50), [], "0x", 0)).to.be.revertedWithCustomError(store, "UnknownProgram");
  });

  it("clock: o programa lê o sysvar montado do bloco", async () => {
    const clockId = keyFor(dev.address, 4);
    await store.connect(dev).deployProgram(clockId, elfOf("clock_sysvar_program"));
    const rc = await (await store.connect(alice).invoke(clockId, [], "0x", 0)).wait();
    const ev = rc.logs.map((l) => { try { return store.interface.parseLog(l); } catch { return null; } }).find((l) => l && l.name === "Invoked");
    // o programa devolve o unix_timestamp do Clock em big-endian como return data
    const ts = (await ethers.provider.getBlock(rc.blockNumber)).timestamp;
    expect(ev.args.returnData).to.equal(ethers.toBeHex(ts, 8));
    expect(ev.args.logs).to.include("Program return:");
  });

  after(() => console.log(`      gás: deploy do programa ${gas.deploy}, hello ${gas.hello}, escrita na conta ${gas.write}, burn ${gas.burn}`));
});
