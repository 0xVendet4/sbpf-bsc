const { expect } = require("chai");
const { ethers } = require("hardhat");
const { loadJson, deploySolanaRuntime, base58 } = require("./solanaHelpers");

// SolanaStore: programas e contas Solana guardados na EVM, instruções processadas por transação.
// O fluxo é o de um cliente Solana: publicar o programa, criar a conta de dados pelo system
// program, mandar a instrução. As assinaturas vêm do msg.sender (20 últimos bytes da chave).

const fixtures = loadJson("solana/programs.json");
const elfOf = (program) => fixtures.find((f) => f.program === program).elf;
const INCINERATOR = "0x003390728d34116079bdc911bfff00dbd44d2ecdccf79ca6e10038e100000000"; // 1nc1nerator11111111111111111111111111111111
const le64 = (n) => ethers.toBeHex(n, 8).slice(2).match(/../g).reverse().join("");


// --- PDAs e CPI pelo programa de teste em assembly (reference-runtime: pda_program)
const HEAP = 0x300000000n;
const INPUT = 0x400000000n;
const SYSTEM = "0x" + "00".repeat(32);
const u64le = (v) => { const o = []; v = BigInt(v); for (let i = 0; i < 8; i++) { o.push(Number(v & 0xffn)); v >>= 8n; } return o; };
class Heap {
  constructor() { this.b = []; }
  put(bytes) { while (this.b.length % 8) this.b.push(0); const a = HEAP + BigInt(this.b.length); this.b.push(...bytes); return a; }
  seeds(list) { const arr = []; for (const s of list) { arr.push(...u64le(this.put(s)), ...u64le(s.length)); } return this.put(arr); }
}
/// [op][a1..a5][watch][heapLen][heap]: o programa copia o heap e chama a syscall `op` com r1..r5 = a1..a5
const pdaIx = (op, a, watch, h) => ethers.hexlify(Uint8Array.from([...[op, ...a, watch, h.b.length].flatMap(u64le), ...h.b]));

const ED_P = 2n ** 255n - 19n;
const ED_D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
function modpow(b, e, m) { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; }
/// `CompressedEdwardsY::decompress().is_some()`
function onCurve(h) {
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(h[i]);
  y = (y & ((1n << 255n) - 1n)) % ED_P;
  const yy = (y * y) % ED_P, u = (yy + ED_P - 1n) % ED_P, v = (ED_D * yy + 1n) % ED_P;
  if (u === 0n) return true;
  if (v === 0n) return false;
  return modpow((u * v) % ED_P, (ED_P - 1n) / 2n, ED_P) === 1n;
}
function findPda(seeds, programId) {
  for (let bump = 255; bump >= 0; bump--) {
    const h = ethers.getBytes(ethers.sha256(ethers.concat([...seeds, Uint8Array.of(bump), programId, ethers.toUtf8Bytes("ProgramDerivedAddress")])));
    if (!onCurve(h)) return [ethers.hexlify(h), bump];
  }
  throw new Error("sem PDA");
}

/// Chave assinada por `addr` com um prefixo de 12 bytes (cada endereço controla 2^96 chaves).
function keyFor(addr, prefix = 0) {
  return ethers.zeroPadValue(ethers.concat([ethers.toBeHex(prefix, 12), addr]), 32);
}

const w = (key) => ({ key, isSigner: false, isWritable: true });
const r = (key) => ({ key, isSigner: false, isWritable: false });
const ws = (key) => ({ key, isSigner: true, isWritable: true });

async function deployStore() {
  const { vm, rt } = await deploySolanaRuntime();
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


  it("CPI: programa Solana compilado chama o system program dentro da transação", async () => {
    // simple_transfer_program (agave): transfere `amount` (u64 big-endian) do pagador via invoke()
    const simpleId = keyFor(dev.address, 3);
    const payer = keyFor(alice.address, 8);
    const to = keyFor(bob.address, 8);
    await store.connect(alice).deposit(payer, { value: 5000n });
    const tx = await store.connect(alice).invoke(simpleId, [ws(payer), w(to), r(SYSTEM)], ethers.toBeHex(1000, 8), 0);
    const rc = await tx.wait();
    gas.cpi = Number(rc.gasUsed);
    const ev = rc.logs.map((l) => { try { return store.interface.parseLog(l); } catch { return null; } }).find((l) => l && l.name === "Invoked");
    const lines = ev.args.logs.split("\n");
    expect(lines).to.include("Program 11111111111111111111111111111111 invoke [2]");
    expect(lines).to.include("Program 11111111111111111111111111111111 success");
    expect(ev.args.cu > 2000n).to.equal(true); // ~2274 no agave; varia com os bytes das chaves (comparações)
    expect((await store.account(payer)).lamports).to.equal(4000n);
    expect((await store.account(to)).lamports).to.equal(1000n);
    // sem a assinatura do pagador o agave recusa a CPI (PrivilegeEscalation = 38 + 1)
    await expect(store.connect(bob).invoke(simpleId, [w(payer), w(to), r(SYSTEM)], ethers.toBeHex(1000, 8), 0))
      .to.be.revertedWithCustomError(store, "ProgramFailed").withArgs(39, 0, (logs) => logs.includes("signer privilege escalated"));
  });

  it("PDA: try_find_program_address on-chain e CPI assinada pelo PDA (cofre do programa)", async () => {
    const pdaId = keyFor(dev.address, 20);
    await store.connect(dev).deployProgram(pdaId, elfOf("pda_program"));
    const [vault, bump] = findPda([ethers.toUtf8Bytes("vault")], pdaId);

    // op 1: sol_try_find_program_address(["vault"], programa) → loga r0, bump e o endereço
    let h = new Heap();
    const seeds = h.seeds([ethers.toUtf8Bytes("vault")]);
    const pid = h.put(ethers.getBytes(pdaId));
    const out = h.put(new Array(32).fill(0));
    const bumpOut = h.put(new Array(8).fill(0));
    const sim = await store.simulate(pdaId, [], pdaIx(1, [seeds, 1, pid, out, bumpOut], 0, h), 0, alice.address);
    expect(sim.logs.split("\n").slice(1, 3)).to.deep.equal([`Program log: 0x0, 0x${bump.toString(16)}, 0x0, 0x0, 0x0`, `Program log: ${base58(ethers.getBytes(vault))}`]);

    // o cofre (PDA, dono = system program) recebe lamports; só o programa consegue gastá-los,
    // assinando a CPI com as seeds ["vault", bump] (sol_invoke_signed_c)
    await store.connect(alice).deposit(vault, { value: 5000n });
    const to = keyFor(bob.address, 9);
    const m0 = INPUT + 8n; // marcador do 1º registro de conta no input (cofre, sem dados)
    const m1 = m0 + 88n + 10240n + 8n;
    h = new Heap();
    const sysId = h.put(new Array(32).fill(0));
    const k0 = h.put(ethers.getBytes(vault));
    const k1 = h.put(ethers.getBytes(to));
    const metas = h.put([...u64le(k0), 1, 1, 0, 0, 0, 0, 0, 0, ...u64le(k1), 1, 0, 0, 0, 0, 0, 0, 0]);
    const data = h.put([2, 0, 0, 0, ...u64le(1000)]); // SystemInstruction::Transfer { lamports: 1000 }
    const ix = h.put([sysId, metas, 2, data, 12].flatMap(u64le));
    const info = (m, signer, writable) => [...[m + 8n, m + 72n, 0, m + 88n, m + 40n, 0].flatMap(u64le), signer, writable, 0, 0, 0, 0, 0, 0];
    const infos = h.put([...info(m0, 0, 1), ...info(m1, 0, 1)]);
    const signer = h.seeds([ethers.toUtf8Bytes("vault"), Uint8Array.of(bump)]);
    const signers = h.put([...u64le(signer), ...u64le(2)]);
    const metasTop = [w(vault), w(to), r(SYSTEM)];
    const tx = await store.connect(bob).invoke(pdaId, metasTop, pdaIx(2, [ix, infos, 2, signers, 1], m0 + 72n, h), 0);
    gas.pdaCpi = Number((await tx.wait()).gasUsed);
    expect((await store.account(vault)).lamports).to.equal(4000n);
    expect((await store.account(to)).lamports).to.equal(1000n);
    // seeds erradas: o PDA não assina
    const h2 = new Heap();
    h2.b = [...h.b];
    const bad = h2.seeds([ethers.toUtf8Bytes("vaulx"), Uint8Array.of(bump)]);
    const badSigners = h2.put([...u64le(bad), ...u64le(2)]);
    await expect(store.connect(bob).invoke(pdaId, metasTop, pdaIx(2, [ix, infos, 2, badSigners, 1], 0, h2), 0)).to.be.revertedWithCustomError(store, "ProgramFailed");
  });

  after(() => console.log(`      gás: deploy do programa ${gas.deploy}, hello ${gas.hello}, escrita na conta ${gas.write}, burn ${gas.burn}, CPI ${gas.cpi}, CPI assinada por PDA ${gas.pdaCpi}`));
});
