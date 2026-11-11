const { expect } = require("chai");
const { ethers } = require("hardhat");
const { deploySolanaRuntime } = require("./solanaHelpers");
const { keyFor, w, s, TOKEN_PROGRAM, MINT_LEN, rentExempt, token, cacheImage } = require("../../scripts/solana-client");
const tokenElf = require("../../fixtures/solana/token.json").programs.spl_token;

// Ponte de trava e libera, sem mint e sem burn: o SplBep20 atrás do OFTAdapter oficial da LayerZero.
// O supply inteiro é criado uma vez em cada rede e a autoridade de mint é revogada; na BSC ele nasce
// todo trancado no cofre. Atravessar tranca num cofre e libera do outro. O outro lado (o token na
// Solana) é representado por um token de supply fixo com 9 casas atrás do mesmo adaptador, e as duas
// redes são ligadas por um endpoint de teste que entrega a mensagem na mesma transação. O formato da
// mensagem OFT é o mesmo em todas as redes, então isto exercita o lado da BSC inteiro; o lado da
// Solana de verdade (programa OFT + devnet) fica para o teste de ponta a ponta.

const EID_BSC = 40102; // BSC testnet na LayerZero
const EID_SOL = 40168; // Solana devnet na LayerZero
const SUPPLY = 1_000_000_000_000n; // 1.000.000 de tokens com 6 casas (lado da BSC)
const SUPPLY_SOL = SUPPLY * 1000n; // o mesmo supply com 9 casas (lado da Solana)
/// Opções tipo 3 da LayerZero: gás do lzReceive no destino.
const lzReceiveGas = (gas) => "0x0003" + "01" + "0011" + "01" + BigInt(gas).toString(16).padStart(32, "0");
const b32 = (addr) => ethers.zeroPadValue(addr, 32);

describe("Ponte sem mint e sem burn — SplBep20 atrás do OFTAdapter da LayerZero", function () {
  let store, dev, alice, bob, carol, dave, mint, bep, vaultBsc, vaultSol, sol, epBsc, epSol;
  const gas = {};

  const param = (dstEid, to, amount, receiveGas) => ({ dstEid, to: b32(to), amountLD: amount, minAmountLD: 0, extraOptions: lzReceiveGas(receiveGas), composeMsg: "0x", oftCmd: "0x" });
  const send = async (oft, from, dstEid, to, amount, receiveGas) => {
    const p = param(dstEid, to, amount, receiveGas);
    const fee = await oft.quoteSend(p, false);
    return (await oft.connect(from).send(p, { nativeFee: fee.nativeFee, lzTokenFee: 0n }, from.address, { value: fee.nativeFee })).wait();
  };
  /// O que circula (fora dos cofres) somando as duas redes, em unidades de 6 casas.
  const circulating = async () =>
    (await bep.totalSupply()) - (await bep.balanceOf(await vaultBsc.getAddress())) + ((await sol.totalSupply()) - (await sol.balanceOf(await vaultSol.getAddress()))) / 1000n;
  const invariants = async () => {
    expect(await bep.totalSupply()).to.equal(SUPPLY); // nada cunhado nem queimado na BSC
    expect(await sol.totalSupply()).to.equal(SUPPLY_SOL); // nem do outro lado
    expect(await circulating()).to.equal(SUPPLY);
  };

  before(async () => {
    [dev, alice, bob, carol, dave] = await ethers.getSigners();
    const { rt } = await deploySolanaRuntime();
    const loader = await (await ethers.getContractFactory("SolanaLoader")).deploy();
    store = await (await ethers.getContractFactory("SolanaStore")).deploy(await rt.getAddress(), await loader.getAddress());
    const bytes = ethers.getBytes(tokenElf);
    for (let off = 0; off < bytes.length; off += 24575) await (await store.writeProgram(TOKEN_PROGRAM, bytes.slice(off, off + 24575))).wait();
    await (await store.finalizeProgram(TOKEN_PROGRAM)).wait();
    await (await store.verifyProgram(TOKEN_PROGRAM)).wait();
    await cacheImage(store, dev, TOKEN_PROGRAM);
    // o mint SPL do lado da BSC (6 casas), com a Alice como autoridade de mint só até criar o supply
    const payer = keyFor(alice.address, 0);
    mint = keyFor(alice.address, 1);
    await store.connect(alice).deposit(payer, { value: rentExempt(MINT_LEN) });
    await store.connect(alice).createAccount(payer, mint, rentExempt(MINT_LEN), MINT_LEN, TOKEN_PROGRAM);
    await store.connect(alice).invoke(TOKEN_PROGRAM, [w(mint)], token.initializeMint2(6, payer), 0);
    bep = await (await ethers.getContractFactory("SplBep20")).deploy(await store.getAddress(), mint, "Token nas duas redes", "DUO", { value: ethers.parseEther("0.001") });
    await store.setForwarder(await bep.getAddress(), mint);

    // o outro lado: supply fixo que já circula (tudo com a Carol), sem mint nem burn
    sol = await (await ethers.getContractFactory("FixedSupplyMock")).deploy(carol.address, SUPPLY_SOL);
    // LayerZero: um endpoint por rede e um cofre (o mesmo OFTAdapter) de cada lado
    const Endpoint = await ethers.getContractFactory("LzEndpointMock");
    epBsc = await Endpoint.deploy(EID_BSC);
    epSol = await Endpoint.deploy(EID_SOL);
    await epBsc.setRemote(EID_SOL, await epSol.getAddress());
    await epSol.setRemote(EID_BSC, await epBsc.getAddress());
    const Vault = await ethers.getContractFactory("SplOftAdapter");
    vaultBsc = await Vault.deploy(await bep.getAddress(), await epBsc.getAddress(), dev.address);
    vaultSol = await Vault.deploy(await sol.getAddress(), await epSol.getAddress(), dev.address);
    await vaultBsc.setPeer(EID_SOL, b32(await vaultSol.getAddress()));
    await vaultSol.setPeer(EID_BSC, b32(await vaultBsc.getAddress()));
  });

  it("o supply da BSC é criado uma vez, vai inteiro para o cofre, e a autoridade de mint é revogada", async () => {
    await bep.connect(alice).open();
    const acc = await bep.accountOf(alice.address);
    const authority = keyFor(alice.address, 0);
    await store.connect(alice).invoke(TOKEN_PROGRAM, [w(mint), w(acc), s(authority)], token.mintTo(SUPPLY), 0);
    await bep.connect(alice).transfer(await vaultBsc.getAddress(), SUPPLY);
    await store.connect(alice).invoke(TOKEN_PROGRAM, [w(mint), s(authority)], token.setAuthority(0, null), 0);

    expect(ethers.dataSlice((await store.account(mint)).data, 0, 4)).to.equal("0x00000000"); // COption::None
    await expect(store.connect(alice).invoke(TOKEN_PROGRAM, [w(mint), w(acc), s(authority)], token.mintTo(1n), 0)).to.be.reverted;
    expect(await bep.balanceOf(await vaultBsc.getAddress())).to.equal(SUPPLY);
    expect(await bep.balanceOf(alice.address)).to.equal(0n);
    // o contrato BEP-20 não tem como cunhar nem queimar (`mint()` só devolve a chave do mint SPL)
    const fns = bep.interface.fragments.filter((f) => f.type === "function").map((f) => f.format());
    expect(fns.filter((f) => /^(mint|burn)\(.+\)$/i.test(f) || /^(mintTo|burnFrom)\(/.test(f))).to.deep.equal([]);
    expect(await vaultBsc.token()).to.equal(await bep.getAddress());
    expect(await vaultBsc.approvalRequired()).to.equal(true);
    await invariants();
  });

  it("da outra rede para a BSC: tranca lá, libera do cofre daqui com o Transfer do SPL Token", async () => {
    await sol.connect(carol).approve(await vaultSol.getAddress(), ethers.MaxUint256);
    const rc = await send(vaultSol, carol, EID_BSC, carol.address, 400_000_000_000n, 3_000_000); // 400 tokens
    gas.receiveFirst = Number(rc.gasUsed);
    expect(await sol.balanceOf(await vaultSol.getAddress())).to.equal(400_000_000_000n); // trancado lá
    expect(await bep.balanceOf(carol.address)).to.equal(400_000_000n); // liberado aqui (6 casas)
    expect(await bep.balanceOf(await vaultBsc.getAddress())).to.equal(SUPPLY - 400_000_000n);
    // o que chegou é SPL de verdade: a conta de token da Carol no SolanaStore, pelo programa oficial
    expect((await store.account(await bep.accountOf(carol.address))).owner).to.equal(TOKEN_PROGRAM);
    const ev = rc.logs.map((l) => { try { return store.interface.parseLog(l); } catch { return null; } }).filter((e) => e && e.name === "Invoked");
    expect(ev.at(-1).args.logs).to.include("Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 76 of 200000 compute units");
    await invariants();
    gas.receive = Number((await send(vaultSol, carol, EID_BSC, carol.address, 100_000_000_000n, 3_000_000)).gasUsed);
    expect(await bep.balanceOf(carol.address)).to.equal(500_000_000n);
    await invariants();
  });

  it("o token que veio pela ponte é um BEP-20 normal", async () => {
    await expect(bep.connect(carol).transfer(bob.address, 50_000_000n)).to.emit(bep, "Transfer").withArgs(carol.address, bob.address, 50_000_000n);
    expect(await bep.balanceOf(bob.address)).to.equal(50_000_000n);
    expect(await bep.balanceOf(carol.address)).to.equal(450_000_000n);
    await invariants();
  });

  it("da BSC para a outra rede: tranca no cofre daqui (com approve), libera lá", async () => {
    const p = param(EID_SOL, dave.address, 150_000_000n, 200_000);
    const fee = await vaultBsc.quoteSend(p, false);
    await expect(vaultBsc.connect(carol).send(p, { nativeFee: fee.nativeFee, lzTokenFee: 0n }, carol.address, { value: fee.nativeFee })).to.be.revertedWithCustomError(bep, "InsufficientAllowance");
    await bep.connect(carol).approve(await vaultBsc.getAddress(), ethers.MaxUint256);
    const rc = await send(vaultBsc, carol, EID_SOL, dave.address, 150_000_000n, 200_000);
    gas.send = Number(rc.gasUsed);
    await expect(rc).to.emit(bep, "Transfer").withArgs(carol.address, await vaultBsc.getAddress(), 150_000_000n);
    expect(await bep.balanceOf(carol.address)).to.equal(300_000_000n);
    expect(await bep.balanceOf(await vaultBsc.getAddress())).to.equal(SUPPLY - 350_000_000n);
    expect(await sol.balanceOf(dave.address)).to.equal(150_000_000_000n);
    expect(await sol.balanceOf(await vaultSol.getAddress())).to.equal(350_000_000_000n);
    await invariants();
  });

  it("ninguém envia mais do que tem", async () => {
    await bep.connect(bob).approve(await vaultBsc.getAddress(), ethers.MaxUint256);
    const p = param(EID_SOL, bob.address, 60_000_000n, 200_000);
    const fee = await vaultBsc.quoteSend(p, false);
    await expect(vaultBsc.connect(bob).send(p, { nativeFee: fee.nativeFee, lzTokenFee: 0n }, bob.address, { value: fee.nativeFee })).to.be.revertedWithCustomError(bep, "InsufficientBalance");
    await invariants();
  });

  it("tudo pode atravessar para a BSC e voltar: os cofres nunca ficam sem saldo", async () => {
    const rest = await sol.balanceOf(carol.address);
    await send(vaultSol, carol, EID_BSC, carol.address, rest, 3_000_000);
    await sol.connect(dave).approve(await vaultSol.getAddress(), ethers.MaxUint256);
    await send(vaultSol, dave, EID_BSC, dave.address, await sol.balanceOf(dave.address), 3_000_000);
    expect(await bep.balanceOf(await vaultBsc.getAddress())).to.equal(0n); // tudo circulando na BSC
    expect(await sol.balanceOf(await vaultSol.getAddress())).to.equal(SUPPLY_SOL); // tudo trancado lá
    await invariants();
    await bep.connect(dave).approve(await vaultBsc.getAddress(), ethers.MaxUint256);
    await send(vaultBsc, dave, EID_SOL, dave.address, await bep.balanceOf(dave.address), 200_000);
    await invariants();
  });

  it("o gás cabe com folga numa transação da BSC", async () => {
    for (const k of ["receiveFirst", "receive", "send"]) expect(gas[k] < 16_000_000).to.equal(true);
  });

  after(() => console.log(`      gás: receber pela ponte (1ª vez do endereço) ${gas.receiveFirst}, receber ${gas.receive}, enviar pela ponte ${gas.send}`));
});
