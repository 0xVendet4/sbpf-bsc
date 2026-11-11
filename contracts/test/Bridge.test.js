const { expect } = require("chai");
const { ethers } = require("hardhat");
const { deploySolanaRuntime } = require("./solanaHelpers");
const { keyFor, w, s, TOKEN_PROGRAM, MINT_LEN, rentExempt, token, cacheImage } = require("../../scripts/solana-client");
const tokenElf = require("../../fixtures/solana/token.json").programs.spl_token;

// Ponte de queima e cunhagem: o SplBep20 atrás do MintBurnOFTAdapter oficial da LayerZero. O outro
// lado (o token na Solana) é representado por um OFT comum de 9 casas, e as duas redes são ligadas
// por um endpoint de teste que entrega a mensagem na mesma transação. O formato da mensagem OFT é o
// mesmo em todas as redes, então isto exercita o lado da BSC inteiro; o lado da Solana de verdade
// (programa OFT + devnet) fica para o teste de ponta a ponta.

const EID_BSC = 40102; // BSC testnet na LayerZero
const EID_SOL = 40168; // Solana devnet na LayerZero
/// Opções tipo 3 da LayerZero: gás do lzReceive no destino.
const lzReceiveGas = (gas) => "0x0003" + "01" + "0011" + "01" + BigInt(gas).toString(16).padStart(32, "0");
const b32 = (addr) => ethers.zeroPadValue(addr, 32);

describe("Ponte — SplBep20 atrás do MintBurnOFTAdapter da LayerZero", function () {
  let store, dev, alice, bob, carol, dave, mint, bep, adapter, remote, epBsc, epSol;
  const gas = {};

  const send = async (oft, from, dstEid, to, amount, receiveGas) => {
    const p = { dstEid, to: b32(to), amountLD: amount, minAmountLD: 0, extraOptions: lzReceiveGas(receiveGas), composeMsg: "0x", oftCmd: "0x" };
    const fee = await oft.quoteSend(p, false);
    return (await oft.connect(from).send(p, { nativeFee: fee.nativeFee, lzTokenFee: 0n }, from.address, { value: fee.nativeFee })).wait();
  };
  /// supply somado das duas redes, em unidades de 6 casas
  const total = async () => (await bep.totalSupply()) + (await remote.totalSupply()) / 1000n;

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
    // o mint SPL do lado da BSC (6 casas), com a Alice como autoridade de mint no começo
    const payer = keyFor(alice.address, 0);
    mint = keyFor(alice.address, 1);
    await store.connect(alice).deposit(payer, { value: rentExempt(MINT_LEN) });
    await store.connect(alice).createAccount(payer, mint, rentExempt(MINT_LEN), MINT_LEN, TOKEN_PROGRAM);
    await store.connect(alice).invoke(TOKEN_PROGRAM, [w(mint)], token.initializeMint2(6, payer), 0);
    bep = await (await ethers.getContractFactory("SplBep20")).deploy(await store.getAddress(), mint, "Token nas duas redes", "DUO", { value: ethers.parseEther("0.001") });
    await store.setForwarder(await bep.getAddress(), mint);

    // LayerZero: um endpoint por rede, o adaptador na "BSC" e o OFT do outro lado
    const Endpoint = await ethers.getContractFactory("LzEndpointMock");
    epBsc = await Endpoint.deploy(EID_BSC);
    epSol = await Endpoint.deploy(EID_SOL);
    await epBsc.setRemote(EID_SOL, await epSol.getAddress());
    await epSol.setRemote(EID_BSC, await epBsc.getAddress());
    adapter = await (await ethers.getContractFactory("SplOftAdapter")).deploy(await bep.getAddress(), await epBsc.getAddress(), dev.address);
    remote = await (await ethers.getContractFactory("RemoteOftMock")).deploy(await epSol.getAddress(), dev.address);
    await adapter.setPeer(EID_SOL, b32(await remote.getAddress()));
    await remote.setPeer(EID_BSC, b32(await adapter.getAddress()));
  });

  it("só quem assina a autoridade de mint do SPL escolhe a ponte", async () => {
    expect(await bep.mintAuthority()).to.equal(keyFor(alice.address, 0));
    await expect(bep.connect(bob).setBridge(bob.address)).to.be.revertedWithCustomError(bep, "NotMintAuthority");
    await expect(bep.connect(alice).setBridge(await adapter.getAddress())).to.emit(bep, "BridgeSet").withArgs(await adapter.getAddress());
    expect(await bep.bridge()).to.equal(await adapter.getAddress());
    expect(await adapter.token()).to.equal(await bep.getAddress());
    expect(await adapter.approvalRequired()).to.equal(false);
  });

  it("mint e burn só pela ponte", async () => {
    await expect(bep.connect(alice).mint(alice.address, 1n)).to.be.revertedWithCustomError(bep, "NotBridge");
    await expect(bep.connect(alice).burn(alice.address, 1n)).to.be.revertedWithCustomError(bep, "NotBridge");
  });

  it("a autoridade de mint passa para o SplBep20 e a ponte fica fixa", async () => {
    const facadeKey = await store.keyOf(await bep.getAddress());
    await store.connect(alice).invoke(TOKEN_PROGRAM, [w(mint), s(keyFor(alice.address, 0))], token.setAuthority(0, facadeKey), 0);
    expect(await bep.mintAuthority()).to.equal(facadeKey);
    // a Alice não cunha mais direto pelo SPL Token e não troca mais a ponte
    await bep.connect(alice).open();
    const acc = await bep.accountOf(alice.address);
    await expect(store.connect(alice).invoke(TOKEN_PROGRAM, [w(mint), w(acc), s(keyFor(alice.address, 0))], token.mintTo(1n), 0)).to.be.reverted;
    await expect(bep.connect(alice).setBridge(alice.address)).to.be.revertedWithCustomError(bep, "NotMintAuthority");
    expect(await bep.totalSupply()).to.equal(0n);
  });

  it("da outra rede para a BSC: queima lá, MintTo do SPL Token aqui", async () => {
    await remote.mintTo(carol.address, 1_000_000_000_000n); // 1.000 tokens (9 casas) nascem na outra rede
    expect(await total()).to.equal(1_000_000_000n);
    const rc = await send(remote, carol, EID_BSC, carol.address, 400_000_000_000n, 3_000_000);
    gas.receiveFirst = Number(rc.gasUsed);
    expect(await remote.balanceOf(carol.address)).to.equal(600_000_000_000n);
    expect(await bep.balanceOf(carol.address)).to.equal(400_000_000n); // 400 tokens, 6 casas
    expect(await bep.totalSupply()).to.equal(400_000_000n);
    expect(await total()).to.equal(1_000_000_000n);
    // o que chegou é SPL de verdade: a conta de token da Carol no SolanaStore
    const a = await store.account(await bep.accountOf(carol.address));
    expect(a.owner).to.equal(TOKEN_PROGRAM);
    const ev = rc.logs.map((l) => { try { return store.interface.parseLog(l); } catch { return null; } }).filter((e) => e && e.name === "Invoked");
    expect(ev.at(-1).args.logs).to.include("Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success");
    gas.receive = Number((await send(remote, carol, EID_BSC, carol.address, 100_000_000_000n, 3_000_000)).gasUsed);
    expect(await bep.balanceOf(carol.address)).to.equal(500_000_000n);
  });

  it("o token que veio pela ponte é um BEP-20 normal", async () => {
    await expect(bep.connect(carol).transfer(bob.address, 50_000_000n)).to.emit(bep, "Transfer").withArgs(carol.address, bob.address, 50_000_000n);
    expect(await bep.balanceOf(bob.address)).to.equal(50_000_000n);
    expect(await bep.balanceOf(carol.address)).to.equal(450_000_000n);
  });

  it("da BSC para a outra rede: Burn do SPL Token aqui, cunha lá (sem approve)", async () => {
    const rc = await send(adapter, carol, EID_SOL, dave.address, 150_000_000n, 200_000);
    gas.send = Number(rc.gasUsed);
    await expect(rc).to.emit(bep, "Transfer").withArgs(carol.address, ethers.ZeroAddress, 150_000_000n);
    expect(await bep.balanceOf(carol.address)).to.equal(300_000_000n);
    expect(await bep.balanceOf(await bep.getAddress())).to.equal(0n); // nada fica na conta de passagem
    expect(await bep.totalSupply()).to.equal(350_000_000n);
    expect(await remote.balanceOf(dave.address)).to.equal(150_000_000_000n);
    expect(await total()).to.equal(1_000_000_000n);
    // o 1º envio abriu a conta de passagem do contrato; daqui em diante é só Transfer + Burn
    gas.sendNext = Number((await send(adapter, carol, EID_SOL, dave.address, 50_000_000n, 200_000)).gasUsed);
    expect(await bep.balanceOf(carol.address)).to.equal(250_000_000n);
    expect(await bep.totalSupply()).to.equal(300_000_000n);
    expect(await total()).to.equal(1_000_000_000n);
  });

  it("ninguém envia mais do que tem, e o supply somado não muda", async () => {
    const p = { dstEid: EID_SOL, to: b32(bob.address), amountLD: 60_000_000n, minAmountLD: 0, extraOptions: lzReceiveGas(200_000), composeMsg: "0x", oftCmd: "0x" };
    const fee = await adapter.quoteSend(p, false);
    await expect(adapter.connect(bob).send(p, { nativeFee: fee.nativeFee, lzTokenFee: 0n }, bob.address, { value: fee.nativeFee })).to.be.revertedWithCustomError(bep, "InsufficientBalance");
    expect(await total()).to.equal(1_000_000_000n);
  });

  it("o gás cabe com folga numa transação da BSC", async () => {
    for (const k of ["receiveFirst", "receive", "send", "sendNext"]) expect(gas[k] < 16_000_000).to.equal(true);
  });

  after(() => console.log(`      gás: receber pela ponte (1ª vez do endereço) ${gas.receiveFirst}, receber ${gas.receive}, enviar pela ponte (1º envio do contrato) ${gas.send}, enviar ${gas.sendNext}`));
});
