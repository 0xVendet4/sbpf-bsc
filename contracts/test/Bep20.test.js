const { expect } = require("chai");
const { ethers } = require("hardhat");
const { deploySolanaRuntime } = require("./solanaHelpers");
const { keyFor, w, r, s, TOKEN_PROGRAM, MINT_LEN, TOKEN_ACCOUNT_LEN, rentExempt, token, tokenAmount, cacheImage } = require("../../scripts/solana-client");
const tokenElf = require("../../fixtures/solana/token.json").programs.spl_token;
const uni = (n) => require(n);

// SplBep20: a cara BEP-20 de um mint SPL. O saldo é a conta SPL, o transfer é o Transfer do SPL Token
// (binário oficial, rodando no SolanaVM), e um par Uniswap v2 (o código que a PancakeSwap copiou)
// negocia o token como qualquer BEP-20.

describe("SplBep20 — BEP-20 em cima de um mint do SPL Token", function () {
  let store, dev, alice, bob, carol, dave, mint, bep;
  const gas = {};

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
    // o mint SPL, criado como num cliente Solana: conta pelo system program + InitializeMint2
    const payer = keyFor(alice.address, 0);
    mint = keyFor(alice.address, 1);
    await store.connect(alice).deposit(payer, { value: rentExempt(MINT_LEN) });
    await store.connect(alice).createAccount(payer, mint, rentExempt(MINT_LEN), MINT_LEN, TOKEN_PROGRAM);
    await store.connect(alice).invoke(TOKEN_PROGRAM, [w(mint)], token.initializeMint2(6, payer), 0);
    bep = await (await ethers.getContractFactory("SplBep20")).deploy(await store.getAddress(), mint, "Teste SPL", "TSPL", { value: ethers.parseEther("0.001") });
    await store.setForwarder(await bep.getAddress(), mint);
  });

  it("nome, símbolo, decimais e supply lidos do mint SPL", async () => {
    expect(await bep.name()).to.equal("Teste SPL");
    expect(await bep.symbol()).to.equal("TSPL");
    expect(await bep.decimals()).to.equal(6n);
    expect(await bep.totalSupply()).to.equal(0n);
    await expect((await ethers.getContractFactory("SplBep20")).deploy(await store.getAddress(), keyFor(alice.address, 9), "x", "x")).to.be.reverted;
  });

  it("MintTo direto pelo SPL Token aparece no balanceOf e no totalSupply", async () => {
    await bep.connect(alice).open();
    const acc = await bep.accountOf(alice.address);
    const a = await store.account(acc);
    expect(a.owner).to.equal(TOKEN_PROGRAM);
    await store.connect(alice).invoke(TOKEN_PROGRAM, [w(mint), w(acc), s(keyFor(alice.address, 0))], token.mintTo(1_000_000_000_000n), 0);
    expect(await bep.balanceOf(alice.address)).to.equal(1_000_000_000_000n);
    expect(await bep.totalSupply()).to.equal(1_000_000_000_000n);
  });

  it("transfer roda o Transfer do SPL Token (e cria a conta SPL de quem recebe pela primeira vez)", async () => {
    let rc = await (await bep.connect(alice).transfer(bob.address, 250_000_000n)).wait();
    gas.firstTransfer = Number(rc.gasUsed);
    const ev = rc.logs.map((l) => { try { return store.interface.parseLog(l); } catch { return null; } }).filter((e) => e && e.name === "Invoked");
    expect(ev.at(-1).args.logs).to.include("Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 76 of 200000 compute units");
    await expect(rc).to.emit(bep, "Transfer").withArgs(alice.address, bob.address, 250_000_000n);
    rc = await (await bep.connect(alice).transfer(bob.address, 50_000_000n)).wait();
    gas.transfer = Number(rc.gasUsed);
    expect(await bep.balanceOf(alice.address)).to.equal(700_000_000_000n - 300_000_000n + 300_000_000_000n);
    expect(await bep.balanceOf(bob.address)).to.equal(300_000_000n);
    // a conta do Bob é uma conta SPL comum, com dono = chave do Bob
    const d = ethers.getBytes((await store.account(await bep.accountOf(bob.address))).data);
    expect(ethers.hexlify(d.slice(0, 32))).to.equal(mint);
    expect(ethers.hexlify(d.slice(32, 64))).to.equal(keyFor(bob.address, 0));
    expect(tokenAmount(d)).to.equal(300_000_000n);
    await expect(bep.connect(bob).transfer(carol.address, 300_000_001n)).to.be.revertedWithCustomError(bep, "InsufficientBalance");
    await expect(bep.connect(carol).transfer(bob.address, 1n)).to.be.revertedWithCustomError(bep, "InsufficientBalance");
    await expect(bep.connect(bob).transfer(bob.address, 1n)).to.emit(bep, "Transfer");
    await expect(bep.connect(bob).transfer(carol.address, 0n)).to.emit(bep, "Transfer");
  });

  it("approve + transferFrom", async () => {
    await bep.connect(bob).approve(carol.address, 100_000_000n);
    await (await bep.connect(carol).transferFrom(bob.address, dave.address, 60_000_000n)).wait();
    expect(await bep.allowance(bob.address, carol.address)).to.equal(40_000_000n);
    expect(await bep.balanceOf(dave.address)).to.equal(60_000_000n);
    await expect(bep.connect(carol).transferFrom(bob.address, dave.address, 40_000_001n)).to.be.revertedWithCustomError(bep, "InsufficientAllowance");
    await expect(bep.connect(dave).transferFrom(bob.address, dave.address, 1n)).to.be.revertedWithCustomError(bep, "InsufficientAllowance");
  });

  it("o mesmo token pelo lado Solana: Transfer direto pelo SolanaStore muda o balanceOf", async () => {
    const from = await bep.accountOf(dave.address);
    const to = await bep.accountOf(alice.address);
    await store.connect(dave).invoke(TOKEN_PROGRAM, [w(from), w(to), s(keyFor(dave.address, 0))], token.transfer(10_000_000n), 0);
    expect(await bep.balanceOf(dave.address)).to.equal(50_000_000n);
    // uma conta SPL criada fora (pelo system program + InitializeAccount3) pode ser ligada
    const own = keyFor(carol.address, 7);
    await store.connect(carol).deposit(keyFor(carol.address, 0), { value: rentExempt(TOKEN_ACCOUNT_LEN) });
    await store.connect(carol).createAccount(keyFor(carol.address, 0), own, rentExempt(TOKEN_ACCOUNT_LEN), TOKEN_ACCOUNT_LEN, TOKEN_PROGRAM);
    await store.connect(carol).invoke(TOKEN_PROGRAM, [w(own), r(mint)], token.initializeAccount3(keyFor(carol.address, 0)), 0);
    await expect(bep.connect(dave).link(own)).to.be.revertedWithCustomError(bep, "BadAccount");
    await bep.connect(carol).link(own);
    await bep.connect(dave).transfer(carol.address, 5_000_000n);
    expect(tokenAmount((await store.account(own)).data)).to.equal(5_000_000n);
  });

  it("o Store só deixa o encaminhador assinar Transfer de contas do mint dele", async () => {
    const data = token.transfer(1n);
    const metas = [w(await bep.accountOf(alice.address)), w(await bep.accountOf(bob.address)), s(keyFor(alice.address, 0))];
    await expect(store.connect(bob).invokeAs(alice.address, metas, data)).to.be.revertedWithCustomError(store, "NotForwarder");
    await expect(store.connect(alice).setForwarder(bob.address, mint)).to.be.revertedWithCustomError(store, "NotForwarder");
    await store.setForwarder(dave.address, keyFor(dave.address, 99)); // outro mint
    await expect(store.connect(dave).invokeAs(alice.address, metas, data)).to.be.revertedWithCustomError(store, "NotForwarder");
    await store.setForwarder(dave.address, mint);
    await expect(store.connect(dave).invokeAs(alice.address, metas, token.mintTo(1n))).to.be.revertedWithCustomError(store, "NotForwarder");
    await store.connect(dave).invokeAs(alice.address, metas, data); // com o mint certo e Transfer, passa
    await store.setForwarder(dave.address, ethers.ZeroHash);
    await expect(store.connect(dave).invokeAs(alice.address, metas, data)).to.be.revertedWithCustomError(store, "NotForwarder");
  });

  it("Uniswap v2 (o par da PancakeSwap): pool com BNB e swap nos dois sentidos", async () => {
    const deployJson = async (j, ...args) => {
      const f = new ethers.ContractFactory(j.abi, j.bytecode.startsWith("0x") ? j.bytecode : "0x" + j.bytecode, dev);
      const c = await f.deploy(...args);
      await c.waitForDeployment();
      return c;
    };
    const weth = await deployJson(uni("@uniswap/v2-periphery/build/WETH9.json"));
    const factory = await deployJson(uni("@uniswap/v2-core/build/UniswapV2Factory.json"), dev.address);
    const router = await deployJson(uni("@uniswap/v2-periphery/build/UniswapV2Router02.json"), await factory.getAddress(), await weth.getAddress());
    const deadline = 2n ** 40n;
    await bep.connect(alice).approve(await router.getAddress(), ethers.MaxUint256);
    let rc = await (await router.connect(alice).addLiquidityETH(await bep.getAddress(), 100_000_000_000n, 0, 0, alice.address, deadline, { value: ethers.parseEther("10") })).wait();
    gas.addLiquidity = Number(rc.gasUsed);
    const pair = await factory.getPair(await bep.getAddress(), await weth.getAddress());
    expect(await bep.balanceOf(pair)).to.equal(100_000_000_000n);
    // compra: BNB → token (o par transfere o token para o Bob, que já tem conta SPL)
    const before = await bep.balanceOf(bob.address);
    rc = await (await router.connect(bob).swapExactETHForTokens(0, [await weth.getAddress(), await bep.getAddress()], bob.address, deadline, { value: ethers.parseEther("0.1") })).wait();
    gas.buy = Number(rc.gasUsed);
    const bought = (await bep.balanceOf(bob.address)) - before;
    expect(bought > 980_000_000n && bought < 990_000_000n).to.equal(true); // ~0,98% do pool, menos 0,3%
    // venda: token → BNB
    await bep.connect(bob).approve(await router.getAddress(), ethers.MaxUint256);
    const bnb = await ethers.provider.getBalance(bob.address);
    rc = await (await router.connect(bob).swapExactTokensForETH(bought, 0, [await bep.getAddress(), await weth.getAddress()], bob.address, deadline)).wait();
    gas.sell = Number(rc.gasUsed);
    expect(await ethers.provider.getBalance(bob.address) > bnb - rc.gasUsed * rc.gasPrice).to.equal(true);
    expect(await bep.balanceOf(bob.address)).to.equal(before);
    // comprador novo: a conta SPL dele nasce no swap
    rc = await (await router.connect(carol).swapExactETHForTokens(0, [await weth.getAddress(), await bep.getAddress()], dave.address, deadline, { value: ethers.parseEther("0.01") })).wait();
    for (const k of ["addLiquidity", "buy", "sell"]) expect(gas[k] < 16_000_000).to.equal(true);
  });

  after(() => console.log(`      gás: 1º transfer para um endereço novo ${gas.firstTransfer}, transfer ${gas.transfer}, addLiquidityETH ${gas.addLiquidity}, compra ${gas.buy}, venda ${gas.sell}`));
});
