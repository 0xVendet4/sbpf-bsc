// "Lance seu SPL na BSC": cria um mint no SPL Token (que roda no SolanaStore), publica a cara BEP-20
// dele (SplBep20), cunha pelo SPL, abre um pool na PancakeSwap v2, faz uma compra e uma venda, e
// depois queima e cunha pelo SPL Token para mostrar o totalSupply/balanceOf do BEP-20 mudando junto.
//   npx hardhat run scripts/bep20-demo.js --network bscTestnet   (depois do token-demo.js)
// Retomável: cada passo fica em deployments/<rede>-bep20-demo.json.
const hre = require("hardhat");
const { ethers } = hre;
const fs = require("fs");
const { keyFor, w, s, TOKEN_PROGRAM, MINT_LEN, rentExempt, token } = require("./solana-client");

// PancakeSwap v2 na BSC testnet (router → factory 0x6725F303…, WBNB 0xae13d989…)
const ROUTER = { bscTestnet: "0xD99D1c33F9fC3444f8101754aBC46c52416550D1", bsc: "0x10ED43C718714eb63d5aA57B78B54704E256024E" };
const ROUTER_ABI = [
  "function factory() view returns (address)",
  "function WETH() view returns (address)",
  "function addLiquidityETH(address token, uint amountTokenDesired, uint amountTokenMin, uint amountETHMin, address to, uint deadline) payable returns (uint, uint, uint)",
  "function swapExactETHForTokens(uint amountOutMin, address[] path, address to, uint deadline) payable returns (uint[])",
  "function swapExactTokensForETH(uint amountIn, uint amountOutMin, address[] path, address to, uint deadline) returns (uint[])",
];

async function main() {
  const [me] = await ethers.getSigners();
  const dep = JSON.parse(fs.readFileSync(`deployments/${hre.network.name}-solana.json`, "utf8"));
  const store = await ethers.getContractAt("SolanaStore", dep.contracts.SolanaStore.address);
  if (!(await store.imageReady(TOKEN_PROGRAM))) throw new Error("rode o token-demo.js neste SolanaStore antes");
  const router = new ethers.Contract(ROUTER[hre.network.name], ROUTER_ABI, me);
  const file = `deployments/${hre.network.name}-bep20-demo.json`;
  const demo = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : { store: dep.contracts.SolanaStore.address, steps: {} };
  if (demo.store !== dep.contracts.SolanaStore.address) throw new Error(`${file} é de outro SolanaStore`);
  const save = () => fs.writeFileSync(file, JSON.stringify(demo, null, 2) + "\n");
  const send = async (label, call) => {
    if (demo.steps[label]) return console.log(label.padEnd(34), "já feito", demo.steps[label].tx);
    let tx;
    for (let i = 0; ; i++) {
      try {
        tx = await call({ nonce: await ethers.provider.getTransactionCount(me.address, "pending") });
        break;
      } catch (e) {
        if (i >= 4 || !/nonce/i.test(String(e.message))) throw e;
        await new Promise((ok) => setTimeout(ok, 3000));
      }
    }
    const rc = await tx.wait();
    console.log(label.padEnd(34), "gás", rc.gasUsed.toString().padStart(9), "tx", rc.hash);
    demo.steps[label] = { tx: rc.hash, gas: Number(rc.gasUsed) };
    save();
    return rc;
  };

  // 1. o mint SPL (6 casas, autoridade = chave principal da carteira)
  const payer = keyFor(me.address, 0);
  const mint = keyFor(me.address, 200);
  demo.keys = { payer, mint };
  await send("deposit (rent do mint)", (o) => store.deposit(payer, { value: rentExempt(MINT_LEN), ...o }));
  await send("createAccount mint", (o) => store.createAccount(payer, mint, rentExempt(MINT_LEN), MINT_LEN, TOKEN_PROGRAM, o));
  await send("InitializeMint2 (6 casas)", (o) => store.invoke(TOKEN_PROGRAM, [w(mint)], token.initializeMint2(6, payer), 0, o));

  // 2. a cara BEP-20 (com BNB para o rent das contas SPL novas) e a autorização no Store
  if (!demo.bep20) {
    const f = await ethers.getContractFactory("SplBep20");
    const c = await f.deploy(await store.getAddress(), mint, "SPL na BSC", "SPLB", { value: ethers.parseEther("0.0001"), nonce: await ethers.provider.getTransactionCount(me.address, "pending") });
    const rc = await c.deploymentTransaction().wait();
    demo.bep20 = await c.getAddress();
    demo.steps["deploy SplBep20"] = { tx: rc.hash, gas: Number(rc.gasUsed) };
    console.log("deploy SplBep20".padEnd(34), "gás", rc.gasUsed.toString().padStart(9), "tx", rc.hash, demo.bep20);
    save();
  }
  const bep = await ethers.getContractAt("SplBep20", demo.bep20);
  await send("setForwarder", (o) => store.setForwarder(demo.bep20, mint, o));

  // 3. cunhar 1.000.000 tokens pelo SPL Token na conta SPL da carteira
  await send("open (conta SPL da carteira)", (o) => bep.open(o));
  const acc = await bep.accountOf(me.address);
  await send("MintTo 1.000.000 (SPL Token)", (o) => store.invoke(TOKEN_PROGRAM, [w(mint), w(acc), s(payer)], token.mintTo(1_000_000_000_000n), 0, o));

  // 4. BEP-20 puro: transferência para um endereço novo (a conta SPL dele nasce aqui)
  const other = ethers.getAddress("0x" + ethers.keccak256(ethers.toUtf8Bytes("spl-na-bsc demo")).slice(-40));
  demo.other = other;
  await send("transfer 1.000 para endereço novo", (o) => bep.transfer(other, 1_000_000_000n, o));

  // 5. PancakeSwap v2: pool 100.000 tokens + 0,01 tBNB, compra com 0,001 tBNB e venda de 500 tokens
  const deadline = Math.floor(Date.now() / 1000) + 3600;
  const wbnb = await router.WETH();
  await send("approve router", (o) => bep.approve(ROUTER[hre.network.name], ethers.MaxUint256, o));
  await send("addLiquidityETH", (o) => router.addLiquidityETH(demo.bep20, 100_000_000_000n, 0, 0, me.address, deadline, { value: ethers.parseEther("0.01"), ...o }));
  const factory = new ethers.Contract(await router.factory(), ["function getPair(address, address) view returns (address)"], me);
  demo.pair = await factory.getPair(demo.bep20, wbnb);
  await send("compra (0,001 tBNB → token)", (o) => router.swapExactETHForTokens(0, [wbnb, demo.bep20], me.address, deadline, { value: ethers.parseEther("0.001"), ...o }));
  await send("venda (500 tokens → tBNB)", (o) => router.swapExactTokensForETH(500_000_000n, 0, [demo.bep20, wbnb], me.address, deadline, o));

  demo.balances = {
    totalSupply: (await bep.totalSupply()).toString(),
    me: (await bep.balanceOf(me.address)).toString(),
    other: (await bep.balanceOf(other)).toString(),
    pair: (await bep.balanceOf(demo.pair)).toString(),
  };
  console.log("BEP-20", demo.bep20, "par", demo.pair, demo.balances);
  save();

  // 6. burn e mint pelo SPL Token (o BEP-20 não tem mint/burn próprios: ele só reflete o mint SPL)
  const snap = async () => ({ totalSupply: (await bep.totalSupply()).toString(), me: (await bep.balanceOf(me.address)).toString() });
  demo.supplyChanges = demo.supplyChanges || {};
  if (!demo.steps["Burn 10.000 (SPL Token)"]) demo.supplyChanges.antes = await snap();
  await send("Burn 10.000 (SPL Token)", (o) => store.invoke(TOKEN_PROGRAM, [w(acc), w(mint), s(payer)], token.burn(10_000_000_000n), 0, o));
  if (!demo.supplyChanges.depoisBurn) demo.supplyChanges.depoisBurn = await snap();
  await send("MintTo 5.000 (SPL Token)", (o) => store.invoke(TOKEN_PROGRAM, [w(mint), w(acc), s(payer)], token.mintTo(5_000_000_000n), 0, o));
  if (!demo.supplyChanges.depoisMint) demo.supplyChanges.depoisMint = await snap();
  console.log("BEP-20 lido do SPL", demo.supplyChanges);
  save();
  console.log("gravado", file);
}

main().catch((e) => { console.error(e); process.exit(1); });
