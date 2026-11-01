// SPL Token na rede: publica o programa oficial (sBPF v0, Tokenkeg...) no SolanaStore em pedaços,
// guarda a imagem pronta, cria um mint e duas contas de token pelo system program e manda InitializeMint2,
// InitializeAccount3, MintTo e Transfer, uma transação cada.
//   npx hardhat run scripts/token-demo.js --network bscTestnet
// Retomável: cada passo fica em deployments/<rede>-token-demo.json.
const hre = require("hardhat");
const { ethers } = hre;
const fs = require("fs");
const { keyFor, w, r, s, TOKEN_PROGRAM, MINT_LEN, TOKEN_ACCOUNT_LEN, rentExempt, token, tokenAmount, mintSupply } = require("./solana-client");

const CHUNK = 24575;
const elf = ethers.getBytes(JSON.parse(fs.readFileSync("fixtures/solana/token.json", "utf8")).programs.spl_token);

async function main() {
  const [me] = await ethers.getSigners();
  const dep = JSON.parse(fs.readFileSync(`deployments/${hre.network.name}-solana.json`, "utf8"));
  const store = await ethers.getContractAt("SolanaStore", dep.contracts.SolanaStore.address);
  const file = `deployments/${hre.network.name}-token-demo.json`;
  const demo = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : { store: dep.contracts.SolanaStore.address, steps: {} };
  if (demo.store !== dep.contracts.SolanaStore.address) throw new Error(`${file} é de outro SolanaStore`);
  const save = () => fs.writeFileSync(file, JSON.stringify(demo, null, 2) + "\n");
  const send = async (label, call) => {
    if (demo.steps[label]) return console.log(label.padEnd(30), "já feito", demo.steps[label].tx);
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
    console.log(label.padEnd(30), "gás", rc.gasUsed.toString().padStart(9), "tx", rc.hash);
    demo.steps[label] = { tx: rc.hash, gas: Number(rc.gasUsed) };
    const ev = rc.logs.map((l) => { try { return store.interface.parseLog(l); } catch { return null; } }).find((l) => l && l.name === "Invoked");
    if (ev) {
      demo.steps[label].cu = Number(ev.args.cu);
      demo.steps[label].logs = ev.args.logs.split("\n");
      for (const line of demo.steps[label].logs) console.log("    " + line);
    }
    save();
  };

  // 1. o programa: pedaços de 24.575 bytes + finalizeProgram (SolanaLoader) + verifyProgram (verificador on-chain)
  if (!(await store.account(TOKEN_PROGRAM)).executable) {
    for (let i = 0, off = 0; off < elf.length; i++, off += CHUNK) {
      await send(`writeProgram ${i}`, (o) => store.writeProgram(TOKEN_PROGRAM, elf.slice(off, off + CHUNK), o));
    }
    await send("finalizeProgram", (o) => store.finalizeProgram(TOKEN_PROGRAM, o));
    await send("verifyProgram", (o) => store.verifyProgram(TOKEN_PROGRAM, o));
  }
  // 1b. a imagem pronta (lida por eth_call, conferida on-chain): cada instrução deixa de remontá-la
  if (!(await store.imageReady(TOKEN_PROGRAM))) {
    const img = ethers.getBytes(await store.program(TOKEN_PROGRAM));
    for (let i = 0, off = 0; off < img.length; i++, off += CHUNK) {
      await send(`writeImage ${i}`, (o) => store.writeImage(TOKEN_PROGRAM, i, img.slice(off, off + CHUNK), o));
    }
    await send("finalizeImage", (o) => store.finalizeImage(TOKEN_PROGRAM, o));
  }

  // 2. contas: um pagador com lamports (lastreados em wei), o mint e duas contas de token
  const payer = keyFor(me.address, 100);
  const mint = keyFor(me.address, 101);
  const holderB = keyFor(me.address, 103);
  const accA = keyFor(me.address, 102);
  const accB = keyFor(me.address, 104);
  demo.keys = { payer, mint, accA, holderB, accB };
  const need = rentExempt(MINT_LEN) + 2n * rentExempt(TOKEN_ACCOUNT_LEN);
  await send("deposit (rent das 3 contas)", (o) => store.deposit(payer, { value: need, ...o }));
  await send("createAccount mint", (o) => store.createAccount(payer, mint, rentExempt(MINT_LEN), MINT_LEN, TOKEN_PROGRAM, o));
  await send("createAccount conta A", (o) => store.createAccount(payer, accA, rentExempt(TOKEN_ACCOUNT_LEN), TOKEN_ACCOUNT_LEN, TOKEN_PROGRAM, o));
  await send("createAccount conta B", (o) => store.createAccount(payer, accB, rentExempt(TOKEN_ACCOUNT_LEN), TOKEN_ACCOUNT_LEN, TOKEN_PROGRAM, o));

  // 3. instruções do SPL Token
  await send("InitializeMint2 (6 casas)", (o) => store.invoke(TOKEN_PROGRAM, [w(mint)], token.initializeMint2(6, payer), 0, o));
  await send("InitializeAccount3 A", (o) => store.invoke(TOKEN_PROGRAM, [w(accA), r(mint)], token.initializeAccount3(payer), 0, o));
  await send("InitializeAccount3 B", (o) => store.invoke(TOKEN_PROGRAM, [w(accB), r(mint)], token.initializeAccount3(holderB), 0, o));
  await send("MintTo 1.000000 → A", (o) => store.invoke(TOKEN_PROGRAM, [w(mint), w(accA), s(payer)], token.mintTo(1_000_000), 0, o));
  await send("Transfer 0.250000 A → B", (o) => store.invoke(TOKEN_PROGRAM, [w(accA), w(accB), s(payer)], token.transfer(250_000), 0, o));

  demo.balances = {
    supply: (mintSupply((await store.account(mint)).data)).toString(),
    A: (tokenAmount((await store.account(accA)).data)).toString(),
    B: (tokenAmount((await store.account(accB)).data)).toString(),
  };
  console.log("supply", demo.balances.supply, "A", demo.balances.A, "B", demo.balances.B);
  save();
  console.log("gravado", file);
}

main().catch((e) => { console.error(e); process.exit(1); });
