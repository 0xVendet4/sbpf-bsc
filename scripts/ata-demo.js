// Associated Token Account na rede: publica o programa oficial (sBPF v0, ATokenGP...) no SolanaStore
// em pedaços, guarda a imagem pronta e cria a conta de token associada de uma carteira para o mint do
// token-demo. O ATA chama o SPL Token três vezes e o system program uma vez (CPI sBPF → sBPF).
//   npx hardhat run scripts/ata-demo.js --network bscTestnet   (depois do token-demo.js)
// Retomável: cada passo fica em deployments/<rede>-ata-demo.json.
const hre = require("hardhat");
const { ethers } = hre;
const fs = require("fs");
const { keyFor, w, s, TOKEN_PROGRAM, TOKEN_ACCOUNT_LEN, rentExempt, token, tokenAmount, ATA_PROGRAM, ataAddress, ata } = require("./solana-client");

const CHUNK = 24575;
const elf = ethers.getBytes(JSON.parse(fs.readFileSync("fixtures/solana/ata.json", "utf8")).programs.associated_token);

async function main() {
  const [me] = await ethers.getSigners();
  const dep = JSON.parse(fs.readFileSync(`deployments/${hre.network.name}-solana.json`, "utf8"));
  const tok = JSON.parse(fs.readFileSync(`deployments/${hre.network.name}-token-demo.json`, "utf8"));
  const store = await ethers.getContractAt("SolanaStore", dep.contracts.SolanaStore.address);
  if (tok.store !== dep.contracts.SolanaStore.address) throw new Error("rode o token-demo.js neste SolanaStore antes");
  const file = `deployments/${hre.network.name}-ata-demo.json`;
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
    const ev = rc.logs.map((l) => { try { return store.interface.parseLog(l); } catch { return null; } }).find((l) => l && l.name === "Invoked");
    if (ev) {
      demo.steps[label].cu = Number(ev.args.cu);
      demo.steps[label].logs = ev.args.logs.split("\n");
      for (const line of demo.steps[label].logs) console.log("    " + line);
    }
    save();
  };

  // 1. o programa: pedaços + finalizeProgram (SolanaLoader) + verifyProgram (verificador) + imagem pronta
  if (!(await store.account(ATA_PROGRAM)).executable) {
    for (let i = 0, off = 0; off < elf.length; i++, off += CHUNK) {
      await send(`writeProgram ${i}`, (o) => store.writeProgram(ATA_PROGRAM, elf.slice(off, off + CHUNK), o));
    }
    await send("finalizeProgram", (o) => store.finalizeProgram(ATA_PROGRAM, o));
    await send("verifyProgram", (o) => store.verifyProgram(ATA_PROGRAM, o));
  }
  if (!(await store.imageReady(ATA_PROGRAM))) {
    const img = ethers.getBytes(await store.program(ATA_PROGRAM));
    for (let i = 0, off = 0; off < img.length; i++, off += CHUNK) {
      await send(`writeImage ${i}`, (o) => store.writeImage(ATA_PROGRAM, i, img.slice(off, off + CHUNK), o));
    }
    await send("finalizeImage", (o) => store.finalizeImage(ATA_PROGRAM, o));
  }

  // 2. a conta associada de uma carteira nova para o mint do token-demo, paga pelo pagador do demo
  const { payer, mint, accA } = tok.keys;
  const wallet = keyFor(me.address, 105);
  const addr = ataAddress(wallet, mint);
  demo.keys = { payer, mint, wallet, ata: addr };
  await send("deposit (rent da conta de token)", (o) => store.deposit(payer, { value: rentExempt(TOKEN_ACCOUNT_LEN), ...o }));
  await send("ATA Create", (o) => store.invoke(ATA_PROGRAM, ata.metas(payer, wallet, mint), ata.create(), 0, o));
  await send("ATA CreateIdempotent (já existe)", (o) => store.invoke(ATA_PROGRAM, ata.metas(payer, wallet, mint), ata.createIdempotent(), 0, o));
  await send("Transfer 0.100000 A → conta associada", (o) => store.invoke(TOKEN_PROGRAM, [w(accA), w(addr), s(payer)], token.transfer(100_000), 0, o));

  const acc = await store.account(addr);
  demo.result = { owner: acc.owner, lamports: acc.lamports.toString(), amount: tokenAmount(acc.data).toString() };
  console.log("conta associada", addr, "dono", acc.owner, "saldo", demo.result.amount);
  save();
  console.log("gravado", file);
}

main().catch((e) => { console.error(e); process.exit(1); });
