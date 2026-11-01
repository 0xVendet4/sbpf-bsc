// Demonstração do runtime Solana na rede: publica três programas Solana reais no SolanaStore e
// manda instruções por transação (hello, CPI ao system program, cofre PDA).
//   npx hardhat run scripts/solana-demo.js --network bscTestnet
// Lê deployments/<rede>-solana.json e acrescenta a seção "demo" com as transações.
const hre = require("hardhat");
const { ethers } = hre;
const fs = require("fs");
const { SYSTEM, keyFor, w, r, ws, findPda, vaultTransferIx, findVaultIx } = require("./solana-client");

const programs = JSON.parse(fs.readFileSync("fixtures/solana/programs.json", "utf8")).programs;

async function main() {
  const [me] = await ethers.getSigners();
  const file = `deployments/${hre.network.name}-solana.json`;
  const dep = JSON.parse(fs.readFileSync(file, "utf8"));
  const store = await ethers.getContractAt("SolanaStore", dep.contracts.SolanaStore.address);
  const demo = (dep.demo = dep.demo || {});
  const save = () => fs.writeFileSync(file, JSON.stringify(dep, null, 2) + "\n");
  // cada passo fica gravado; rodar de novo continua de onde parou (RPCs públicos às vezes erram o nonce)
  const send = async (label, call) => {
    if (demo[label]) return console.log(label.padEnd(34), "já feito", demo[label].tx);
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
    demo[label] = { tx: rc.hash, gas: Number(rc.gasUsed) };
    const ev = rc.logs.map((l) => { try { return store.interface.parseLog(l); } catch { return null; } }).find((l) => l && l.name === "Invoked");
    if (ev) {
      demo[label].logs = ev.args.logs.split("\n");
      for (const line of demo[label].logs) console.log("    " + line);
    }
    save();
    return rc;
  };

  // 1. publica os programas (o ELF vai para código de contrato, verificado uma vez)
  const ids = { hello: keyFor(me.address, 1), transfer: keyFor(me.address, 2), vault: keyFor(me.address, 3) };
  const elfs = { hello: programs.hello_solana_program, transfer: programs.simple_transfer_program, vault: programs.pda_program };
  for (const k of Object.keys(ids)) {
    if ((await store.elfLength(ids[k])) === 0n) await send(`deploy ${k}`, (o) => store.deployProgram(ids[k], elfs[k], o));
    demo.programs = { ...(demo.programs || {}), [k]: ids[k] };
  }

  // 2. hello: o programa loga "Hello, Solana!"
  await send("invoke hello", (o) => store.invoke(ids.hello, [], "0x", 0, o));

  // 3. CPI: o simple_transfer_program (compilado pelo agave) chama o system program
  const payer = keyFor(me.address, 10);
  const friend = keyFor("0x000000000000000000000000000000000000dEaD", 1);
  await send("deposit 10000 lamports", (o) => store.deposit(payer, { value: 10000n, ...o }));
  await send("invoke transfer (CPI)", (o) => store.invoke(ids.transfer, [ws(payer), w(friend), r(SYSTEM)], ethers.toBeHex(2500, 8), 0, o));

  // 4. cofre PDA: só o programa assina pelo endereço derivado ["vault", bump]
  const [vault, bump] = findPda([ethers.toUtf8Bytes("vault")], ids.vault);
  demo.vault = { address: vault, bump };
  await send("invoke try_find_program_address", (o) => store.invoke(ids.vault, [], findVaultIx(ids.vault), 0, o));
  await send("deposit 5000 no cofre PDA", (o) => store.deposit(vault, { value: 5000n, ...o }));
  const ix = vaultTransferIx(vault, bump, friend, 1234);
  await send("invoke cofre → friend (CPI assinada)", (o) => store.invoke(ids.vault, ix.metas, ix.data, 0, o));

  for (const [name, key] of [["payer", payer], ["friend", friend], ["vault", vault]]) {
    const a = await store.account(key);
    console.log(name.padEnd(8), key, "lamports", a.lamports.toString());
    demo[`saldo ${name}`] = a.lamports.toString();
  }
  save();
  console.log("gravado", file);
}

main().catch((e) => { console.error(e); process.exit(1); });
