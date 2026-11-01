// Joga uma rodada do CU Golf com um programa demo:
//   GOLF=0x... PROGRAM=programs/isqrt.s npx hardhat run scripts/play.js --network bscTestnet
// Fase decidida pelo bloco atual: na janela de commit, comita; na de reveal, revela (salt em .salt-<rodada>).
const fs = require("fs");
const { ethers } = require("hardhat");

async function main() {
  const [me] = await ethers.getSigners();
  const golf = await ethers.getContractAt("SbpfGolf", process.env.GOLF);
  const name = (process.env.PROGRAM || "programs/isqrt.s").replace(/^.*\//, "").replace(/\.s$/, "");
  const fx = JSON.parse(fs.readFileSync("fixtures/programs.json", "utf8")).fixtures.find((f) => f.name.startsWith(name + "_"));
  if (!fx) throw new Error(`programa ${name} não está em fixtures/programs.json (rode npm run fixtures)`);
  const program = fx.program;

  const round = await golf.round();
  const r = await golf.currentRound();
  const block = await ethers.provider.getBlockNumber();
  console.log(`rodada ${round}, tarefa ${await golf.taskName(r.task)}, bloco ${block}, commit até ${r.commitEnd}, reveal até ${r.revealEnd}`);
  const saltFile = `.salt-${round}`;

  if (block <= r.commitEnd) {
    const salt = ethers.hexlify(ethers.randomBytes(32));
    fs.writeFileSync(saltFile, salt);
    const fee = await golf.entryFee();
    if (fee > 0n) {
      const token = await ethers.getContractAt("GolfToken", await golf.token());
      await (await token.approve(golf, fee)).wait();
    }
    const tx = await golf.commit(await golf.commitHash(me.address, round, program, salt));
    console.log("commit:", tx.hash);
  } else if (block <= r.revealEnd) {
    const salt = fs.readFileSync(saltFile, "utf8").trim();
    const tx = await golf.reveal(program, salt);
    const rc = await tx.wait();
    console.log(`reveal: ${tx.hash} (gas ${rc.gasUsed})`);
  } else {
    const tx = await golf.finalize();
    console.log("finalize:", tx.hash);
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
