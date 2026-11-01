// Minera POE: TOKEN=0x... npx hardhat run scripts/mine.js --network bscTestnet
const { ethers } = require("hardhat");
const { mine } = require("../js/miner");

async function main() {
  const [signer] = await ethers.getSigners();
  const tok = await ethers.getContractAt("ProofOfExecutionToken", process.env.TOKEN);
  const code = Buffer.from((await tok.puzzleCode()).slice(2), "hex");
  const rounds = Number(process.env.ROUNDS || 1);
  for (let i = 0; i < rounds; i++) {
    const challenge = await tok.challenge();
    const target = await tok.difficultyTarget();
    const t0 = Date.now();
    const found = mine(code, challenge, signer.address, target, {
      start: BigInt(Math.floor(Math.random() * 2 ** 48)),
      onProgress: (n) => process.stdout.write(`\r  ${n} execuções sBPF...`),
    });
    if (!found) throw new Error("nonce não encontrado");
    const secs = (Date.now() - t0) / 1000;
    console.log(`\nnonce ${found.nonce} após ${found.tries} execuções (${(found.tries / secs).toFixed(0)}/s)`);
    if ((await tok.challenge()) !== challenge) { console.log("challenge mudou (alguém minerou antes), recomeçando"); i--; continue; }
    const tx = await tok.mint(found.nonce);
    const rc = await tx.wait();
    console.log(`mint ok: ${tx.hash} (gas ${rc.gasUsed})`);
  }
  console.log("saldo:", ethers.formatEther(await tok.balanceOf(signer.address)), "POE");
}
main().catch((e) => { console.error(e); process.exit(1); });
