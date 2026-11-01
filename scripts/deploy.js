// Deploy do runtime e do token: npx hardhat run scripts/deploy.js --network bscTestnet
const fs = require("fs");
const { ethers } = require("hardhat");
const { assemble } = require("../js/assembler");

async function main() {
  const puzzle = assemble(fs.readFileSync("programs/puzzle.s", "utf8"));
  // alvo inicial: ~65 mil execuções do puzzle por mint (alguns segundos na VM JS)
  const target = BigInt(process.env.INITIAL_TARGET || ((1n << 64n) / 65536n).toString());

  const rt = await (await ethers.getContractFactory("SolanaRuntime")).deploy();
  await rt.waitForDeployment();
  console.log("SolanaRuntime:", await rt.getAddress());

  const tok = await (await ethers.getContractFactory("ProofOfExecutionToken")).deploy(puzzle, target);
  await tok.waitForDeployment();
  console.log("ProofOfExecutionToken:", await tok.getAddress());
  console.log("puzzleHash:", await tok.puzzleHash());
}
main().catch((e) => { console.error(e); process.exit(1); });
