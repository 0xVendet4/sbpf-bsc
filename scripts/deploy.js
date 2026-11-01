// Deploy completo: npx hardhat run scripts/deploy.js --network bscTestnet
// Depois: npx hardhat verify --network bscTestnet <endereço> <args...>  (precisa de hardhat-verify)
const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("deployer:", deployer.address);

  const vm = await (await ethers.getContractFactory("SbpfVM")).deploy();
  await vm.waitForDeployment();
  console.log("SbpfVM:", await vm.getAddress());

  const token = await (await ethers.getContractFactory("GolfToken")).deploy();
  await token.waitForDeployment();
  console.log("GolfToken:", await token.getAddress());

  // Parâmetros iniciais (ajuste depois de medir demanda e tempo de bloco da BSC):
  // taxa de entrada 10 GOLF (50% queimada), 100 rodadas grátis, commit 400 blocos, reveal 200 blocos.
  const entryFee = ethers.parseEther(process.env.ENTRY_FEE || "10");
  const golf = await (await ethers.getContractFactory("SbpfGolf")).deploy(
    vm, token, entryFee, 5000, Number(process.env.FREE_ROUNDS || 100),
    Number(process.env.COMMIT_BLOCKS || 400), Number(process.env.REVEAL_BLOCKS || 200),
  );
  await golf.waitForDeployment();
  console.log("SbpfGolf:", await golf.getAddress());
  await (await token.setMinter(golf)).wait();

  const board = await (await ethers.getContractFactory("BountyBoard")).deploy(vm, token, ethers.parseEther(process.env.BOUNTY_FEE || "5"));
  await board.waitForDeployment();
  console.log("BountyBoard:", await board.getAddress());
  await (await golf.setBountyBoard(board)).wait();

  const r = await golf.currentRound();
  console.log(`rodada 1: tarefa ${r.task} (${await golf.taskName(r.task)}), commit até o bloco ${r.commitEnd}, reveal até ${r.revealEnd}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
