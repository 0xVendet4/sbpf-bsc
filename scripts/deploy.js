// Deploy completo: npx hardhat run scripts/deploy.js --network bscTestnet
// Depois: npx hardhat verify --network bscTestnet <endereço> <args...>  (precisa de hardhat-verify)
const hre = require("hardhat");
const { ethers } = hre;

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("deployer:", deployer.address);
  // Nonce controlado aqui: RPCs públicos com balanceador às vezes devolvem nonce atrasado
  // ("nonce too low") entre transações seguidas.
  let nonce = await ethers.provider.getTransactionCount(deployer.address, "pending");
  const tx = () => ({ nonce: nonce++ });

  const vm = await (await ethers.getContractFactory("SbpfVM")).deploy(tx());
  await vm.waitForDeployment();
  console.log("SbpfVM:", await vm.getAddress());

  const token = await (await ethers.getContractFactory("GolfToken")).deploy(tx());
  await token.waitForDeployment();
  console.log("GolfToken:", await token.getAddress());

  // Parâmetros iniciais (ajuste depois de medir demanda e tempo de bloco da BSC):
  // taxa de entrada 10 GOLF (50% queimada), 100 rodadas grátis, commit 8000 blocos (~1 h a 0,45 s/bloco), reveal 4000 blocos (~30 min; máx. 8000).
  const entryFee = ethers.parseEther(process.env.ENTRY_FEE || "10");
  const golf = await (await ethers.getContractFactory("SbpfGolf")).deploy(
    vm, token, entryFee, 5000, Number(process.env.FREE_ROUNDS || 100),
    Number(process.env.COMMIT_BLOCKS || 8000), Number(process.env.REVEAL_BLOCKS || 4000), tx(),
  );
  await golf.waitForDeployment();
  console.log("SbpfGolf:", await golf.getAddress());
  await (await token.setMinter(golf, tx())).wait();

  const board = await (await ethers.getContractFactory("BountyBoard")).deploy(vm, token, ethers.parseEther(process.env.BOUNTY_FEE || "5"), tx());
  await board.waitForDeployment();
  console.log("BountyBoard:", await board.getAddress());
  await (await golf.setBountyBoard(board, tx())).wait();

  const out = {
    network: hre.network.name, chainId: Number((await ethers.provider.getNetwork()).chainId),
    deployer: deployer.address, deployedAt: new Date().toISOString(),
    contracts: {
      SbpfVM: { address: await vm.getAddress(), args: [] },
      GolfToken: { address: await token.getAddress(), args: [] },
      SbpfGolf: { address: await golf.getAddress(), args: [await vm.getAddress(), await token.getAddress(), entryFee.toString(), 5000,
        Number(process.env.FREE_ROUNDS || 100), Number(process.env.COMMIT_BLOCKS || 8000), Number(process.env.REVEAL_BLOCKS || 4000)] },
      BountyBoard: { address: await board.getAddress(), args: [await vm.getAddress(), await token.getAddress(), ethers.parseEther(process.env.BOUNTY_FEE || "5").toString()] },
    },
  };
  require("fs").mkdirSync("deployments", { recursive: true });
  require("fs").writeFileSync(`deployments/${hre.network.name}.json`, JSON.stringify(out, null, 2) + "\n");

  const r = await golf.currentRound();
  console.log(`rodada 1: tarefa ${r.task} (${await golf.taskName(r.task)}), commit até o bloco ${r.commitEnd}, reveal até ${r.revealEnd}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
