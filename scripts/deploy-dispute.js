// Deploy do SbpfDispute na rede escolhida, apontando para o SbpfVM de deployments/<rede>.json.
//   BOND=0.001 CHALLENGE_BLOCKS=8000 MOVE_BLOCKS=4000 npx hardhat run scripts/deploy-dispute.js --network bscTestnet
const hre = require("hardhat");
const { ethers } = hre;
const fs = require("fs");

async function main() {
  const [deployer] = await ethers.getSigners();
  const file = `deployments/${hre.network.name}.json`;
  const dep = JSON.parse(fs.readFileSync(file, "utf8"));
  let nonce = await ethers.provider.getTransactionCount(deployer.address, "pending");

  // o SbpfVM anterior não tem step(): sobe a versão nova e atualiza o endereço
  const vm = await (await ethers.getContractFactory("SbpfVM")).deploy({ nonce: nonce++ });
  await vm.waitForDeployment();
  console.log("SbpfVM (com step):", await vm.getAddress());

  const bond = ethers.parseEther(process.env.BOND || "0.001");
  const args = [await vm.getAddress(), bond.toString(), Number(process.env.CHALLENGE_BLOCKS || 8000), Number(process.env.MOVE_BLOCKS || 4000)];
  const d = await (await ethers.getContractFactory("SbpfDispute")).deploy(...args, { nonce: nonce++ });
  await d.waitForDeployment();
  console.log("SbpfDispute:", await d.getAddress(), "caução", ethers.formatEther(bond), "BNB; janelas", args[2], "/", args[3], "blocos");

  dep.contracts.SbpfVM_v2 = { address: await vm.getAddress(), args: [], source: "contracts/src/SbpfVM.sol:SbpfVM" };
  dep.contracts.SbpfDispute = { address: await d.getAddress(), args, source: "contracts/src/SbpfDispute.sol:SbpfDispute" };
  fs.writeFileSync(file, JSON.stringify(dep, null, 2) + "\n");
}

main().catch((e) => { console.error(e); process.exit(1); });
