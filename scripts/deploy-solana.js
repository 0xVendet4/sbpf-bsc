// Deploy do runtime Solana (parte 2): SolanaVM, SolanaCpi, SolanaLog, SolanaRuntime e SolanaStore.
//   npx hardhat run scripts/deploy-solana.js --network bscTestnet
// Grava os endereços em deployments/<rede>-solana.json.
const hre = require("hardhat");
const { ethers } = hre;
const fs = require("fs");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("rede", hre.network.name, "deployer", deployer.address, ethers.formatEther(await ethers.provider.getBalance(deployer.address)), "BNB");
  let nonce = await ethers.provider.getTransactionCount(deployer.address, "pending");
  const out = { network: hre.network.name, chainId: Number((await ethers.provider.getNetwork()).chainId), deployer: deployer.address, contracts: {} };
  const deploy = async (name, args = []) => {
    const c = await (await ethers.getContractFactory(name)).deploy(...args, { nonce: nonce++ });
    const rc = await c.deploymentTransaction().wait();
    const address = await c.getAddress();
    console.log(name.padEnd(14), address, "gás", rc.gasUsed.toString(), "tx", rc.hash);
    out.contracts[name] = { address, args, tx: rc.hash, source: `contracts/src/${name}.sol:${name}` };
    return address;
  };
  const vm = await deploy("SolanaVM");
  const cpi = await deploy("SolanaCpi");
  const log = await deploy("SolanaLog");
  const rt = await deploy("SolanaRuntime", [vm, cpi, log]);
  await deploy("SolanaStore", [rt]);
  const file = `deployments/${hre.network.name}-solana.json`;
  fs.writeFileSync(file, JSON.stringify(out, null, 2) + "\n");
  console.log("gravado", file);
}

main().catch((e) => { console.error(e); process.exit(1); });
