// Verifica no BscScan (Etherscan API V2) os contratos de deployments/<rede>.json.
// ETHERSCAN_API_KEY=... npx hardhat run scripts/verify.js --network bscTestnet
// Obs.: o plano grátis da Etherscan não cobre a BSC; sem plano pago, use o formulário web
// (instruções no README, arquivo deployments/verify/standard-input.json).
const hre = require("hardhat");

async function main() {
  const dep = require(`../deployments/${hre.network.name}.json`);
  for (const [name, c] of Object.entries(dep.contracts)) {
    console.log(`\n== ${name} ${c.address}`);
    try {
      await hre.run("verify:verify", { address: c.address, constructorArguments: c.args, contract: c.source });
    } catch (e) {
      console.log(`falhou: ${e.message.split("\n")[0]}`);
    }
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
