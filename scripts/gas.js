// Mede gas por instrução sBPF: npx hardhat run scripts/gas.js
const { ethers } = require("hardhat");
const { assemble } = require("../js/assembler");
async function main() {
  const rt = await (await ethers.getContractFactory("SolanaRuntime")).deploy();
  const base = await rt.execute.estimateGas(assemble("exit"), "0x", 10);
  for (const n of [100, 1000, 5000]) {
    const code = assemble(`mov64 r1, ${n}\nl:\nsub64 r1, 1\njne r1, 0, l\nexit`);
    const g = await rt.execute.estimateGas(code, "0x", 1_000_000);
    console.log(`${2 * n + 2} instruções: ${g} gas  (~${((g - base) / BigInt(2 * n + 1))} gas/instrução)`);
  }
}
main().catch((e) => { console.error(e); process.exit(1); });
