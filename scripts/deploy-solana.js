// Deploy do runtime Solana: SolanaVM, SolanaCpi, SolanaLog, SolanaRuntime, SolanaLoader e SolanaStore.
//   npx hardhat run scripts/deploy-solana.js --network bscTestnet
// Grava os endereços em deployments/<rede>-solana.json (a versão anterior vai para -solana-v<N>.json).
// REUSE=SolanaCpi,SolanaLog reaproveita contratos já publicados cujo código não mudou.
const hre = require("hardhat");
const { ethers } = hre;
const fs = require("fs");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("rede", hre.network.name, "deployer", deployer.address, ethers.formatEther(await ethers.provider.getBalance(deployer.address)), "BNB");
  const file = `deployments/${hre.network.name}-solana.json`;
  const prev = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : null;
  // REUSE=Nome (endereço do deploy anterior) ou Nome=0x... (endereço explícito)
  const reuse = new Map((process.env.REUSE || "").split(",").filter(Boolean).map((x) => x.split("=")));
  // o código tem de ser o atual, a menos dos metadados CBOR do solc (mudam com qualquer import)
  const strip = (hex) => {
    const b = ethers.getBytes(hex);
    const n = (b[b.length - 2] << 8) | b[b.length - 1];
    return ethers.hexlify(b.slice(0, b.length - n - 2));
  };
  let nonce = await ethers.provider.getTransactionCount(deployer.address, "pending");
  const out = { network: hre.network.name, chainId: Number((await ethers.provider.getNetwork()).chainId), deployer: deployer.address, contracts: {} };
  const deploy = async (name, args = []) => {
    if (reuse.has(name)) {
      const c = reuse.get(name) ? { address: reuse.get(name), args, source: `contracts/src/${name}.sol:${name}` } : prev.contracts[name];
      const code = await ethers.provider.getCode(c.address);
      const art = await hre.artifacts.readArtifact(name);
      if (code === "0x" || strip(code) !== strip(art.deployedBytecode)) throw new Error(`${name} em ${c.address} não tem o código atual`);
      console.log(name.padEnd(14), c.address, "reaproveitado");
      out.contracts[name] = c;
      return c.address;
    }
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
  const loader = await deploy("SolanaLoader");
  await deploy("SolanaStore", [rt, loader]);
  if (prev) {
    let v = 1;
    while (fs.existsSync(`deployments/${hre.network.name}-solana-v${v}.json`)) v++;
    fs.writeFileSync(`deployments/${hre.network.name}-solana-v${v}.json`, JSON.stringify(prev, null, 2) + "\n");
    console.log("versão anterior em", `deployments/${hre.network.name}-solana-v${v}.json`);
  }
  fs.writeFileSync(file, JSON.stringify(out, null, 2) + "\n");
  console.log("gravado", file);
}

main().catch((e) => { console.error(e); process.exit(1); });
