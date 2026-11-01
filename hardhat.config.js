require("@nomicfoundation/hardhat-ethers");
require("@nomicfoundation/hardhat-chai-matchers");
require("@nomicfoundation/hardhat-verify");

const accounts = process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [];

module.exports = {
  // Versão fixada (ver README). Mudar exige rodar os fixtures de novo e revisar o gás.
  solidity: {
    version: "0.8.28",
    settings: { optimizer: { enabled: true, runs: 10_000 }, evmVersion: "cancun" },
  },
  paths: { sources: "./contracts/src", tests: "./contracts/test" },
  mocha: { timeout: 600_000 },
  networks: {
    hardhat: { blockGasLimit: 140_000_000 },
    bscTestnet: {
      url: process.env.BSC_TESTNET_RPC || "https://bsc-testnet-rpc.publicnode.com",
      chainId: 97,
      accounts,
    },
    bsc: { url: process.env.BSC_RPC || "https://bsc-dataseed.bnbchain.org", chainId: 56, accounts },
  },
  // Etherscan API V2: uma chave só (etherscan.io) vale para BscScan, chainid 97/56.
  etherscan: { apiKey: process.env.ETHERSCAN_API_KEY || "" },
  sourcify: { enabled: false },
};

// Sem acesso a binaries.soliditylang.org (ambiente restrito): USE_SOLCJS=1 usa o solc-js do npm,
// mesma versão 0.8.28.
const { subtask } = require("hardhat/config");
const { TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD } = require("hardhat/builtin-tasks/task-names");
subtask(TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD, async (args, hre, runSuper) => {
  if (process.env.USE_SOLCJS !== "1") return runSuper();
  return {
    compilerPath: require.resolve("solc/soljson.js"),
    isSolcJs: true,
    version: args.solcVersion,
    longVersion: require("solc").version(),
  };
});
