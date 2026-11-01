require("@nomicfoundation/hardhat-ethers");
require("@nomicfoundation/hardhat-chai-matchers");

const accounts = process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [];

module.exports = {
  solidity: {
    version: "0.8.28",
    settings: { optimizer: { enabled: true, runs: 200 }, viaIR: true, evmVersion: "cancun" },
  },
  networks: {
    hardhat: { blockGasLimit: 140_000_000, allowUnlimitedContractSize: false },
    bscTestnet: { url: process.env.BSC_TESTNET_RPC || "https://data-seed-prebsc-1-s1.bnbchain.org:8545", chainId: 97, accounts },
    bsc: { url: process.env.BSC_RPC || "https://bsc-dataseed.bnbchain.org", chainId: 56, accounts },
  },
};

// Ambiente sem acesso a binaries.soliditylang.org: usa o solc-js do npm.
const { subtask } = require("hardhat/config");
const { TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD } = require("hardhat/builtin-tasks/task-names");
subtask(TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD, async (args, hre, runSuper) => {
  if (process.env.USE_SOLCJS !== "1") return runSuper();
  const solcPath = require.resolve("solc/soljson.js");
  return { compilerPath: solcPath, isSolcJs: true, version: args.solcVersion, longVersion: require("solc").version() };
});
