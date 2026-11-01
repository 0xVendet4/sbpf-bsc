// Minerador off-chain: roda o MESMO bytecode sBPF do contrato na VM JS até achar um nonce.
const jsvm = require("./vm");
const { keccak256, AbiCoder } = require("ethers");

function buildInput(challenge, miner, nonce, target) {
  const seed = Buffer.from(keccak256(AbiCoder.defaultAbiCoder().encode(["bytes32", "address"], [challenge, miner])).slice(2), "hex");
  const b = Buffer.alloc(16);
  b.writeBigUInt64LE(BigInt(nonce), 0);
  b.writeBigUInt64LE(BigInt(target), 8);
  return Buffer.concat([seed, b]);
}

function mine(code, challenge, miner, target, { start = 0n, maxTries = 10_000_000, budget = 20000, onProgress } = {}) {
  for (let i = 0; i < maxTries; i++) {
    const nonce = start + BigInt(i);
    const r = jsvm.run(code, buildInput(challenge, miner, nonce, target), budget);
    if (r.r0 === 0n) return { nonce, tries: i + 1, steps: r.steps };
    if (onProgress && i % 5000 === 0 && i) onProgress(i);
  }
  return null;
}

module.exports = { buildInput, mine };
