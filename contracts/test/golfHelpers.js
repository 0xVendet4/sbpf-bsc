const { ethers, network } = require("hardhat");
const { loadFixtures } = require("./helpers");

const programs = Object.fromEntries(loadFixtures("programs").map((f) => [f.name.replace(/_\d+$/, ""), f.program]));

/// bytecode dos programas demo (programs/*.s montados pelo solana-sbpf)
function program(name) { return programs[name]; }

/// mesma lógica, 1 CU a mais por execução: `mov64 r9, r9` na frente (offsets relativos não mudam)
function slower(prog, nops = 1) { return "0x" + "bf99000000000000".repeat(nops) + prog.slice(2); }

/// resposta errada: devolve sempre 0
const WRONG = "0xb700000000000000" + "9500000000000000";

function insn(opc, dst, src, off, imm) {
  const b = Buffer.alloc(8);
  b[0] = opc; b[1] = (src << 4) | dst; b.writeInt16LE(off, 2); b.writeInt32LE(imm, 4);
  return b;
}

async function mine(n) { await network.provider.send("hardhat_mine", ["0x" + n.toString(16)]); }
async function mineTo(block) {
  const now = await ethers.provider.getBlockNumber();
  if (Number(block) > now) await mine(Number(block) - now);
}

const salt = (s) => ethers.id(s);
function hashOf(player, round, prog, s) {
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["address", "uint256", "bytes32", "bytes32"], [player, round, ethers.keccak256(prog), s]));
}

module.exports = { program, slower, WRONG, insn, mine, mineTo, salt, hashOf };
