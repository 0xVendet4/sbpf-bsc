// Disputa real na testnet: A afirma um resultado falso (r0 + 1), B contesta, bisseção até uma
// instrução, prova on-chain, B leva as duas cauções.
//   npx hardhat run scripts/dispute-demo.js --network bscTestnet   (PRIVATE_KEY = A; B é criada e abastecida por A)
const hre = require("hardhat");
const { ethers } = hre;
const fs = require("fs");

const ZERO_STACK = "0x" + "00".repeat(4096);
const asStruct = (t) => ({ pc: t.pc, cu: t.cu, halted: t.halted, status: t.status, regs: [...t.regs], stackHash: t.stackHash });

async function main() {
  const [A] = await ethers.getSigners();
  const dep = JSON.parse(fs.readFileSync(`deployments/${hre.network.name}.json`, "utf8"));
  const vm = await ethers.getContractAt("SbpfVM", dep.contracts.SbpfVM_v2.address);
  const dispute = await ethers.getContractAt("SbpfDispute", dep.contracts.SbpfDispute.address);
  const BOND = await dispute.BOND();

  const B = ethers.Wallet.createRandom().connect(ethers.provider);
  console.log("A:", A.address, "B:", B.address);
  await (await A.sendTransaction({ to: B.address, value: ethers.parseEther("0.02") })).wait();

  const fx = JSON.parse(fs.readFileSync("fixtures/programs.json", "utf8")).fixtures.find((f) => f.name === "isqrt_8");
  // provador fora da cadeia: cadeia honesta de estados
  let s = asStruct(await vm.initialState()), stack = ZERO_STACK;
  const chain = [{ s, stack, hash: await vm.stateHash(s) }];
  while (!s.halted) {
    const [t, out] = await vm.trace(s, stack, fx.program, fx.input, fx.maxCu, 1);
    s = asStruct(t); stack = out;
    chain.push({ s, stack, hash: await vm.stateHash(s) });
  }
  const steps = chain.length - 1;
  console.log(`isqrt(u64::MAX): ${steps} instruções, r0 = 0x${chain[steps].s.regs[0].toString(16)}`);

  const fake = { ...chain[steps].s, regs: chain[steps].s.regs.map((v, i) => (i === 0 ? v + 1n : v)) };
  const fakeHash = await vm.stateHash(fake);
  const log = [];
  const tx = async (label, p) => { const r = await (await p).wait(); log.push({ label, hash: r.hash, gas: r.gasUsed.toString() }); console.log(label, r.hash, r.gasUsed.toString()); return r; };

  const rc = await tx("A afirma (falso)", dispute.connect(A).assertRun(fx.program, ethers.keccak256(fx.input), fx.maxCu, steps, fakeHash, { value: BOND }));
  const id = dispute.interface.parseLog(rc.logs.find((l) => l.address === dispute.target)).args.id;
  await tx("B contesta", dispute.connect(B).challenge(id, { value: BOND }));
  for (let round = 1; ; round++) {
    const c = await dispute.claim(id);
    if (c.phase === 3n) break;
    const mid = Number((c.lo + c.hi) / 2n);
    const midHash = mid === steps ? fakeHash : chain[mid].hash;
    await tx(`rodada ${round}: A posta o meio (${mid})`, dispute.connect(A).bisect(id, midHash));
    await tx(`rodada ${round}: B escolhe ${midHash === chain[mid].hash ? "direita" : "esquerda"}`, dispute.connect(B).choose(id, midHash !== chain[mid].hash));
  }
  const c = await dispute.claim(id);
  const k = Number(c.lo);
  console.log(`sobrou a instrução ${k} -> ${k + 1}`);
  const balB = await ethers.provider.getBalance(B.address);
  const pr = await tx("B prova o passo", dispute.connect(B).prove(id, chain[k].s, chain[k].stack, fx.program, fx.input));
  const ev = dispute.interface.parseLog(pr.logs.find((l) => l.address === dispute.target && l.topics.length === 2 && dispute.interface.parseLog(l)?.name === "Resolved"));
  console.log("Resolved:", ev.args.confirmed ? "confirmada" : "derrubada", "vencedor", ev.args.winner, "B ganhou", ethers.formatEther((await ethers.provider.getBalance(B.address)) - balB), "BNB líquido");
  fs.writeFileSync(`deployments/${hre.network.name}-dispute-demo.json`, JSON.stringify({ id: id.toString(), fixture: fx.name, steps, k, txs: log }, null, 2) + "\n");
}

main().catch((e) => { console.error(e); process.exit(1); });
