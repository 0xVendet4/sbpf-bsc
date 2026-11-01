const fs = require("fs");
const path = require("path");
const { ethers } = require("hardhat");

const STATUS = ["Ok", "Invalid", "DivideByZero", "AccessViolation", "CuExceeded"];

function loadFixtures(name) {
  const p = path.join(__dirname, "..", "..", "fixtures", name + ".json");
  return JSON.parse(fs.readFileSync(p, "utf8")).fixtures;
}

async function deployVM() {
  const F = await ethers.getContractFactory("SbpfVM");
  const vm = await F.deploy();
  await vm.waitForDeployment();
  return vm;
}

/// Executa um fixture no contrato e devolve uma descrição da divergência (ou null).
async function checkFixture(vm, f) {
  const [status, r0, cu] = await vm.run(f.program, f.input, f.maxCu);
  const got = STATUS[Number(status)];
  const want = f.expect.status;
  if (got !== want) return `${f.name}: status ${got}, esperado ${want}`;
  if (want === "Ok") {
    if (r0 !== BigInt(f.expect.r0)) return `${f.name}: r0 0x${r0.toString(16)}, esperado ${f.expect.r0}`;
    if (Number(cu) !== f.expect.cu) return `${f.name}: cu ${cu}, esperado ${f.expect.cu}`;
  }
  return null;
}

async function checkAll(vm, fixtures, batch = 64) {
  const bad = [];
  for (let i = 0; i < fixtures.length; i += batch) {
    const res = await Promise.all(fixtures.slice(i, i + batch).map((f) => checkFixture(vm, f)));
    for (const r of res) if (r) bad.push(r);
  }
  return bad;
}

module.exports = { STATUS, loadFixtures, deployVM, checkFixture, checkAll };
