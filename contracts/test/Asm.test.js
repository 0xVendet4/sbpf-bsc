const { expect } = require("chai");
const fs = require("fs");
const path = require("path");
const { sbpfAssemble } = require("../../web/sbpf-asm.js");

// O assembler em JS (usado pela página web) contra o assembler oficial do solana-sbpf.
describe("Assembler JS contra o solana-sbpf", function () {
  const { cases } = JSON.parse(fs.readFileSync(path.join(__dirname, "../../fixtures/asm.json"), "utf8"));

  it(`fixtures/asm.json: mesmos bytes e mesmos erros`, () => {
    const bad = [];
    let ok = 0, errs = 0;
    for (const c of cases) {
      let got, gotErr;
      try { got = "0x" + Buffer.from(sbpfAssemble(c.src)).toString("hex"); } catch (e) { gotErr = e.message; }
      if (c.program !== undefined) {
        if (got !== c.program) bad.push({ src: c.src.slice(0, 200), want: c.program.slice(0, 120), got: got?.slice(0, 120), gotErr });
        else ok++;
      } else if (gotErr === undefined) bad.push({ src: c.src.slice(0, 200), wantErr: c.error, got: got?.slice(0, 120) });
      else errs++;
    }
    console.log(`      ${ok} montados iguais, ${errs} erros iguais, ${bad.length} diferentes (de ${cases.length})`);
    if (bad.length) console.log(JSON.stringify(bad.slice(0, 8), null, 1));
    expect(bad.length).to.equal(0);
  });

  it("programs/*.s montam igual aos fixtures", () => {
    const fx = JSON.parse(fs.readFileSync(path.join(__dirname, "../../fixtures/programs.json"), "utf8")).fixtures;
    for (const name of ["fib", "popcount", "isqrt", "max8", "gcd", "hello"]) {
      const src = fs.readFileSync(path.join(__dirname, `../../programs/${name}.s`), "utf8");
      const want = fx.find((f) => f.name.startsWith(name + "_")).program;
      expect("0x" + Buffer.from(sbpfAssemble(src)).toString("hex")).to.equal(want);
    }
  });
});
