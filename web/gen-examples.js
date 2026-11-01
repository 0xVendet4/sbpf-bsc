// Gera web/examples.js a partir de programs/*.s (exemplos que a página carrega no editor).
// node web/gen-examples.js
const fs = require("fs"), path = require("path");
const dir = path.join(__dirname, "..", "programs");
const ex = {};
for (const n of ["fib", "popcount", "isqrt", "max8", "gcd"]) ex[n] = fs.readFileSync(path.join(dir, n + ".s"), "utf8");
fs.writeFileSync(path.join(__dirname, "examples.js"),
  "// Gerado por web/gen-examples.js a partir de programs/*.s. Não edite à mão.\nwindow.CU_GOLF_EXAMPLES = " + JSON.stringify(ex, null, 1) + ";\n");
