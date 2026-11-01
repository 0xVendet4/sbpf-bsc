// Monta um .s em bytecode: node scripts/asm.js programs/hello.s
const fs = require("fs");
const { assemble } = require("../js/assembler");
console.log("0x" + assemble(fs.readFileSync(process.argv[2], "utf8")).toString("hex"));
