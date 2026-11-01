const { murmur3_32 } = require("./murmur");
const NAMES = [
  "abort", "sol_panic_", "sol_log_", "sol_log_64_", "sol_log_compute_units_",
  "sol_keccak256", "sol_memcpy_", "sol_memmove_", "sol_memset_", "sol_memcmp_",
];
const SYSCALLS = Object.fromEntries(NAMES.map((n) => [n, murmur3_32(n)]));
const BY_HASH = Object.fromEntries(NAMES.map((n) => [murmur3_32(n), n]));
module.exports = { SYSCALLS, BY_HASH };
