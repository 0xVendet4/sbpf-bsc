// murmur3_32 (seed 0) — usado pelo Solana para identificar syscalls pelo nome
function murmur3_32(str, seed = 0) {
  const data = Buffer.from(str, "utf8");
  let h = seed >>> 0;
  const c1 = 0xcc9e2d51, c2 = 0x1b873593;
  const nblocks = data.length >>> 2;
  for (let i = 0; i < nblocks; i++) {
    let k = data.readUInt32LE(i * 4);
    k = Math.imul(k, c1); k = (k << 15) | (k >>> 17); k = Math.imul(k, c2);
    h ^= k; h = (h << 13) | (h >>> 19); h = (Math.imul(h, 5) + 0xe6546b64) >>> 0;
  }
  let k = 0; const tail = nblocks * 4;
  switch (data.length & 3) {
    case 3: k ^= data[tail + 2] << 16;
    case 2: k ^= data[tail + 1] << 8;
    case 1: k ^= data[tail];
      k = Math.imul(k, c1); k = (k << 15) | (k >>> 17); k = Math.imul(k, c2); h ^= k;
  }
  h ^= data.length;
  h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b); h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35); h ^= h >>> 16;
  return h >>> 0;
}
module.exports = { murmur3_32 };
