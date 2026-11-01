// Cliente mínimo do SolanaStore: chaves assinadas por endereço EVM, PDAs e os dados do programa de
// teste `pda_program` (reference-runtime). Usado pelos testes e pelos scripts de demonstração.
const { ethers } = require("ethers");

const HEAP = 0x300000000n;
const INPUT = 0x400000000n;
const SYSTEM = "0x" + "00".repeat(32);

/// Chave assinada por `addr` com um prefixo de 12 bytes (cada endereço controla 2^96 chaves).
function keyFor(addr, prefix = 0) {
  return ethers.zeroPadValue(ethers.concat([ethers.toBeHex(prefix, 12), addr]), 32);
}

const meta = (key, isSigner, isWritable) => ({ key, isSigner, isWritable });
const w = (key) => meta(key, false, true);
const r = (key) => meta(key, false, false);
const ws = (key) => meta(key, true, true);

const u64le = (v) => {
  const o = [];
  v = BigInt(v);
  for (let i = 0; i < 8; i++) {
    o.push(Number(v & 0xffn));
    v >>= 8n;
  }
  return o;
};

/// Bytes que o pda_program copia para o heap (0x300000000); `put` devolve o endereço (alinhado a 8).
class Heap {
  constructor() {
    this.b = [];
  }
  put(bytes) {
    while (this.b.length % 8) this.b.push(0);
    const a = HEAP + BigInt(this.b.length);
    this.b.push(...bytes);
    return a;
  }
  /// array de VmSlice (ptr, len)
  seeds(list) {
    const arr = [];
    for (const s of list) arr.push(...u64le(this.put(s)), ...u64le(s.length));
    return this.put(arr);
  }
}

/// Dados do pda_program: [op][a1..a5][watch][heapLen][heap]. op 0 create_program_address,
/// 1 try_find_program_address, 2 invoke_signed_c, 3 invoke_signed_rust (r1..r5 = a1..a5).
const pdaIx = (op, a, watch, h) => ethers.hexlify(Uint8Array.from([...[op, ...a, watch, h.b.length].flatMap(u64le), ...h.b]));

const ED_P = 2n ** 255n - 19n;
const ED_D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
function modpow(b, e, m) {
  let res = 1n;
  b %= m;
  while (e > 0n) {
    if (e & 1n) res = (res * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return res;
}
/// `CompressedEdwardsY::decompress().is_some()`
function onCurve(h) {
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(h[i]);
  y = (y & ((1n << 255n) - 1n)) % ED_P;
  const yy = (y * y) % ED_P;
  const u = (yy + ED_P - 1n) % ED_P;
  const v = (ED_D * yy + 1n) % ED_P;
  if (u === 0n) return true;
  if (v === 0n) return false;
  return modpow((u * v) % ED_P, (ED_P - 1n) / 2n, ED_P) === 1n;
}
/// `Pubkey::find_program_address`
function findPda(seeds, programId) {
  for (let bump = 255; bump >= 0; bump--) {
    const h = ethers.getBytes(ethers.sha256(ethers.concat([...seeds, Uint8Array.of(bump), programId, ethers.toUtf8Bytes("ProgramDerivedAddress")])));
    if (!onCurve(h)) return [ethers.hexlify(h), bump];
  }
  throw new Error("sem PDA");
}

/// CPI do cofre: SystemInstruction::Transfer do PDA `vault` (1ª conta da instrução, sem dados) para
/// `to` (2ª), assinada com as seeds ["vault", bump] — dados prontos para o pda_program (op 2).
function vaultTransferIx(vault, bump, to, lamports, seedWord = "vault") {
  const m0 = INPUT + 8n; // marcador do 1º registro de conta no input serializado
  const m1 = m0 + 88n + 10240n + 8n; // 2º registro (1ª conta sem dados: 88 + 10240 reservados + rent_epoch)
  const h = new Heap();
  const sysId = h.put(new Array(32).fill(0));
  const k0 = h.put(ethers.getBytes(vault));
  const k1 = h.put(ethers.getBytes(to));
  const metas = h.put([...u64le(k0), 1, 1, 0, 0, 0, 0, 0, 0, ...u64le(k1), 1, 0, 0, 0, 0, 0, 0, 0]);
  const data = h.put([2, 0, 0, 0, ...u64le(lamports)]);
  const ix = h.put([sysId, metas, 2, data, 12].flatMap(u64le));
  const info = (m) => [...[m + 8n, m + 72n, 0, m + 88n, m + 40n, 0].flatMap(u64le), 0, 1, 0, 0, 0, 0, 0, 0];
  const infos = h.put([...info(m0), ...info(m1)]);
  const signer = h.seeds([ethers.toUtf8Bytes(seedWord), Uint8Array.of(bump)]);
  const signers = h.put([...u64le(signer), ...u64le(2)]);
  return { data: pdaIx(2, [ix, infos, 2, signers, 1], m0 + 72n, h), metas: [w(vault), w(to), r(SYSTEM)] };
}

/// Dados para o pda_program logar try_find_program_address(["vault"], programId).
function findVaultIx(programId, seedWord = "vault") {
  const h = new Heap();
  const seeds = h.seeds([ethers.toUtf8Bytes(seedWord)]);
  const pid = h.put(ethers.getBytes(programId));
  const out = h.put(new Array(32).fill(0));
  const bumpOut = h.put(new Array(8).fill(0));
  return pdaIx(1, [seeds, 1, pid, out, bumpOut], 0, h);
}

// ------------------------------------------------------------------ SPL Token (Tokenkeg...)
const TOKEN_PROGRAM = "0x06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a9"; // TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
const MINT_LEN = 82;
const TOKEN_ACCOUNT_LEN = 165;
/// Rent::default().minimum_balance(len) (6960 lamports por byte, 128 de overhead)
const rentExempt = (len) => BigInt((128 + len) * 6960);
const ixData = (...parts) => ethers.hexlify(Uint8Array.from(parts.flat()));
const token = {
  /// InitializeMint2 { decimals, mint_authority, freeze_authority: None }  — contas: [mint (w)]
  initializeMint2: (decimals, authority) => ixData([20, decimals], [...ethers.getBytes(authority)], [0]),
  /// InitializeAccount3 { owner } — contas: [conta (w), mint]
  initializeAccount3: (owner) => ixData([18], [...ethers.getBytes(owner)]),
  /// MintTo { amount } — contas: [mint (w), destino (w), autoridade (s)]
  mintTo: (amount) => ixData([7], u64le(amount)),
  /// Transfer { amount } — contas: [origem (w), destino (w), dono (s)]
  transfer: (amount) => ixData([3], u64le(amount)),
  /// TransferChecked { amount, decimals } — contas: [origem (w), mint, destino (w), dono (s)]
  transferChecked: (amount, decimals) => ixData([12], u64le(amount), [decimals]),
  /// Burn { amount } — contas: [conta (w), mint (w), dono (s)]
  burn: (amount) => ixData([8], u64le(amount)),
};
/// Saldo de uma conta de token (u64 no offset 64 dos 165 bytes).
function tokenAmount(data) {
  const b = ethers.getBytes(data);
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[64 + i]);
  return v;
}
/// Supply de um mint (u64 no offset 36).
function mintSupply(data) {
  const b = ethers.getBytes(data);
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[36 + i]);
  return v;
}
const s = (key) => meta(key, true, false);

module.exports = {
  TOKEN_PROGRAM, MINT_LEN, TOKEN_ACCOUNT_LEN, rentExempt, token, tokenAmount, mintSupply, s, HEAP, INPUT, SYSTEM, keyFor, w, r, ws, u64le, Heap, pdaIx, onCurve, findPda, vaultTransferIx, findVaultIx };
