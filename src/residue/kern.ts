// kern.ts - the WASM word kernel of residue openings (AssemblyScript), behind
// cyberspace-core's WordKernel interface (src/residue.ts, WASM_WORD_KERNEL).
//
// Built by scripts/build-kernel.mjs into kernWasm.ts (the module as base64);
// kern.sha256 records the hash of this source and of the module, and a test
// checks both. Never edit kernWasm.ts by hand: edit this file and rebuild.
//
// 64-bit Montgomery arithmetic, R = 2^64, for odd p in [2^61, 2^62).
// Memory map (bytes): 0..1023 scratch and state (the pointers below),
// 1024..33799 the engine table, 65536.. AssemblyScript's static data
// (--memoryBase 65536), and from 1 MiB the caller's arrays, written by the
// loader. Nothing allocates after start, so the stub runtime's heap stays far
// below 1 MiB.
//
// Lifted unchanged from the research kernel (cantor-verification,
// browser-bench/kern.ts): the Montgomery arithmetic, sprp2, searchPrime with
// its sieve, the SHA-256 compression from a midstate, treeM, engineM (the
// method of differences), residue, hopResidue, combineBatch, combine2Batch.
// Rewritten to the spec (CYBERSPACE_V2.md 5.9 and 5.10 at 8b45430):
// primesBatch (the index is be64(j)), and the attempt and the grind (the seed
// hashes the id, the seal and a full 64-bit nonce, g_base is its low 85 bits,
// G is a second hash over the seed and r_g, and the price is G A < 2^256).
// New and small: searchBatch and pairMod, the rest of the WordKernel shape.

let P: u64 = 0, PINV: u64 = 0, ONE: u64 = 0, R2: u64 = 0

@inline function mulhi(a: u64, b: u64): u64 {
  const a0 = a & 0xffffffff, a1 = a >> 32, b0 = b & 0xffffffff, b1 = b >> 32
  const p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1
  const mid = (p00 >> 32) + (p01 & 0xffffffff) + (p10 & 0xffffffff)
  return p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32)
}
@inline function mmul(a: u64, b: u64): u64 {
  const lo = a * b, hi = mulhi(a, b)
  const q = lo * PINV
  const u = hi + mulhi(q, P) + (lo != 0 ? 1 : 0)
  return u >= P ? u - P : u
}
@inline function madd(a: u64, b: u64): u64 { const s = a + b; return s >= P ? s - P : s }
@inline function msub(a: u64, b: u64): u64 { return a >= b ? a - b : a + P - b }
@inline function mhalf(a: u64): u64 { return (a & 1) ? (a + P) >> 1 : a >> 1 }
@inline function mpair(a: u64, b: u64): u64 {
  const s = madd(a, b)
  return madd(mhalf(mmul(s, madd(s, ONE))), b)
}

export function setPrime(p: u64): void {
  P = p
  let inv = p
  for (let i = 0; i < 5; i++) inv *= 2 - p * inv
  PINV = 0 - inv
  ONE = (0 - p) % p
  let r = ONE
  for (let i = 0; i < 64; i++) r = madd(r, r)
  R2 = r
}
@inline function toMont(a: u64): u64 { return mmul(a % P, R2) }
@inline function fromMont(a: u64): u64 { return mmul(a, 1) }
/** plain a*b mod p */
@inline function mulmod(a: u64, b: u64): u64 { return mmul(mmul(a, b), R2) }

// ------------------------------------------------------------------ primes
function sprp2(n: u64): bool {
  setPrimeLite(n)
  let d = n - 1
  const r = <i32>ctz(d)
  d >>= r
  const top = 63 - <i32>clz(d)
  let x = madd(ONE, ONE)
  for (let b = top - 1; b >= 0; b--) {
    x = mmul(x, x)
    if ((d >> <u64>b) & 1) x = madd(x, x)
  }
  const mone = P - ONE
  if (x == ONE || x == mone) return true
  for (let i = 1; i < r; i++) {
    x = mmul(x, x)
    if (x == mone) return true
  }
  return false
}
/** setPrime without R^2 (the SPRP needs only R mod p). */
@inline function setPrimeLite(p: u64): void {
  P = p
  let inv = p
  for (let i = 0; i < 5; i++) inv *= 2 - p * inv
  PINV = 0 - inv
  ONE = (0 - p) % p
}

const SMALL: StaticArray<u32> = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]
const REM = new StaticArray<u32>(24)

export function searchPrime(n: u64): u64 {
  for (let i = 0; i < 24; i++) REM[i] = <u32>(n % <u64>SMALL[i])
  while (true) {
    let ok = true
    for (let i = 0; i < 24; i++) if (REM[i] == 0) { ok = false; break }
    if (ok && sprp2(n)) return n
    n += 2
    for (let i = 0; i < 24; i++) { let v = REM[i] + 2; if (v >= SMALL[i]) v -= SMALL[i]; REM[i] = v }
  }
}

// ------------------------------------------------------------------ SHA-256 (one compression from a midstate)
const K256: StaticArray<u32> = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
const W = new StaticArray<u32>(64)
const S = new StaticArray<u32>(8)
/** S = compress(state at memory midPtr, W[0..15]). */
function compressFrom(midPtr: usize): void {
  for (let i = 16; i < 64; i++) {
    const x = W[i - 15], y = W[i - 2]
    const g0 = rotr<u32>(x, 7) ^ rotr<u32>(x, 18) ^ (x >> 3)
    const g1 = rotr<u32>(y, 17) ^ rotr<u32>(y, 19) ^ (y >> 10)
    W[i] = g1 + W[i - 7] + g0 + W[i - 16]
  }
  let a = load<u32>(midPtr), b = load<u32>(midPtr + 4), c = load<u32>(midPtr + 8), d = load<u32>(midPtr + 12)
  let e = load<u32>(midPtr + 16), f = load<u32>(midPtr + 20), g = load<u32>(midPtr + 24), h = load<u32>(midPtr + 28)
  for (let i = 0; i < 64; i++) {
    const t1 = h + (rotr<u32>(e, 6) ^ rotr<u32>(e, 11) ^ rotr<u32>(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + W[i]
    const t2 = (rotr<u32>(a, 2) ^ rotr<u32>(a, 13) ^ rotr<u32>(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))
    h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2
  }
  S[0] = load<u32>(midPtr) + a; S[1] = load<u32>(midPtr + 4) + b; S[2] = load<u32>(midPtr + 8) + c; S[3] = load<u32>(midPtr + 12) + d
  S[4] = load<u32>(midPtr + 16) + e; S[5] = load<u32>(midPtr + 20) + f; S[6] = load<u32>(midPtr + 24) + g; S[7] = load<u32>(midPtr + 28) + h
}

/**
 * p_j for j in [j0, j0 + count) (5.9). SHA256(PRIME_DOMAIN || prev || be64(j))
 * is 71 bytes, two blocks, and the first ends with the first byte of be64(j),
 * so a midstate over it (8 words, numeric values, at midPtr) serves every j
 * with that top byte; the tail is the other seven bytes. The caller keeps
 * j0 .. j0 + count - 1 under one top byte. Primes written as u64 at outPtr.
 */
export function primesBatch(midPtr: usize, j0: u64, count: u32, outPtr: usize): void {
  for (let k: u32 = 0; k < count; k++) {
    const j = j0 + <u64>k
    W[0] = <u32>(j >> 24)                     // bytes 1 to 4 of be64(j)
    W[1] = (<u32>(j & 0xffffff) << 8) | 0x80  // bytes 5 to 7, then the padding bit
    for (let i = 2; i < 15; i++) W[i] = 0
    W[15] = 71 * 8
    compressFrom(midPtr)
    const x = ((<u64>S[0] << 32) | <u64>S[1]) >> 4
    const n = ((<u64>1 << 61) + x) | 1
    store<u64>(outPtr + (<usize>k << 3), searchPrime(n))
  }
}

/** searchPrime from each odd start (u64 at inPtr, in [2^61, 2^62)), into outPtr. */
export function searchBatch(inPtr: usize, outPtr: usize, count: u32): void {
  for (let k: u32 = 0; k < count; k++) {
    const o = <usize>k << 3
    store<u64>(outPtr + o, searchPrime(load<u64>(inPtr + o)))
  }
}

// ------------------------------------------------------------------ residue trees and the engine
const STK = new StaticArray<u64>(72)
const LVL = new StaticArray<i32>(72)
const DTAB: usize = 1024   // engine table: (2^k + 1) u64, k <= 12 -> 32 KB

/** Montgomery root over [b, b + 2^h) with b given in Montgomery form. */
function treeM(bm: u64, h: i32): u64 {
  let sp = 0
  const n: u64 = <u64>1 << <u64>h
  let x = bm
  for (let i: u64 = 0; i < n; i++) {
    let c = x, l = 0
    while (sp > 0 && LVL[sp - 1] == l) { sp--; c = mpair(STK[sp], c); l++ }
    STK[sp] = c; LVL[sp] = l; sp++
    x = madd(x, ONE)
  }
  return STK[0]
}

function engineM(bm: u64, h: i32, k: i32): u64 {
  if (k > h) k = h
  const d: i32 = 1 << k
  const nodes: u64 = <u64>1 << <u64>(h - k)
  const n0: i32 = nodes < <u64>(d + 1) ? <i32>nodes : d + 1
  let step = ONE
  for (let i = 0; i < k; i++) step = madd(step, step)
  let x = bm
  for (let j = 0; j < n0; j++) { store<u64>(DTAB + (<usize>j << 3), treeM(x, k)); x = madd(x, step) }
  for (let i = 1; i < n0; i++)
    for (let j = n0 - 1; j >= i; j--) {
      const pj = DTAB + (<usize>j << 3)
      store<u64>(pj, msub(load<u64>(pj), load<u64>(pj - 8)))
    }
  for (let i = n0; i <= d; i++) store<u64>(DTAB + (<usize>i << 3), 0)
  let sp = 0
  const p = P
  for (let j: u64 = 0; j < nodes; j++) {
    let c = load<u64>(DTAB), l = 0
    while (sp > 0 && LVL[sp - 1] == l) { sp--; c = mpair(STK[sp], c); l++ }
    STK[sp] = c; LVL[sp] = l; sp++
    if (j + 1 < nodes) {
      let cur = load<u64>(DTAB)
      for (let i = 0; i < d; i++) {
        const pi = DTAB + (<usize>i << 3)
        const nx = load<u64>(pi + 8)
        const s = cur + nx
        store<u64>(pi, s >= p ? s - p : s)
        cur = nx
      }
    }
  }
  return STK[0]
}

/** root(base, h) mod p for the current prime; baseMod = base mod p (plain). k < 0: plain tree. */
export function residue(p: u64, baseMod: u64, h: i32, k: i32): u64 {
  setPrime(p)
  const bm = toMont(baseMod)
  if (h == 0) return baseMod % p
  return fromMont(k < 0 ? treeM(bm, h) : engineM(bm, h, k))
}

/** hop_n mod p from four per-component (baseMod, h) pairs; heights < 0 mean "a plain value". */
export function hopResidue(p: u64, bx: u64, hx: i32, kx: i32, by: u64, hy: i32, ky: i32,
                           bz: u64, hz: i32, kz: i32, bt: u64, ht: i32, kt: i32): u64 {
  setPrime(p)
  const rx = hx > 0 ? engineM(toMont(bx), hx, kx) : toMont(bx)
  const ry = hy > 0 ? engineM(toMont(by), hy, ky) : toMont(by)
  const rz = hz > 0 ? engineM(toMont(bz), hz, kz) : toMont(bz)
  const rt = ht > 0 ? engineM(toMont(bt), ht, kt) : toMont(bt)
  return fromMont(mpair(mpair(mpair(rx, ry), rz), rt))
}

/** r_j = pi(pi(pi(x, y), z), t) mod p_j over arrays of u64. */
export function combineBatch(pP: usize, px: usize, py: usize, pz: usize, pt: usize, out: usize, m: u32): void {
  for (let j: u32 = 0; j < m; j++) {
    const o = <usize>j << 3
    setPrime(load<u64>(pP + o))
    const r = mpair(mpair(mpair(toMont(load<u64>(px + o)), toMont(load<u64>(py + o))), toMont(load<u64>(pz + o))), toMont(load<u64>(pt + o)))
    store<u64>(out + o, fromMont(r))
  }
}

/** pi_p(a, b) for a and b below p. */
export function pairMod(p: u64, a: u64, b: u64): u64 {
  setPrime(p)
  return fromMont(mpair(toMont(a), toMont(b)))
}

/** r_j = pi(a_j, b_j) mod p_j over arrays of u64 (region_n residues with the temporal residues). */
export function combine2Batch(pP: usize, pa: usize, pb: usize, out: usize, m: u32): void {
  for (let j: u32 = 0; j < m; j++) {
    const o = <usize>j << 3
    setPrime(load<u64>(pP + o))
    store<u64>(out + o, fromMont(mpair(toMont(load<u64>(pa + o)), toMont(load<u64>(pb + o)))))
  }
}

// ------------------------------------------------------------------ re-roll attempts (5.10)
//
// seed = SHA256(GRIND_DOMAIN || prev || seal || be64(nonce)) is 103 bytes. Its
// first block (the domain's 31 bytes, the id's 32, the seal's first byte) is
// the same for every nonce, so the loader takes its midstate once (GMID); the
// second block is the seal's other 31 bytes, the nonce and the padding, kept
// as a template of 16 words (GTAIL) into which each attempt writes its nonce.
// G = SHA256(GRIND_DOMAIN || seed || be64(r_g)) is 71 bytes and the seed
// changes every attempt, so it costs two compressions from the IV: the first
// block is the domain (its first 28 bytes as words 0 to 6 of GDOM, bytes 28 to
// 30 in word 7), the seed and the first byte of r_g; the second is r_g's other
// seven bytes. Three compressions an attempt; the height-12 tree dominates.

const GMID: usize = 256   // midstate over (GRIND_DOMAIN || prev || seal[0]), 8 words
const IV: usize = 288     // the SHA-256 initial state, 8 words
const GOUT: usize = 320   // G of the last attempt, 8 words
const GSEED: usize = 352  // the seed of the last attempt, 8 words
const GTAIL: usize = 384  // the seed's second block, 16 words, the nonce's bytes left zero
const GDOM: usize = 448   // the first 32 bytes of G's first block, the domain then a zero byte, 8 words
const GMID2: usize = 480  // the state after G's first block, 8 words
const GNONCE: usize = 512 // the nonce grind found, u64
let GP: u64 = 0           // p_0
let GK: i32 = 4           // the engine level of the attempt's height-12 tree
let GA: u64 = 1           // the price A, in attempts
let GRG: u64 = 0          // r_g of the last attempt

store<u32>(IV, 0x6a09e667); store<u32>(IV + 4, 0xbb67ae85); store<u32>(IV + 8, 0x3c6ef372); store<u32>(IV + 12, 0xa54ff53a)
store<u32>(IV + 16, 0x510e527f); store<u32>(IV + 20, 0x9b05688c); store<u32>(IV + 24, 0x1f83d9ab); store<u32>(IV + 28, 0x5be0cd19)

/** p_0, the engine level, and the price A (at least 1, below 2^64). */
export function grindSetup(p0: u64, k: i32, a: u64): void { GP = p0; GK = k; GA = a }
export function gmidPtr(): usize { return GMID }
export function gtailPtr(): usize { return GTAIL }
export function gdomPtr(): usize { return GDOM }
export function goutPtr(): usize { return GOUT }
export function gseedPtr(): usize { return GSEED }
export function gnoncePtr(): usize { return GNONCE }
export function lastRg(): u64 { return GRG }

/** One attempt for any 64-bit nonce, with p_0 already the current prime. Whether G A < 2^256. */
function attemptCore(nonce: u64): bool {
  for (let i = 0; i < 16; i++) W[i] = load<u32>(GTAIL + (<usize>i << 2))
  W[7] = (W[7] & 0xffffff00) | <u32>(nonce >> 56)   // byte 31: the nonce's first
  W[8] = <u32>(nonce >> 24)                         // bytes 32 to 35
  W[9] = (<u32>(nonce & 0xffffff) << 8) | 0x80      // bytes 36 to 38, then the padding bit
  compressFrom(GMID)
  for (let i = 0; i < 8; i++) store<u32>(GSEED + (<usize>i << 2), S[i])
  // g_base = ((int(seed) mod 2^85) >> 12) << 12: 21 bits above 2^64 and 52 below.
  const ghi = <u64>(S[5] & 0x1fffff)
  const glo = ((<u64>S[6] << 32) | <u64>S[7]) & ~(<u64>0xfff)
  // g_base mod p = ghi (2^64 mod p) + glo mod p; ghi < p, and ONE is 2^64 mod p.
  const bmod = madd(mulmod(ghi, ONE), glo % P)
  const r = fromMont(engineM(toMont(bmod), 12, GK))
  GRG = r
  // G's first block: the domain, the seed at bytes 31 to 62, r_g's first byte at 63.
  for (let i = 0; i < 7; i++) W[i] = load<u32>(GDOM + (<usize>i << 2))
  W[7] = (load<u32>(GDOM + 28) & 0xffffff00) | (load<u32>(GSEED) >> 24)
  for (let i = 0; i < 7; i++) W[8 + i] = (load<u32>(GSEED + (<usize>i << 2)) << 8) | (load<u32>(GSEED + (<usize>(i + 1) << 2)) >> 24)
  W[15] = (load<u32>(GSEED + 28) << 8) | <u32>(r >> 56)
  compressFrom(IV)
  for (let i = 0; i < 8; i++) store<u32>(GMID2 + (<usize>i << 2), S[i])
  W[0] = <u32>(r >> 24)
  W[1] = (<u32>(r & 0xffffff) << 8) | 0x80
  for (let i = 2; i < 15; i++) W[i] = 0
  W[15] = 71 * 8
  compressFrom(GMID2)
  for (let i = 0; i < 8; i++) store<u32>(GOUT + (<usize>i << 2), S[i])
  // The price: G A < 2^256 exactly when the 256-by-64-bit product carries nothing past 2^256.
  let c: u64 = 0
  for (let i = 3; i >= 0; i--) {
    const g = (<u64>S[2 * i] << 32) | <u64>S[2 * i + 1]
    const lo = g * GA
    const hi = mulhi(g, GA)
    const s = lo + c
    c = hi + (s < lo ? 1 : 0)
  }
  return c == 0
}

/** One attempt for `nonce` under the setup; seed at GSEED, G at GOUT, r_g in lastRg(). 1 when it meets the price. */
export function attempt(nonce: u64): u32 {
  setPrime(GP)
  return attemptCore(nonce) ? 1 : 0
}

/**
 * The first nonce of [start, start + count) meeting the price, at GNONCE, with
 * its seed, G and r_g as attempt leaves them: 1 when found, 0 when not.
 * start + count never passes 2^64 (the caller's range).
 */
export function grind(start: u64, count: u64): u32 {
  setPrime(GP)
  for (let i: u64 = 0; i < count; i++) {
    const n = start + i
    if (attemptCore(n)) { store<u64>(GNONCE, n); return 1 }
  }
  return 0
}
