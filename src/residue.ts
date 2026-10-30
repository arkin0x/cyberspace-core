/**
 * residue.ts - residue openings, version 2 of the hop proof (spec 5.9 to 5.13).
 *
 * Version 1 of the hop proof is SHA256(SHA256(hop_n)) (spec 5.6), a
 * fingerprint, so checking it means rebuilding every tree: verification costs
 * what production costs. Version 2 keeps the Cantor work exactly as it was and
 * changes only the commitment at the end. A Cantor root modulo an odd p is the
 * same tree carried on a clock of p positions, with halving replaced by a
 * multiplication by (p + 1) / 2, so anyone can compute hop_n mod p in word
 * arithmetic without building hop_n (5.9). The prover computes hop_n modulo m
 * primes, each drawn on its own from the previous event id and its index,
 * seals that list in a Merkle tree (the `proof` tag), pays a re-roll price in
 * residue work for a nonce (the `mn` tag), and opens the 16 entries the nonce
 * draws (the `mp` tag) (5.10). A verifier recomputes those 16 entries itself
 * and climbs their paths to the seal (5.11): milliseconds at height 20.
 *
 * Two seams keep the arithmetic replaceable. A WordKernel does the 61-bit
 * modular work (the prime search, a root modulo one prime, the combine modulo
 * every prime, and optionally whole steps with their hashes); JS_WORD_KERNEL
 * is the pure JavaScript one, Montgomery with 25-bit limbs in plain numbers,
 * and WASM_WORD_KERNEL is src/residue/kern.ts compiled (64-bit Montgomery in
 * WebAssembly, committed as kernWasm.ts). Every function that takes a kernel
 * defaults to selectWordKernel(): WASM when WebAssembly is there and the
 * module can be instantiated, JavaScript otherwise. A BigBackend does the big
 * numbers: the Cantor trees, the exact pairings for region_n, the product
 * tree of the primes, the pairings modulo Q and the remainder trees.
 * BIGINT_BACKEND is native BigInt and the default; a consumer passes its own
 * as `backend` to computeHopProofV2, proveHopResidues, computeHopResidues or
 * auditHopLevel2 (a GMP adapter, say, which core never imports: see the
 * README). Every implementation of either MUST give the same values, which
 * the golden vectors check. The three exported implementations are frozen.
 *
 * Checked against the spec's hop-residue-vectors.json (written from
 * hop-residue-reference.py), copied unchanged into test/fixtures.
 */

import { bytesToHex, cantorPair, hexToBytes, sha256, sha256FromMidstate, sha256Midstate } from './cantor.js'
import { AXIS_BITS, type Plane, type Xyz } from './coords.js'
import { GRANDFATHERED_V1_HOPS } from './grandfathered_v1_hops.js'
import {
  DEFAULT_MAX_COMPUTE_HEIGHT,
  TEMPORAL_MAX_COMPUTE_HEIGHT,
  alignedBase,
  computeHopProof,
  computeSubtreeCantor,
  findLcaHeight,
  type ProgressFn,
} from './movement.js'
import { decodeNonce, encodeNonce, meetsPrice, type NonceSearch } from './sidestep.js'
import { terrainK } from './terrain.js'
import { KERN_WASM_BASE64 } from './residue/kernWasm.js'

// ------------------------------------------------------------- constants (5.9)

const ascii = (s: string): Uint8Array => new TextEncoder().encode(s)

/** Domain of the hop primes (5.9). 31 bytes. */
export const HOP_RESIDUE_PRIME_DOMAIN = ascii('CYBERSPACE_HOP_RESIDUE_PRIME_V1')
/** Domain of the seal's leaves (5.10). 30 bytes. */
export const HOP_RESIDUE_LEAF_DOMAIN = ascii('CYBERSPACE_HOP_RESIDUE_LEAF_V1')
/** Domain of the re-roll attempt, both its seed and its G (5.10). 31 bytes. */
export const HOP_RESIDUE_GRIND_DOMAIN = ascii('CYBERSPACE_HOP_RESIDUE_GRIND_V1')
/** Domain of the draw of sample indices from G (5.10). 32 bytes. */
export const HOP_RESIDUE_SAMPLE_DOMAIN = ascii('CYBERSPACE_HOP_RESIDUE_SAMPLE_V1')
/** Residues a verifier recomputes. */
export const HOP_SAMPLES = 16
/** Residues per Merkle leaf. */
export const RESIDUE_BLOCK = 8
/** Every hop prime is at least 2^61. */
export const PRIME_BITS = 61
/** The primes' product spans a quarter of the widest root. */
export const WIDTH_DIVISOR = 4
/** One re-roll attempt is one aligned height-12 tree modulo p_0. */
export const HOP_GRIND_HEIGHT = 12
/** The small-factor filter of the prime search (5.9). */
export const SMALL_ODD_PRIMES: readonly number[] = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]
/** The re-roll budget B(h) in attempts for heights 0 to 22 (5.9, 5.10): one sixteenth of an honest hop at that height. */
export const HOP_REROLL_BUDGET: readonly bigint[] = [
  0n, 0n, 0n, 0n, 0n, 0n, 1n, 2n, 4n, 7n, 14n, 30n, 65n, 149n, 355n, 782n,
  1753n, 4016n, 8959n, 20028n, 44826n, 99974n, 223681n,
]
/** The leaf that pads the seal's tree to a power of two (5.10). */
export const PAD_LEAF = new Uint8Array(32)

const TWO_64 = 1n << 64n
const TWO_61 = 1n << 61n
const AXIS_MASK = (1n << BigInt(AXIS_BITS)) - 1n
const HEX64 = /^[0-9a-f]{64}$/
const LOWER_HEX = /^[0-9a-f]*$/
/** Characters of one opening in `mp` for each residue of its block and each sibling (8.4). */
const RESIDUE_HEX = 16
const SIBLING_HEX = 64

/**
 * Residue arithmetic counts its leaves in Number loops, exact below 2^53, and a
 * tree that tall is centuries of work anyway; refuse loudly rather than spin.
 */
const MAX_RESIDUE_HEIGHT = 52

// ------------------------------------------------------------- bytes

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let at = 0
  for (const p of parts) { out.set(p, at); at += p.length }
  return out
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let n = 0n
  for (const b of bytes) n = (n << 8n) | BigInt(b)
  return n
}

/** be64(n) (5.9): n as 8 big-endian bytes, for 0 <= n < 2^64. */
export function be64(n: bigint | number): Uint8Array {
  const v = BigInt(n)
  if (v < 0n || v >= TWO_64) throw new Error('be64 takes an integer in [0, 2^64)')
  const out = new Uint8Array(8)
  new DataView(out.buffer).setBigUint64(0, v)
  return out
}

/** be32(n) (5.9): n as 4 big-endian bytes, for 0 <= n < 2^32. */
export function be32(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n >= 2 ** 32) throw new Error('be32 takes an integer in [0, 2^32)')
  const out = new Uint8Array(4)
  new DataView(out.buffer).setUint32(0, n)
  return out
}

function checkPreviousEventId(previousEventId: Uint8Array): void {
  if (previousEventId.length !== 32) throw new Error('previous_event_id must be 32 raw bytes')
}

// ------------------------------------------------------------- word lists

/**
 * A list of values below 2^64, two 32-bit words each, high word first:
 * entry j is (list[2j] << 32) | list[2j + 1]. Primes and residues travel this
 * way between the kernel, the big-number backend and the seal, so a WASM
 * kernel can copy one buffer and no step depends on the platform's byte order.
 */
export type WordList = Uint32Array

/** An empty word list for `count` values. */
export function wordList(count: number): WordList {
  return new Uint32Array(2 * count)
}

/** Entry j of a word list. */
export function wordAt(list: WordList, j: number): bigint {
  return (BigInt(list[2 * j]) << 32n) | BigInt(list[2 * j + 1])
}

/** Sets entry j of a word list to v, for 0 <= v < 2^64. */
export function setWord(list: WordList, j: number, v: bigint): void {
  list[2 * j] = Number(v >> 32n)
  list[2 * j + 1] = Number(v & 0xffffffffn)
}

/** A word list's values, in order. */
export function wordsOf(list: WordList): bigint[] {
  const out: bigint[] = []
  for (let j = 0; j < list.length / 2; j++) out.push(wordAt(list, j))
  return out
}

/** SHA-256 over be64 of every value in a word list, as the vectors hash the primes and residues. */
export function wordListSha256(list: WordList): Uint8Array {
  const bytes = new Uint8Array(4 * list.length)
  const view = new DataView(bytes.buffer)
  for (let i = 0; i < list.length; i++) view.setUint32(4 * i, list[i])
  return sha256(bytes)
}

// ------------------------------------------------------------- the two seams

/**
 * The 61-bit modular arithmetic of residue openings. Every method returns
 * exactly what spec 5.9 defines; an implementation chooses only how fast.
 */
export interface WordKernel {
  readonly name: string
  /**
   * For each j, the hop prime search of 5.9 from the odd start at entry j of
   * `starts` (in [2^61, 2^62)): the smallest n >= start, stepping by 2, with no
   * factor in SMALL_ODD_PRIMES that is a base-2 strong probable prime. Written
   * to entry j of `out`.
   */
  searchPrimes(starts: WordList, out: WordList): void
  /**
   * compute_subtree_cantor(base, height) mod p for an odd p in [2^61, 2^62),
   * by any equivalent method (5.9), without the root. `base` is any natural
   * number.
   */
  rootResidue(p: bigint, base: bigint, height: number): bigint
  /** pi_p(a, b) (5.9) for a and b below p. */
  pairMod(p: bigint, a: bigint, b: bigint): bigint
  /**
   * For each j, the entries j of `parts` folded from the left with pi modulo
   * prime j: pi_p(pi_p(pi_p(a, b), c), d) for four parts, pi_p(a, b) for two.
   * Every entry of every part is below its prime. Written to entry j of `out`.
   */
  combine(primes: WordList, parts: readonly WordList[], out: WordList): void
  /*
   * Whole steps, hashes included, for a kernel that can do them faster than
   * residue.ts composes them from the four methods above and its own SHA-256.
   * Each is optional; when a kernel has one it MUST give exactly what the
   * composition gives (the golden vectors check both).
   */
  /** p_0 to p_(m-1) for an id (5.9), m = out.length / 2 (at most 2^53), into `out`: deriveHopPrimes. */
  hopPrimes?(previousEventId: Uint8Array, out: WordList): void
  /** One attempt (5.10) for a nonce below 2^64 under a seal: hopAttempt. */
  attempt?(previousEventId: Uint8Array, seal: Uint8Array, nonce: bigint, p0: bigint): HopAttempt
  /**
   * The first nonce in [start, end) whose attempt meets the price `attempts`
   * (G A < 2^256), with that attempt, or null: one range of findHopNonce.
   */
  findNonce?(previousEventId: Uint8Array, seal: Uint8Array, attempts: bigint, p0: bigint, start: bigint, end: bigint): HopNonce | null
}

/** The product tree over a hop's primes: level 0 the primes, each level up the products of pairs, the top Q. */
export interface ProductTree<N> {
  readonly levels: readonly (readonly N[])[]
}

/**
 * The big-number arithmetic of a hop, every step of the prover that works on
 * numbers wider than a word: the Cantor trees, the exact pairings for
 * region_n, the product tree of the primes, the region pairings modulo Q (the
 * multi-axis path of the prover) and the remainder trees. The values are the
 * backend's own type N, which core only passes back to the same backend;
 * native BigInt is N = bigint.
 *
 * Any implementation MUST return exactly the values BIGINT_BACKEND returns
 * (the residues, and so the tags, are then bit for bit the same); it chooses
 * only how fast and in what memory. Methods never modify their arguments.
 */
export interface BigBackend<N = bigint> {
  readonly name: string
  fromBigInt(v: bigint): N
  toBigInt(v: N): bigint
  /** compute_subtree_cantor(base, height) (4.6), refusing heights above maxComputeHeight. */
  subtreeCantor(base: bigint, height: number, maxComputeHeight: number, onProgress?: ProgressFn): N
  /** pi(a, b) exactly. */
  pair(a: N, b: N): N
  /** The product tree over the primes, built once per hop. */
  productTree(primes: WordList): ProductTree<N>
  /** pi(a, b) mod Q, from a and b reduced modulo Q first, Q the product of every prime (odd, so halving is exact). */
  pairModQ(tree: ProductTree<N>, a: N, b: N): N
  /** x mod p_j for every prime, by one descent of the tree, into entry j of `out`. */
  remainders(tree: ProductTree<N>, x: N, out: WordList): void
  /**
   * Optional, for a backend whose values live outside the JavaScript heap (a
   * GMP adapter's mpz_t in WebAssembly memory, which no garbage collector
   * sees): frees one value. Core calls it exactly once for every value it
   * made through the backend, as soon as it no longer needs it, and never for
   * a value it was given (the roots handed to proveHopResidues and
   * computeHopResidues stay the caller's). BigInt needs neither hook.
   */
  release?(value: N): void
  /** Optional, as `release`: frees a product tree core made through `productTree`. */
  releaseTree?(tree: ProductTree<N>): void
}

// ------------------------------------------------------------- residues of a root, by definition (5.9)

/** pi_p(a, b) = ((a + b)(a + b + 1)(p + 1)/2 + b) mod p, for odd p: pi(a, b) mod p from a mod p and b mod p. */
export function pairModP(a: bigint, b: bigint, p: bigint): bigint {
  const s = (a + b) % p
  return (s * (s + 1n) * ((p + 1n) / 2n) + b) % p
}

/** compute_subtree_cantor(base, height) mod p, by the same tree carried modulo p (5.9). The definition, in BigInt. */
export function residueTree(base: bigint, height: number, p: bigint): bigint {
  if (height < 0 || height > MAX_RESIDUE_HEIGHT) throw new Error(`residue height ${height} out of range`)
  const values: bigint[] = []
  const levels: number[] = []
  for (let i = 0; i < 2 ** height; i++) {
    let cur = (base + BigInt(i)) % p
    let level = 0
    while (levels.length > 0 && levels[levels.length - 1] === level) {
      levels.pop()
      cur = pairModP(values.pop()!, cur, p)
      level++
    }
    values.push(cur)
    levels.push(level)
  }
  return values[0]
}

/**
 * The same value by Babbage's method of differences at level k (5.9). The
 * level-k nodes of an aligned tree are the values of one polynomial of degree
 * 2^k at evenly spaced points, so once its differences are tabulated each
 * further node costs 2^k additions modulo p. In BigInt, for checking kernels.
 */
export function residueEngine(base: bigint, height: number, p: bigint, k: number = engineLevel(height)): bigint {
  if (height < 0 || height > MAX_RESIDUE_HEIGHT) throw new Error(`residue height ${height} out of range`)
  k = Math.max(0, Math.min(k, height))
  const d = 2 ** k
  const nodes = 2 ** (height - k)
  const n0 = Math.min(nodes, d + 1)
  const D: bigint[] = new Array(d + 1).fill(0n)
  for (let j = 0; j < n0; j++) D[j] = residueTree(base + (BigInt(j) << BigInt(k)), k, p)
  for (let i = 1; i < n0; i++) for (let j = n0 - 1; j >= i; j--) D[j] = (D[j] - D[j - 1] + p) % p
  const values: bigint[] = []
  const levels: number[] = []
  for (let n = 0; n < nodes; n++) {
    let cur = D[0]
    let level = 0
    while (levels.length > 0 && levels[levels.length - 1] === level) {
      levels.pop()
      cur = pairModP(values.pop()!, cur, p)
      level++
    }
    values.push(cur)
    levels.push(level)
    for (let i = 0; i < d; i++) D[i] = (D[i] + D[i + 1]) % p
  }
  return values[0]
}

/**
 * The difference engine's level for a residue of height h: the reference's
 * choice below h16, and 7 from there up (2^7 additions per node). Every level
 * gives the same residue; this one is only the fastest measured.
 */
export function engineLevel(height: number): number {
  return height < 16 ? Math.max(0, (height - 2) >> 1) : 7
}

/** The engine level of the attempt's height-12 tree, measured fastest in the JavaScript kernel. */
const ATTEMPT_ENGINE_LEVEL = 4

// ------------------------------------------------------------- the JavaScript word kernel
//
// A residue below p < 2^62 is three limbs of 25 bits, l0 + l1 2^25 + l2 2^50,
// held in plain numbers, and arithmetic is Montgomery with R = 2^75: every
// partial product is below 2^50 and every sum below 2^53, so doubles carry
// them exactly. The kernel keeps the current prime in module state and leaves
// each result in OUT, so the inner loops allocate nothing.

const LIMB = 33554432 // 2^25
const INV_LIMB = 1 / LIMB
const M25 = 0x1ffffff
const OUT = new Int32Array(3)
let P0 = 0, P1 = 0, P2 = 0, PINV = 0
/** R mod p, which is 1 in the Montgomery domain. */
let O0 = 0, O1 = 0, O2 = 0

interface PrimeContext {
  p: bigint
  p0: number; p1: number; p2: number; pinv: number
  /** R mod p. */
  o0: number; o1: number; o2: number
  /** R^2 mod p, to enter the Montgomery domain. */
  r0: number; r1: number; r2: number
}

/** a b / R mod p, fully reduced, for a and b below p. */
function mont(a0: number, a1: number, a2: number, b0: number, b1: number, b2: number): void {
  const p0 = P0, p1 = P1, p2 = P2, pinv = PINV
  let x0 = a0 * b0
  let m = Math.imul(x0 & M25, pinv) & M25
  let t0 = a0 * b1 + m * p1 + (x0 + m * p0) * INV_LIMB
  let t1 = a0 * b2 + m * p2
  x0 = t0 + a1 * b0
  m = Math.imul(x0 & M25, pinv) & M25
  t0 = t1 + a1 * b1 + m * p1 + (x0 + m * p0) * INV_LIMB
  t1 = a1 * b2 + m * p2
  x0 = t0 + a2 * b0
  m = Math.imul(x0 & M25, pinv) & M25
  t0 = t1 + a2 * b1 + m * p1 + (x0 + m * p0) * INV_LIMB
  t1 = a2 * b2 + m * p2
  let c = Math.floor(t0 * INV_LIMB)
  const r0 = t0 - c * LIMB
  t1 += c
  c = Math.floor(t1 * INV_LIMB)
  const r1 = t1 - c * LIMB
  const r2 = c
  // The result is below 2p: subtract p once if that stays non-negative.
  let d0 = r0 - p0, d1 = r1 - p1, d2 = r2 - p2
  if (d0 < 0) { d0 += LIMB; d1 -= 1 }
  if (d1 < 0) { d1 += LIMB; d2 -= 1 }
  if (d2 >= 0) { OUT[0] = d0; OUT[1] = d1; OUT[2] = d2 } else { OUT[0] = r0; OUT[1] = r1; OUT[2] = r2 }
}

/** (a + b) mod p for a and b below p, branch-free in int32. */
function add(a0: number, a1: number, a2: number, b0: number, b1: number, b2: number): void {
  let s0 = a0 + b0, s1 = a1 + b1, s2 = a2 + b2
  let c = s0 >> 25; s0 &= M25; s1 += c; c = s1 >> 25; s1 &= M25; s2 += c
  let t0 = s0 - P0, t1 = s1 - P1, t2 = s2 - P2
  c = t0 >> 25; t0 &= M25; t1 += c; c = t1 >> 25; t1 &= M25; t2 += c
  const k = t2 >> 31
  OUT[0] = (t0 & ~k) | (s0 & k); OUT[1] = (t1 & ~k) | (s1 & k); OUT[2] = (t2 & ~k) | (s2 & k)
}

/** (a - b) mod p for a and b below p. */
function sub(a0: number, a1: number, a2: number, b0: number, b1: number, b2: number): void {
  let t0 = a0 - b0, t1 = a1 - b1, t2 = a2 - b2
  let c = t0 >> 25; t0 &= M25; t1 += c; c = t1 >> 25; t1 &= M25; t2 += c
  const k = t2 >> 31 // all ones when negative: add p back
  let s0 = t0 + (P0 & k), s1 = t1 + (P1 & k), s2 = t2 + (P2 & k)
  c = s0 >> 25; s0 &= M25; s1 += c; c = s1 >> 25; s1 &= M25; s2 += c
  OUT[0] = s0; OUT[1] = s1; OUT[2] = s2
}

/** a / 2 mod p, the same in either domain: add p first when a is odd. */
function half(a0: number, a1: number, a2: number): void {
  if (a0 & 1) {
    a0 += P0; a1 += P1; a2 += P2
    let c = a0 >> 25; a0 &= M25; a1 += c; c = a1 >> 25; a1 &= M25; a2 += c
  }
  OUT[0] = (a0 >>> 1) | ((a1 & 1) << 24)
  OUT[1] = (a1 >>> 1) | ((a2 & 1) << 24)
  OUT[2] = a2 >>> 1
}

/** pi_p in the Montgomery domain: s(s + 1) / 2 + b with s = a + b. */
function pair(a0: number, a1: number, a2: number, b0: number, b1: number, b2: number): void {
  add(a0, a1, a2, b0, b1, b2)
  const s0 = OUT[0], s1 = OUT[1], s2 = OUT[2]
  add(s0, s1, s2, O0, O1, O2)
  mont(s0, s1, s2, OUT[0], OUT[1], OUT[2])
  half(OUT[0], OUT[1], OUT[2])
  add(OUT[0], OUT[1], OUT[2], b0, b1, b2)
}

/**
 * Loads the limbs of the odd n = hi 2^32 + lo in [2^61, 2^62) as the current
 * prime, with -n^-1 mod 2^25 and R mod n.
 */
function loadModulus(hi: number, lo: number): void {
  P0 = lo & M25
  P1 = ((lo >>> 25) | (hi << 7)) & M25
  P2 = hi >>> 18
  let inv = P0
  for (let i = 0; i < 5; i++) inv = Math.imul(inv, (2 - Math.imul(P0, inv)) | 0)
  PINV = (-inv) & M25
  // 2^62 mod n = 2^62 - n, as n > 2^61; thirteen doublings make it R = 2^75 mod n.
  let t0 = 0 - P0, t1 = 0 - P1, t2 = 4096 - P2
  let c = t0 >> 25; t0 &= M25; t1 += c; c = t1 >> 25; t1 &= M25; t2 += c
  for (let i = 0; i < 13; i++) { add(t0, t1, t2, t0, t1, t2); t0 = OUT[0]; t1 = OUT[1]; t2 = OUT[2] }
  O0 = t0; O1 = t1; O2 = t2
}

function makeContext(p: bigint): PrimeContext {
  if (p < TWO_61 || p >= 1n << 62n || (p & 1n) === 0n) throw new Error('the kernel works modulo an odd p in [2^61, 2^62)')
  loadModulus(Number(p >> 32n), Number(p & 0xffffffffn))
  const ctx: PrimeContext = { p, p0: P0, p1: P1, p2: P2, pinv: PINV, o0: O0, o1: O1, o2: O2, r0: 0, r1: 0, r2: 0 }
  // R^2 = 2^150: with x = 2^(75 + e) as a plain value, mont(x, x) = 2^(75 + 2e) and a doubling adds 1 to e.
  add(O0, O1, O2, O0, O1, O2) // e = 1
  let e0 = OUT[0], e1 = OUT[1], e2 = OUT[2]
  for (const bit of [0, 0, 1, 0, 1, 1]) { // 75 = 0b1001011, after its leading 1
    mont(e0, e1, e2, e0, e1, e2); e0 = OUT[0]; e1 = OUT[1]; e2 = OUT[2]
    if (bit) { add(e0, e1, e2, e0, e1, e2); e0 = OUT[0]; e1 = OUT[1]; e2 = OUT[2] }
  }
  ctx.r0 = e0; ctx.r1 = e1; ctx.r2 = e2
  return ctx
}

function useContext(ctx: PrimeContext): void {
  P0 = ctx.p0; P1 = ctx.p1; P2 = ctx.p2; PINV = ctx.pinv; O0 = ctx.o0; O1 = ctx.o1; O2 = ctx.o2
}

/** The plain value hi 2^32 + lo, below p, into the Montgomery domain of the current context. */
function toMont(ctx: PrimeContext, hi: number, lo: number): void {
  mont(lo & M25, ((lo >>> 25) | (hi << 7)) & M25, hi >>> 18, ctx.r0, ctx.r1, ctx.r2)
}

/** Montgomery limbs out to a plain value, as OUT limbs. */
function fromMont(a0: number, a1: number, a2: number): void {
  mont(a0, a1, a2, 1, 0, 0)
}

const limbsToBigInt = (a0: number, a1: number, a2: number): bigint => BigInt(a0) + (BigInt(a1) << 25n) + (BigInt(a2) << 50n)
const limbsHi = (a1: number, a2: number): number => ((a1 >>> 7) | (a2 << 18)) >>> 0
const limbsLo = (a0: number, a1: number): number => (a0 | (a1 << 25)) >>> 0

// Pending nodes of a fold, three limbs each, and their levels.
let STACK = new Int32Array(3 * 64)
let STACK_LEVEL = new Int32Array(64)
let DIFFS = new Int32Array(3 * 129)

function ensureStack(levels: number): void {
  if (STACK_LEVEL.length < levels) { STACK = new Int32Array(3 * levels); STACK_LEVEL = new Int32Array(levels) }
}

/** The aligned tree of height h over base, base, base + 1, ... modulo p, Montgomery in (base) and out (OUT). */
function treeM(b0: number, b1: number, b2: number, h: number): void {
  ensureStack(h + 2)
  let sp = 0
  const n = 2 ** h
  let x0 = b0, x1 = b1, x2 = b2
  for (let i = 0; i < n; i++) {
    let c0 = x0, c1 = x1, c2 = x2, l = 0
    while (sp > 0 && STACK_LEVEL[sp - 1] === l) {
      sp--
      pair(STACK[3 * sp], STACK[3 * sp + 1], STACK[3 * sp + 2], c0, c1, c2)
      c0 = OUT[0]; c1 = OUT[1]; c2 = OUT[2]; l++
    }
    STACK[3 * sp] = c0; STACK[3 * sp + 1] = c1; STACK[3 * sp + 2] = c2; STACK_LEVEL[sp] = l; sp++
    add(x0, x1, x2, O0, O1, O2); x0 = OUT[0]; x1 = OUT[1]; x2 = OUT[2]
  }
  OUT[0] = STACK[0]; OUT[1] = STACK[1]; OUT[2] = STACK[2]
}

/** The same root by the method of differences at level k, Montgomery in and out. */
function engineM(b0: number, b1: number, b2: number, h: number, k: number): void {
  if (k > h) k = h
  const d = 2 ** k
  const nodes = 2 ** (h - k)
  const n0 = Math.min(nodes, d + 1)
  if (DIFFS.length < 3 * (d + 1)) DIFFS = new Int32Array(3 * (d + 1))
  const D = DIFFS
  // The step between tabulated nodes, 2^k, in the Montgomery domain.
  let s0 = O0, s1 = O1, s2 = O2
  for (let i = 0; i < k; i++) { add(s0, s1, s2, s0, s1, s2); s0 = OUT[0]; s1 = OUT[1]; s2 = OUT[2] }
  let x0 = b0, x1 = b1, x2 = b2
  for (let j = 0; j < n0; j++) {
    treeM(x0, x1, x2, k)
    D[3 * j] = OUT[0]; D[3 * j + 1] = OUT[1]; D[3 * j + 2] = OUT[2]
    add(x0, x1, x2, s0, s1, s2); x0 = OUT[0]; x1 = OUT[1]; x2 = OUT[2]
  }
  for (let i = 1; i < n0; i++) {
    for (let j = n0 - 1; j >= i; j--) {
      sub(D[3 * j], D[3 * j + 1], D[3 * j + 2], D[3 * j - 3], D[3 * j - 2], D[3 * j - 1])
      D[3 * j] = OUT[0]; D[3 * j + 1] = OUT[1]; D[3 * j + 2] = OUT[2]
    }
  }
  for (let i = n0; i <= d; i++) { D[3 * i] = 0; D[3 * i + 1] = 0; D[3 * i + 2] = 0 }
  ensureStack(h - k + 2)
  const p0 = P0, p1 = P1, p2 = P2
  let sp = 0
  for (let j = 0; j < nodes; j++) {
    let c0 = D[0], c1 = D[1], c2 = D[2], l = 0
    while (sp > 0 && STACK_LEVEL[sp - 1] === l) {
      sp--
      pair(STACK[3 * sp], STACK[3 * sp + 1], STACK[3 * sp + 2], c0, c1, c2)
      c0 = OUT[0]; c1 = OUT[1]; c2 = OUT[2]; l++
    }
    STACK[3 * sp] = c0; STACK[3 * sp + 1] = c1; STACK[3 * sp + 2] = c2; STACK_LEVEL[sp] = l; sp++
    if (j + 1 < nodes) {
      // One row of the engine: D[i] += D[i + 1], the addition inlined.
      for (let i = 0, o = 0; i < d; i++, o += 3) {
        let u0 = D[o] + D[o + 3], u1 = D[o + 1] + D[o + 4], u2 = D[o + 2] + D[o + 5]
        let c = u0 >> 25; u0 &= M25; u1 += c; c = u1 >> 25; u1 &= M25; u2 += c
        let t0 = u0 - p0, t1 = u1 - p1, t2 = u2 - p2
        c = t0 >> 25; t0 &= M25; t1 += c; c = t1 >> 25; t1 &= M25; t2 += c
        const m = t2 >> 31
        D[o] = (t0 & ~m) | (u0 & m); D[o + 1] = (t1 & ~m) | (u1 & m); D[o + 2] = (t2 & ~m) | (u2 & m)
      }
    }
  }
  OUT[0] = STACK[0]; OUT[1] = STACK[1]; OUT[2] = STACK[2]
}

/** The base-2 strong probable prime test (5.9) for an odd n = hi 2^32 + lo in [2^61, 2^62). Loads n as the modulus. */
function sprp2(hi: number, lo: number): boolean {
  loadModulus(hi, lo)
  // n - 1 = d 2^r with d odd.
  let dlo = (lo - 1) >>> 0, dhi = hi, r = 0
  while ((dlo & 1) === 0) { dlo = ((dlo >>> 1) | ((dhi & 1) << 31)) >>> 0; dhi >>>= 1; r++ }
  // x = 2^d, left to right: the leading bit makes x = 2, then square and double on each set bit.
  const top = dhi ? 63 - Math.clz32(dhi) : 31 - Math.clz32(dlo)
  add(O0, O1, O2, O0, O1, O2)
  let x0 = OUT[0], x1 = OUT[1], x2 = OUT[2]
  for (let b = top - 1; b >= 0; b--) {
    mont(x0, x1, x2, x0, x1, x2); x0 = OUT[0]; x1 = OUT[1]; x2 = OUT[2]
    const bit = b >= 32 ? (dhi >>> (b - 32)) & 1 : (dlo >>> b) & 1
    if (bit) { add(x0, x1, x2, x0, x1, x2); x0 = OUT[0]; x1 = OUT[1]; x2 = OUT[2] }
  }
  // n - 1 in the Montgomery domain is n - R mod n.
  sub(P0, P1, P2, O0, O1, O2)
  const m0 = OUT[0], m1 = OUT[1], m2 = OUT[2]
  if ((x0 === O0 && x1 === O1 && x2 === O2) || (x0 === m0 && x1 === m1 && x2 === m2)) return true
  for (let i = 1; i < r; i++) {
    mont(x0, x1, x2, x0, x1, x2); x0 = OUT[0]; x1 = OUT[1]; x2 = OUT[2]
    if (x0 === m0 && x1 === m1 && x2 === m2) return true
  }
  return false
}

const SMALL_POW32 = SMALL_ODD_PRIMES.map((q) => 4294967296 % q)
const SMALL_REM = new Int32Array(SMALL_ODD_PRIMES.length)

/** The search of 5.9 step 4 from the odd n = hi 2^32 + lo, carrying n's small-prime remainders as n steps by 2. */
function searchPrime(hi: number, lo: number, out: WordList, j: number): void {
  const count = SMALL_ODD_PRIMES.length
  for (let i = 0; i < count; i++) {
    const q = SMALL_ODD_PRIMES[i]
    SMALL_REM[i] = ((hi % q) * SMALL_POW32[i] + (lo % q)) % q
  }
  for (;;) {
    let clear = true
    for (let i = 0; i < count; i++) if (SMALL_REM[i] === 0) { clear = false; break }
    if (clear && sprp2(hi, lo)) { out[2 * j] = hi; out[2 * j + 1] = lo; return }
    lo = (lo + 2) >>> 0
    if (lo < 2) hi++
    for (let i = 0; i < count; i++) {
      let v = SMALL_REM[i] + 2
      if (v >= SMALL_ODD_PRIMES[i]) v -= SMALL_ODD_PRIMES[i]
      SMALL_REM[i] = v
    }
  }
}

let lastContext: PrimeContext | null = null
function contextFor(p: bigint): PrimeContext {
  if (lastContext === null || lastContext.p !== p) lastContext = makeContext(p)
  useContext(lastContext)
  return lastContext
}

/** A value below p into the Montgomery domain of the current context, left in OUT. */
function enter(ctx: PrimeContext, v: bigint): void {
  toMont(ctx, Number(v >> 32n), Number(v & 0xffffffffn))
}

function rootResidueAt(p: bigint, base: bigint, height: number, k: number): bigint {
  if (!Number.isInteger(height) || height < 0 || height > MAX_RESIDUE_HEIGHT) throw new Error(`residue height ${height} out of range`)
  if (base < 0n) throw new Error('a base is a natural number')
  const ctx = contextFor(p)
  enter(ctx, base % p)
  if (height > 0) engineM(OUT[0], OUT[1], OUT[2], height, k)
  fromMont(OUT[0], OUT[1], OUT[2])
  return limbsToBigInt(OUT[0], OUT[1], OUT[2])
}

/** The pure JavaScript word kernel: Montgomery arithmetic in 25-bit limbs, the difference engine for roots. */
export const JS_WORD_KERNEL: WordKernel = Object.freeze<WordKernel>({
  name: 'js',
  searchPrimes(starts, out) {
    if (out.length !== starts.length) throw new Error('searchPrimes writes one prime per start')
    for (let j = 0; j < starts.length / 2; j++) {
      const hi = starts[2 * j], lo = starts[2 * j + 1]
      if ((lo & 1) === 0 || hi < 2 ** 29 || hi >= 2 ** 30) throw new Error('a prime search starts at an odd number in [2^61, 2^62)')
      searchPrime(hi, lo, out, j)
    }
  },
  rootResidue(p, base, height) {
    return rootResidueAt(p, base, height, height === HOP_GRIND_HEIGHT ? ATTEMPT_ENGINE_LEVEL : engineLevel(height))
  },
  pairMod(p, a, b) {
    if (a < 0n || b < 0n || a >= p || b >= p) throw new Error('pairMod takes residues below p')
    const ctx = contextFor(p)
    enter(ctx, a); const a0 = OUT[0], a1 = OUT[1], a2 = OUT[2]
    enter(ctx, b)
    pair(a0, a1, a2, OUT[0], OUT[1], OUT[2])
    fromMont(OUT[0], OUT[1], OUT[2])
    return limbsToBigInt(OUT[0], OUT[1], OUT[2])
  },
  combine(primes, parts, out) {
    const m = primes.length / 2
    if (parts.length === 0 || parts.some((part) => part.length !== primes.length) || out.length !== primes.length) {
      throw new Error('combine takes one entry per prime in every part')
    }
    for (let j = 0; j < m; j++) {
      const ctx = makeContext(wordAt(primes, j))
      const first = parts[0]
      toMont(ctx, first[2 * j], first[2 * j + 1])
      let a0 = OUT[0], a1 = OUT[1], a2 = OUT[2]
      for (let q = 1; q < parts.length; q++) {
        const part = parts[q]
        toMont(ctx, part[2 * j], part[2 * j + 1])
        pair(a0, a1, a2, OUT[0], OUT[1], OUT[2])
        a0 = OUT[0]; a1 = OUT[1]; a2 = OUT[2]
      }
      fromMont(a0, a1, a2)
      out[2 * j] = limbsHi(OUT[1], OUT[2])
      out[2 * j + 1] = limbsLo(OUT[0], OUT[1])
    }
    lastContext = null
  },
})

// ------------------------------------------------------------- the WASM word kernel
//
// src/residue/kern.ts compiled by scripts/build-kernel.mjs and committed as
// base64 in src/residue/kernWasm.ts, so tsc ships it and no consumer builds or
// fetches anything. 64-bit Montgomery arithmetic with R = 2^64, SHA-256
// compressions from midstates, and the whole prime derivation and nonce
// search inside the module. The module keeps its scratch at fixed addresses
// below 64 KiB (see kern.ts) and takes the caller's arrays from BUF up, as
// u64 words in WebAssembly's little-endian order, written through a DataView
// so nothing here depends on the platform's byte order.

interface KernExports {
  readonly memory: WebAssembly.Memory
  searchBatch(inPtr: number, outPtr: number, count: number): void
  primesBatch(midPtr: number, j0: bigint, count: number, outPtr: number): void
  residue(p: bigint, baseMod: bigint, h: number, k: number): bigint
  pairMod(p: bigint, a: bigint, b: bigint): bigint
  combineBatch(pP: number, px: number, py: number, pz: number, pt: number, out: number, m: number): void
  combine2Batch(pP: number, pa: number, pb: number, out: number, m: number): void
  grindSetup(p0: bigint, k: number, a: bigint): void
  gmidPtr(): number
  gtailPtr(): number
  gdomPtr(): number
  goutPtr(): number
  gseedPtr(): number
  gnoncePtr(): number
  lastRg(): bigint
  attempt(nonce: bigint): number
  grind(start: bigint, count: bigint): number
}

/** Where the caller's arrays start in the module's memory. */
const KERN_BUF = 1 << 20
/** Where the prime-derivation midstate goes (scratch, below the engine table). */
const KERN_PRIME_MID = 128
/** Entries per batch call, so a hop at any height needs a few MiB of module memory. */
const KERN_CHUNK = 1 << 16
/** Attempts per call of the module's grind, between progress reports. */
const KERN_GRIND_CHUNK = 4096n
/** The engine level of the attempt's height-12 tree in the module. */
const KERN_ATTEMPT_LEVEL = 4

const KERN_IMPORTS = { env: { abort: (): never => { throw new Error('the WASM word kernel aborted') } } }

let kern: KernExports | null = null
let kernLoading: Promise<WordKernel> | null = null
let kernSyncRefused = false

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

/** The committed module's bytes. Decoded here so it works the same in Node, browsers and workers. */
export function wasmWordKernelBytes(): Uint8Array {
  const s = KERN_WASM_BASE64.replace(/=+$/, '')
  const out = new Uint8Array(Math.floor((s.length * 3) / 4))
  let acc = 0, bits = 0, at = 0
  for (let i = 0; i < s.length; i++) {
    const v = B64.indexOf(s[i])
    if (v < 0) throw new Error('the committed kernel is not base64')
    acc = (acc << 6) | v
    bits += 6
    if (bits >= 8) { bits -= 8; out[at++] = (acc >> bits) & 255 }
  }
  return out
}

/** The module's bytes in an ArrayBuffer of their own, as WebAssembly takes them. */
const kernBuffer = (): ArrayBuffer => wasmWordKernelBytes().buffer as ArrayBuffer

const hasWebAssembly = (): boolean => typeof WebAssembly === 'object' && WebAssembly !== null

/**
 * The module's exports, instantiating it synchronously the first time unless
 * loadWasmWordKernel() already has. A synchronous compile works in Node, in
 * workers and in current browsers (Chromium 151 on a page's main thread
 * included); a browser may still refuse one on a page's main thread (older
 * Chromium did above 4 KB), and there the caller awaits loadWasmWordKernel().
 */
function kernExports(): KernExports {
  if (kern) return kern
  if (!hasWebAssembly()) throw new Error('WebAssembly is not available here; use JS_WORD_KERNEL')
  try {
    kern = new WebAssembly.Instance(new WebAssembly.Module(kernBuffer()), KERN_IMPORTS).exports as unknown as KernExports
  } catch (e) {
    kernSyncRefused = true
    throw new Error(`the WASM word kernel cannot be instantiated synchronously here (${String(e)}); await loadWasmWordKernel() first`)
  }
  return kern
}

/**
 * Instantiates the WASM word kernel asynchronously (WebAssembly.instantiate on
 * the committed bytes; nothing is fetched), which works on every thread of
 * every runtime that has WebAssembly. Resolves to WASM_WORD_KERNEL, ready; a
 * second call returns the first's promise. Rejects where WebAssembly is
 * missing or disabled (iOS Lockdown Mode, some locked-down WebViews), and
 * then JS_WORD_KERNEL is the kernel to use.
 */
export function loadWasmWordKernel(): Promise<WordKernel> {
  if (kern) return Promise.resolve(WASM_WORD_KERNEL)
  if (!hasWebAssembly()) return Promise.reject(new Error('WebAssembly is not available here; use JS_WORD_KERNEL'))
  kernLoading ??= WebAssembly.instantiate(kernBuffer(), KERN_IMPORTS).then(
    (source) => {
      kern ??= source.instance.exports as unknown as KernExports
      return WASM_WORD_KERNEL
    },
    (e: unknown) => {
      kernLoading = null
      throw e
    },
  )
  return kernLoading
}

/**
 * Whether WASM_WORD_KERNEL can run now: instantiated already, or
 * instantiable synchronously on this thread (tried once).
 */
export function wasmWordKernelReady(): boolean {
  if (kern) return true
  if (kernSyncRefused || !hasWebAssembly()) return false
  try {
    kernExports()
    return true
  } catch {
    return false
  }
}

export type WordKernelChoice = 'auto' | 'wasm' | 'js'

/**
 * The word kernel for a choice: `js` always JS_WORD_KERNEL; `wasm` always
 * WASM_WORD_KERNEL, throwing when it cannot run here; `auto` (every
 * function's default) WASM when it can run now and JavaScript otherwise. A
 * page that wants WASM everywhere awaits loadWasmWordKernel() once at start,
 * so `auto` finds the module ready even where a synchronous compile is
 * refused. Both kernels give identical values, so the choice changes only the
 * speed.
 */
export function selectWordKernel(choice: WordKernelChoice = 'auto'): WordKernel {
  if (choice === 'js') return JS_WORD_KERNEL
  if (choice === 'wasm') {
    kernExports()
    return WASM_WORD_KERNEL
  }
  return wasmWordKernelReady() ? WASM_WORD_KERNEL : JS_WORD_KERNEL
}

/** A DataView over the module's memory with room for `bytes` past KERN_BUF. */
function kernView(x: KernExports, bytes: number): DataView {
  const need = KERN_BUF + bytes
  const have = x.memory.buffer.byteLength
  if (have < need) x.memory.grow(Math.ceil((need - have) / 65536))
  return new DataView(x.memory.buffer)
}

/** Entries [from, from + count) of a word list into the module at `at`, as u64. */
function putWords(view: DataView, at: number, list: WordList, from: number, count: number): void {
  for (let j = 0, i = 2 * from; j < count; j++, i += 2) {
    view.setUint32(at + 8 * j, list[i + 1], true)
    view.setUint32(at + 8 * j + 4, list[i], true)
  }
}

/** `count` u64 values from the module at `at` into entries [from, from + count) of a word list. */
function getWords(view: DataView, at: number, list: WordList, from: number, count: number): void {
  for (let j = 0, i = 2 * from; j < count; j++, i += 2) {
    list[i + 1] = view.getUint32(at + 8 * j, true)
    list[i] = view.getUint32(at + 8 * j + 4, true)
  }
}

/** Big-endian 32-bit words of `bytes` (a multiple of 4) into the module at `at`, as numeric values. */
function putBigEndianWords(view: DataView, at: number, bytes: Uint8Array): void {
  const src = new DataView(bytes.buffer, bytes.byteOffset, bytes.length)
  for (let i = 0; i < bytes.length; i += 4) view.setUint32(at + i, src.getUint32(i), true)
}

/** `n` numeric words from the module at `at` as big-endian bytes. */
function getBigEndianBytes(view: DataView, at: number, n: number): Uint8Array {
  const out = new Uint8Array(4 * n)
  const dst = new DataView(out.buffer)
  for (let i = 0; i < n; i++) dst.setUint32(4 * i, view.getUint32(at + 4 * i, true))
  return out
}

function checkKernelPrime(p: bigint): void {
  if (p < TWO_61 || p >= 1n << 62n || (p & 1n) === 0n) throw new Error('the kernel works modulo an odd p in [2^61, 2^62)')
}

/**
 * Loads the attempt's fixed parts for one id and seal (5.10): the midstate of
 * the seed's first block, the seed's second block with the nonce left zero,
 * the domain of G's first block, p_0 and the price.
 */
function kernPrepareAttempts(x: KernExports, previousEventId: Uint8Array, seal: Uint8Array, p0: bigint, attempts: bigint): void {
  checkPreviousEventId(previousEventId)
  if (seal.length !== 32) throw new Error('the seal is 32 bytes')
  checkKernelPrime(p0)
  const view = kernView(x, 0)
  const mid = sha256Midstate(concatBytes(HOP_RESIDUE_GRIND_DOMAIN, previousEventId, seal.subarray(0, 1)))
  for (let i = 0; i < 8; i++) view.setUint32(x.gmidPtr() + 4 * i, mid[i], true)
  // The seed's 103 bytes end in one block: seal[1..31], be64(nonce), 0x80, zeros, the length in bits.
  const tail = new Uint8Array(64)
  tail.set(seal.subarray(1), 0)
  tail[39] = 0x80
  new DataView(tail.buffer).setUint32(60, (HOP_RESIDUE_GRIND_DOMAIN.length + 32 + 32 + 8) * 8)
  putBigEndianWords(view, x.gtailPtr(), tail)
  const dom = new Uint8Array(32)
  dom.set(HOP_RESIDUE_GRIND_DOMAIN, 0)
  putBigEndianWords(view, x.gdomPtr(), dom)
  x.grindSetup(p0, KERN_ATTEMPT_LEVEL, attempts)
}

/** The attempt the module just made, read back. */
function kernLastAttempt(x: KernExports): HopAttempt {
  const view = kernView(x, 0)
  const seed = getBigEndianBytes(view, x.gseedPtr(), 8)
  const gBase = ((bytesToBigInt(seed) & AXIS_MASK) >> BigInt(HOP_GRIND_HEIGHT)) << BigInt(HOP_GRIND_HEIGHT)
  return { seed, gBase, rG: x.lastRg(), G: getBigEndianBytes(view, x.goutPtr(), 8) }
}

/**
 * The WASM word kernel: src/residue/kern.ts, 64-bit Montgomery arithmetic in
 * WebAssembly, with the prime derivation, the attempt and the nonce search
 * done whole inside the module. Instantiated on first use (synchronously), or
 * ahead of time by loadWasmWordKernel(). Gives exactly JS_WORD_KERNEL's
 * values, several times faster.
 */
export const WASM_WORD_KERNEL: WordKernel = Object.freeze<WordKernel>({
  name: 'wasm',
  searchPrimes(starts, out) {
    if (out.length !== starts.length) throw new Error('searchPrimes writes one prime per start')
    const x = kernExports()
    const m = starts.length / 2
    for (let j = 0; j < m; j++) {
      const hi = starts[2 * j], lo = starts[2 * j + 1]
      if ((lo & 1) === 0 || hi < 2 ** 29 || hi >= 2 ** 30) throw new Error('a prime search starts at an odd number in [2^61, 2^62)')
    }
    for (let j0 = 0; j0 < m; j0 += KERN_CHUNK) {
      const count = Math.min(KERN_CHUNK, m - j0)
      let view = kernView(x, 16 * count)
      putWords(view, KERN_BUF, starts, j0, count)
      x.searchBatch(KERN_BUF, KERN_BUF + 8 * count, count)
      view = kernView(x, 16 * count)
      getWords(view, KERN_BUF + 8 * count, out, j0, count)
    }
  },
  rootResidue(p, base, height) {
    if (!Number.isInteger(height) || height < 0 || height > MAX_RESIDUE_HEIGHT) throw new Error(`residue height ${height} out of range`)
    if (base < 0n) throw new Error('a base is a natural number')
    checkKernelPrime(p)
    const k = height === HOP_GRIND_HEIGHT ? KERN_ATTEMPT_LEVEL : engineLevel(height)
    return kernExports().residue(p, base % p, height, k)
  },
  pairMod(p, a, b) {
    checkKernelPrime(p)
    if (a < 0n || b < 0n || a >= p || b >= p) throw new Error('pairMod takes residues below p')
    return kernExports().pairMod(p, a, b)
  },
  combine(primes, parts, out) {
    const m = primes.length / 2
    if (parts.length === 0 || parts.some((part) => part.length !== primes.length) || out.length !== primes.length) {
      throw new Error('combine takes one entry per prime in every part')
    }
    const x = kernExports()
    const n = parts.length
    for (let j0 = 0; j0 < m; j0 += KERN_CHUNK) {
      const count = Math.min(KERN_CHUNK, m - j0)
      const at = (slot: number): number => KERN_BUF + 8 * count * slot
      let view = kernView(x, 8 * count * (n === 4 ? 6 : 3))
      putWords(view, at(0), primes, j0, count)
      if (n === 4) {
        for (let q = 0; q < 4; q++) putWords(view, at(1 + q), parts[q], j0, count)
        x.combineBatch(at(0), at(1), at(2), at(3), at(4), at(5), count)
        view = kernView(x, 8 * count * 6)
        getWords(view, at(5), out, j0, count)
        continue
      }
      // Any other number of parts: fold from the left, the running value in slot 1.
      putWords(view, at(1), parts[0], j0, count)
      for (let q = 1; q < n; q++) {
        view = kernView(x, 8 * count * 3)
        putWords(view, at(2), parts[q], j0, count)
        x.combine2Batch(at(0), at(1), at(2), at(1), count)
      }
      view = kernView(x, 8 * count * 3)
      getWords(view, at(1), out, j0, count)
    }
  },
  hopPrimes(previousEventId, out) {
    checkPreviousEventId(previousEventId)
    const m = out.length / 2
    if (!Number.isSafeInteger(m) || m < 1) throw new Error('the residue count is a positive integer')
    const x = kernExports()
    // Every index below 2^53 has 0 as the first byte of be64(j): one midstate for the whole list.
    const mid = sha256Midstate(concatBytes(HOP_RESIDUE_PRIME_DOMAIN, previousEventId, new Uint8Array(1)))
    for (let j0 = 0; j0 < m; j0 += KERN_CHUNK) {
      const count = Math.min(KERN_CHUNK, m - j0)
      let view = kernView(x, 8 * count)
      for (let i = 0; i < 8; i++) view.setUint32(KERN_PRIME_MID + 4 * i, mid[i], true)
      x.primesBatch(KERN_PRIME_MID, BigInt(j0), count, KERN_BUF)
      view = kernView(x, 8 * count)
      getWords(view, KERN_BUF, out, j0, count)
    }
  },
  attempt(previousEventId, seal, nonce, p0) {
    checkNonce(nonce)
    const x = kernExports()
    kernPrepareAttempts(x, previousEventId, seal, p0, 1n)
    x.attempt(nonce)
    return kernLastAttempt(x)
  },
  findNonce(previousEventId, seal, attempts, p0, start, end) {
    if (start < 0n || end > TWO_64 || start > end) throw new Error('the nonce range must lie within 0 .. 2^64')
    if (attempts < 1n) throw new Error('the price is at least one attempt')
    // A price of 2^64 attempts or more does not fit the module's u64: the composed search takes it.
    if (attempts >= TWO_64) return searchNonces(seedHasher(previousEventId, seal), p0, attempts, start, end, WASM_WORD_KERNEL)
    const x = kernExports()
    kernPrepareAttempts(x, previousEventId, seal, p0, attempts)
    for (let s = start; s < end; s += KERN_GRIND_CHUNK) {
      const count = end - s < KERN_GRIND_CHUNK ? end - s : KERN_GRIND_CHUNK
      if (x.grind(s, count) === 1) {
        const view = kernView(x, 0)
        return { nonce: view.getBigUint64(x.gnoncePtr(), true), attempt: kernLastAttempt(x) }
      }
    }
    return null
  },
})

// ------------------------------------------------------------- the native BigInt backend

function toBigInts(list: WordList): bigint[] {
  const out: bigint[] = new Array(list.length / 2)
  for (let j = 0; j < out.length; j++) out[j] = wordAt(list, j)
  return out
}

/** Native BigInt: the Cantor trees of movement.ts, and the product and remainder trees in plain BigInt. */
export const BIGINT_BACKEND: BigBackend<bigint> = Object.freeze<BigBackend<bigint>>({
  name: 'bigint',
  fromBigInt: (v) => v,
  toBigInt: (v) => v,
  subtreeCantor: (base, height, maxComputeHeight, onProgress) => computeSubtreeCantor(base, height, maxComputeHeight, onProgress),
  pair: cantorPair,
  productTree(primes) {
    const levels: bigint[][] = [toBigInts(primes)]
    while (levels[levels.length - 1].length > 1) {
      const below = levels[levels.length - 1]
      const next: bigint[] = new Array((below.length + 1) >> 1)
      for (let i = 0; i < next.length; i++) next[i] = 2 * i + 1 < below.length ? below[2 * i] * below[2 * i + 1] : below[2 * i]
      levels.push(next)
    }
    return { levels }
  },
  pairModQ(tree, a, b) {
    const Q = tree.levels[tree.levels.length - 1][0]
    const ra = a < Q ? a : a % Q
    const rb = b < Q ? b : b % Q
    // Q is odd, so s(s + 1) / 2 modulo Q depends only on s modulo Q.
    const s = (ra + rb) % Q
    return (((s * (s + 1n)) >> 1n) + rb) % Q
  },
  remainders(tree, x, out) {
    const levels = tree.levels
    const top = levels.length - 1
    const primes = levels[0]
    if (out.length !== 2 * primes.length) throw new Error('remainders writes one residue per prime')
    // Node i of level l covers primes i 2^l to (i + 1) 2^l - 1; descend to
    // level 2, then reduce each prime directly from its group of four.
    let current = [x < levels[top][0] ? x : x % levels[top][0]]
    let lowest = top
    for (let l = top - 1; l >= 2; l--) {
      const nodes = levels[l]
      const next: bigint[] = new Array(nodes.length)
      for (let i = 0; i < nodes.length; i++) {
        const v = current[Math.floor(i / 2)]
        next[i] = v < nodes[i] ? v : v % nodes[i]
      }
      current = next
      lowest = l
    }
    for (let j = 0; j < primes.length; j++) setWord(out, j, current[Math.floor(j / 2 ** lowest)] % primes[j])
  },
})

// ------------------------------------------------------------- the hop primes (5.9)

/** The prime-derivation midstate, over the domain, the id and the first byte of be64(j), for one id and that byte. */
let primeMidstateKey = ''
let primeMidstate: Uint32Array | null = null
function primeMidstateFor(previousEventId: Uint8Array, topByte: number): Uint32Array {
  const key = bytesToHex(previousEventId) + topByte
  if (primeMidstate === null || primeMidstateKey !== key) {
    primeMidstate = sha256Midstate(concatBytes(HOP_RESIDUE_PRIME_DOMAIN, previousEventId, new Uint8Array([topByte])))
    primeMidstateKey = key
  }
  return primeMidstate
}

/**
 * Where the search for p_j starts (5.9 steps 1 to 3): the first 8 bytes of
 * SHA256(domain || previous_event_id || be64(j)), shifted right 4 bits, plus
 * 2^61, made odd. The 71-byte preimage is two compressions; the first block
 * ends with the first byte of be64(j), so its midstate serves every j below
 * 2^56.
 */
export function hopPrimeStart(previousEventId: Uint8Array, j: bigint | number): bigint {
  checkPreviousEventId(previousEventId)
  const index = be64(j)
  const digest = sha256FromMidstate(primeMidstateFor(previousEventId, index[0]), index.subarray(1))
  const x = new DataView(digest.buffer).getBigUint64(0) >> 4n
  return (TWO_61 + x) | 1n
}

/** p_j (5.9): the prime search from hopPrimeStart. Never deduplicated across indices. */
export function hopPrime(previousEventId: Uint8Array, j: bigint | number, kernel: WordKernel = selectWordKernel()): bigint {
  const starts = wordList(1)
  setWord(starts, 0, hopPrimeStart(previousEventId, j))
  const out = wordList(1)
  kernel.searchPrimes(starts, out)
  return wordAt(out, 0)
}

/** p_0 to p_(m-1), in one batch through the kernel. */
export function deriveHopPrimes(previousEventId: Uint8Array, m: number, kernel: WordKernel = selectWordKernel()): WordList {
  checkPreviousEventId(previousEventId)
  if (!Number.isSafeInteger(m) || m < 1) throw new Error('the residue count is a positive integer')
  if (kernel.hopPrimes) {
    const primes = wordList(m)
    kernel.hopPrimes(previousEventId, primes)
    return primes
  }
  const starts = wordList(m)
  const tail = new Uint8Array(7)
  const mid = primeMidstateFor(previousEventId, 0)
  for (let j = 0; j < m; j++) {
    // be64(j) for j below 2^53: the top byte is 0, and the tail is its last 7 bytes.
    let v = j
    for (let i = 6; i >= 0; i--) { tail[i] = v % 256; v = Math.floor(v / 256) }
    const digest = sha256FromMidstate(mid, tail)
    const view = new DataView(digest.buffer)
    const h32 = view.getUint32(0), l32 = view.getUint32(4)
    starts[2 * j] = 2 ** 29 + (h32 >>> 4)
    starts[2 * j + 1] = (((h32 & 15) << 28) | (l32 >>> 4) | 1) >>> 0
  }
  const out = wordList(m)
  kernel.searchPrimes(starts, out)
  return out
}

// ------------------------------------------------------------- geometry: everything derived from the event (5.11 step 1)

/** One aligned tree of a hop: its base and its height. */
export interface HopTree {
  base: bigint
  height: number
}

export interface HopGeometry {
  /** The three axis trees, x, y, z (4.4, 4.5). */
  axes: [HopTree, HopTree, HopTree]
  /** The temporal tree: t_base and K (5.2, 5.3). */
  temporal: HopTree
  /** K, the terrain height at the destination, plane bit included. */
  K: number
  /** t = previous_event_id mod 2^85 (5.3), before alignment. */
  temporalSeed: bigint
  /** The largest of the three axis heights and K. */
  hMax: number
  /** m, the residue count (5.9). */
  m: bigint
  /** m / RESIDUE_BLOCK leaves before padding. */
  blocks: bigint
  /** Levels of the seal's tree above its leaves (5.10). */
  depth: number
  /** A, the re-roll price in attempts (5.10). */
  A: bigint
}

/** m (5.9): enough 61-bit primes for Q to span a quarter of an 85 2^h_max bit root, in whole blocks of 8. */
export function hopResidueCount(hMax: number): bigint {
  if (!Number.isInteger(hMax) || hMax < 0) throw new Error('h_max is a natural number')
  const divisor = BigInt(WIDTH_DIVISOR * PRIME_BITS)
  const raw = ((BigInt(AXIS_BITS) << BigInt(hMax)) + divisor - 1n) / divisor
  const block = BigInt(RESIDUE_BLOCK)
  const m = ((raw + block - 1n) / block) * block
  return m > block ? m : block
}

/** depth (5.10): the smallest d with 2^d >= m / RESIDUE_BLOCK. */
export function hopMerkleDepth(m: bigint): number {
  const blocks = m / BigInt(RESIDUE_BLOCK)
  let depth = 0
  while ((1n << BigInt(depth)) < blocks) depth++
  return depth
}

/** Characters of the `mp` tag at a depth (8.4): HOP_SAMPLES (128 + 64 depth). */
export function hopOpeningsLength(depth: number): number {
  return HOP_SAMPLES * (RESIDUE_BLOCK * RESIDUE_HEX + SIBLING_HEX * depth)
}

/** B(h) (5.10): the table for h <= 22, and floor(223681 9^(h-22) / 4^(h-22)) above, in exact integers. */
export function hopRerollBudget(h: number): bigint {
  if (!Number.isInteger(h) || h < 0) throw new Error('a height is a natural number')
  if (h < HOP_REROLL_BUDGET.length) return HOP_REROLL_BUDGET[h]
  const n = BigInt(h - (HOP_REROLL_BUDGET.length - 1))
  return (HOP_REROLL_BUDGET[HOP_REROLL_BUDGET.length - 1] * 9n ** n) / 4n ** n
}

/** A (5.10): the budgets of the three axis heights and K, summed, and at least 1. */
export function hopRerollAttempts(heights: readonly number[]): bigint {
  const sum = heights.reduce((s, h) => s + hopRerollBudget(h), 0n)
  return sum > 1n ? sum : 1n
}

/**
 * Everything a verifier derives from the event (5.11 step 1, 8.7.1 steps 1
 * to 6), taking nothing from the prover: each axis's height and base from the
 * source and destination, K from the destination including its plane bit,
 * t_base from previous_event_id and K, and from those h_max, m, depth and A.
 */
export function hopGeometry(previousEventId: Uint8Array, from: Xyz, to: Xyz): HopGeometry {
  checkPreviousEventId(previousEventId)
  const tree = (v1: bigint, v2: bigint): HopTree => {
    const height = findLcaHeight(v1, v2)
    return { base: alignedBase(v1, height), height }
  }
  const axes: [HopTree, HopTree, HopTree] = [tree(from.x, to.x), tree(from.y, to.y), tree(from.z, to.z)]
  const K = terrainK(to.x, to.y, to.z, to.plane)
  const temporalSeed = bytesToBigInt(previousEventId) & AXIS_MASK
  const temporal: HopTree = { base: alignedBase(temporalSeed, K), height: K }
  const heights = [...axes.map((a) => a.height), K]
  const hMax = Math.max(...heights)
  const m = hopResidueCount(hMax)
  return {
    axes,
    temporal,
    K,
    temporalSeed,
    hMax,
    m,
    blocks: m / BigInt(RESIDUE_BLOCK),
    depth: hopMerkleDepth(m),
    A: hopRerollAttempts(heights),
  }
}

/** Each root modulo p and hop_n modulo p (5.9), from the geometry alone: no root, no region_n, no hop_n. */
export interface HopRootResidues {
  x: bigint
  y: bigint
  z: bigint
  t: bigint
  /** pi_p(pi_p(pi_p(x, y), z), t), which is hop_n mod p. */
  hopN: bigint
}

export function hopRootResidues(geometry: HopGeometry, p: bigint, kernel: WordKernel = selectWordKernel()): HopRootResidues {
  const [ax, ay, az] = geometry.axes
  const x = kernel.rootResidue(p, ax.base, ax.height)
  const y = kernel.rootResidue(p, ay.base, ay.height)
  const z = kernel.rootResidue(p, az.base, az.height)
  const t = kernel.rootResidue(p, geometry.temporal.base, geometry.temporal.height)
  const hopN = kernel.pairMod(p, kernel.pairMod(p, kernel.pairMod(p, x, y), z), t)
  return { x, y, z, t, hopN }
}

/** hop_n mod p (5.9, 5.11 step 5), in word arithmetic. */
export function hopResidue(geometry: HopGeometry, p: bigint, kernel: WordKernel = selectWordKernel()): bigint {
  return hopRootResidues(geometry, p, kernel).hopN
}

// ------------------------------------------------------------- leaves, seal and openings (5.10)

/** leaf_b = SHA256(LEAF_DOMAIN || previous_event_id || be64(b) || be64(r_8b) || ... || be64(r_8b+7)). */
export function hopLeafHash(previousEventId: Uint8Array, block: bigint | number, residues: readonly bigint[]): Uint8Array {
  checkPreviousEventId(previousEventId)
  if (residues.length !== RESIDUE_BLOCK) throw new Error('a leaf holds exactly one block of 8 residues')
  return sha256(concatBytes(HOP_RESIDUE_LEAF_DOMAIN, previousEventId, be64(block), ...residues.map((r) => be64(r))))
}

/** parent = SHA256(left || right). */
function parentOf(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concatBytes(left, right))
}

/** The seal's tree: every level packed 32 bytes per node, leaves first (padded with PAD_LEAF), the seal last. */
export interface HopSealTree {
  seal: Uint8Array
  levels: Uint8Array[]
}

/** The seal over a list of residues (5.10), keeping every level so any block can be opened. */
export function hopSealTree(previousEventId: Uint8Array, residues: WordList): HopSealTree {
  checkPreviousEventId(previousEventId)
  const m = residues.length / 2
  if (m < RESIDUE_BLOCK || m % RESIDUE_BLOCK !== 0) throw new Error('the residues come in whole blocks of 8')
  const blocks = m / RESIDUE_BLOCK
  const width = 2 ** hopMerkleDepth(BigInt(m))
  const leaves = new Uint8Array(32 * width) // the padding leaves are PAD_LEAF, 32 zero bytes, already
  const preimage = new Uint8Array(HOP_RESIDUE_LEAF_DOMAIN.length + 32 + 8 + 8 * RESIDUE_BLOCK)
  preimage.set(HOP_RESIDUE_LEAF_DOMAIN, 0)
  preimage.set(previousEventId, HOP_RESIDUE_LEAF_DOMAIN.length)
  const view = new DataView(preimage.buffer)
  const at = HOP_RESIDUE_LEAF_DOMAIN.length + 32
  for (let b = 0; b < blocks; b++) {
    view.setUint32(at, Math.floor(b / 2 ** 32))
    view.setUint32(at + 4, b >>> 0)
    for (let k = 0; k < 2 * RESIDUE_BLOCK; k++) view.setUint32(at + 8 + 4 * k, residues[2 * RESIDUE_BLOCK * b + k])
    leaves.set(sha256(preimage), 32 * b)
  }
  const levels = [leaves]
  let below = leaves
  for (let n = width; n > 1; n /= 2) {
    const level = new Uint8Array(16 * n)
    for (let i = 0; i < n / 2; i++) level.set(sha256(below.subarray(64 * i, 64 * i + 64)), 32 * i)
    levels.push(level)
    below = level
  }
  return { seal: below.slice(0, 32), levels }
}

/** One opening (5.10): a block's 8 residues and the siblings from its leaf up to the seal. */
export interface HopOpening {
  residues: bigint[]
  siblings: Uint8Array[]
}

/** The opening of block `block` from the seal's tree. */
export function openHopBlock(tree: HopSealTree, residues: WordList, block: number): HopOpening {
  const values: bigint[] = []
  for (let k = 0; k < RESIDUE_BLOCK; k++) values.push(wordAt(residues, block * RESIDUE_BLOCK + k))
  const siblings: Uint8Array[] = []
  let i = block
  for (let l = 0; l < tree.levels.length - 1; l++) {
    const s = i ^ 1
    siblings.push(tree.levels[l].slice(32 * s, 32 * s + 32))
    i = Math.floor(i / 2)
  }
  return { residues: values, siblings }
}

/**
 * Whether `siblings` carry `leaf`, at block position `position`, up to `seal`:
 * an even position is a left child and an odd one a right child, and the
 * position halves at each level up (5.10).
 */
export function verifyHopPath(leaf: Uint8Array, position: bigint, siblings: readonly Uint8Array[], seal: Uint8Array): boolean {
  let cur = leaf
  let i = position
  for (const sibling of siblings) {
    cur = (i & 1n) === 0n ? parentOf(cur, sibling) : parentOf(sibling, cur)
    i >>= 1n
  }
  return bytesToHex(cur) === bytesToHex(seal)
}

// ------------------------------------------------------------- the attempt, the price and the draw (5.10)

/** One re-roll attempt, with its parts. */
export interface HopAttempt {
  /** SHA256(GRIND_DOMAIN || previous_event_id || seal || be64(nonce)). */
  seed: Uint8Array
  /** ((int(seed) mod 2^85) >> 12) << 12. */
  gBase: bigint
  /** compute_subtree_cantor(g_base, 12) mod p_0. */
  rG: bigint
  /** SHA256(GRIND_DOMAIN || seed || be64(r_g)). */
  G: Uint8Array
}

/**
 * The seed's first block is the domain, the id and the first byte of the
 * seal, which no nonce changes, so one midstate serves a whole search and each
 * seed costs one compression.
 */
function seedHasher(previousEventId: Uint8Array, seal: Uint8Array): (nonce: bigint) => Uint8Array {
  checkPreviousEventId(previousEventId)
  if (seal.length !== 32) throw new Error('the seal is 32 bytes')
  const mid = sha256Midstate(concatBytes(HOP_RESIDUE_GRIND_DOMAIN, previousEventId, seal.subarray(0, 1)))
  const tail = new Uint8Array(31 + 8)
  tail.set(seal.subarray(1), 0)
  const view = new DataView(tail.buffer)
  return (nonce) => {
    view.setBigUint64(31, nonce)
    return sha256FromMidstate(mid, tail)
  }
}

function checkNonce(nonce: bigint): void {
  if (nonce < 0n || nonce >= TWO_64) throw new Error('the nonce is an unsigned 64-bit integer')
}

function attemptFrom(seed: Uint8Array, p0: bigint, kernel: WordKernel): HopAttempt {
  const gBase = ((bytesToBigInt(seed) & AXIS_MASK) >> BigInt(HOP_GRIND_HEIGHT)) << BigInt(HOP_GRIND_HEIGHT)
  const rG = kernel.rootResidue(p0, gBase, HOP_GRIND_HEIGHT)
  const G = sha256(concatBytes(HOP_RESIDUE_GRIND_DOMAIN, seed, be64(rG)))
  return { seed, gBase, rG, G }
}

/** One attempt (5.10) for `nonce` under a seal, its cost one aligned height-12 tree modulo p_0. */
export function hopAttempt(previousEventId: Uint8Array, seal: Uint8Array, nonce: bigint, p0: bigint, kernel: WordKernel = selectWordKernel()): HopAttempt {
  checkNonce(nonce)
  if (kernel.attempt) return kernel.attempt(previousEventId, seal, nonce, p0)
  return attemptFrom(seedHasher(previousEventId, seal)(nonce), p0, kernel)
}

export interface HopNonce {
  nonce: bigint
  attempt: HopAttempt
}

/**
 * The first nonce from `start` upward and below `end` whose G meets the price
 * A (G A < 2^256, 5.10), or null when that range holds none. Any such nonce
 * verifies, so a caller can split the search over workers by giving each a
 * disjoint range. The golden vectors take the first from 0.
 */
export function findHopNonce(
  previousEventId: Uint8Array,
  seal: Uint8Array,
  attempts: bigint,
  p0: bigint,
  kernel: WordKernel = selectWordKernel(),
  search: NonceSearch = {},
): HopNonce | null {
  const { start = 0n, end = TWO_64, onProgress } = search
  if (start < 0n || end > TWO_64 || start > end) throw new Error('the nonce range must lie within 0 .. 2^64')
  if (attempts < 1n) throw new Error('the price is at least one attempt')
  const expected = Number(attempts)
  const tickEvery = Math.max(1, Math.floor(expected / 64))
  const tick = onProgress && ((tried: number): void => {
    if (tried % tickEvery === 0) onProgress(-Math.expm1(-tried / expected))
  })
  let found: HopNonce | null = null
  if (kernel.findNonce) {
    // The kernel searches whole ranges; with a progress bar, ranges of tickEvery attempts.
    const chunk = tick ? BigInt(tickEvery) : end - start
    let tried = 0
    for (let s = start; s < end && found === null; s += chunk) {
      const e = end - s < chunk ? end : s + chunk
      found = kernel.findNonce(previousEventId, seal, attempts, p0, s, e)
      tried += Number(e - s)
      if (found === null) tick?.(tried)
    }
  } else {
    found = searchNonces(seedHasher(previousEventId, seal), p0, attempts, start, end, kernel, tick || undefined)
  }
  if (found !== null) onProgress?.(1)
  return found
}

/** The nonce search composed from the kernel's rootResidue and SHA-256 here, one attempt at a time. */
function searchNonces(
  seedOf: (nonce: bigint) => Uint8Array,
  p0: bigint,
  attempts: bigint,
  start: bigint,
  end: bigint,
  kernel: WordKernel,
  onTried?: (tried: number) => void,
): HopNonce | null {
  let tried = 0
  for (let nonce = start; nonce < end; nonce++) {
    const attempt = attemptFrom(seedOf(nonce), p0, kernel)
    if (meetsPrice(attempt.G, attempts)) return { nonce, attempt }
    onTried?.(++tried)
  }
  return null
}

/** The draw (5.10): idx_i = int(SHA256(SAMPLE_DOMAIN || G || be32(i))) mod m, for i in 0..15, collisions kept. */
export function hopSampleIndices(G: Uint8Array, m: bigint): bigint[] {
  if (G.length !== 32) throw new Error('G is 32 bytes')
  if (m < 1n) throw new Error('m is positive')
  const out: bigint[] = []
  for (let i = 0; i < HOP_SAMPLES; i++) out.push(bytesToBigInt(sha256(concatBytes(HOP_RESIDUE_SAMPLE_DOMAIN, G, be32(i)))) % m)
  return out
}

// ------------------------------------------------------------- tags (8.4)

/** The `proof` tag's value for a seal: 64 lowercase hex characters. */
export function encodeSeal(seal: Uint8Array): string {
  if (seal.length !== 32) throw new Error('the seal is 32 bytes')
  return bytesToHex(seal)
}

/** The seal in a `proof` tag's value, or null unless it is exactly 64 lowercase hex characters. */
export function decodeSeal(hex: string): Uint8Array | null {
  return typeof hex === 'string' && HEX64.test(hex) ? hexToBytes(hex) : null
}

/** The `mn` tag's value: the nonce as exactly 16 lowercase hex characters, big-endian (8.4). */
export const encodeHopNonce = encodeNonce

/** The nonce in an `mn` tag's value, or null unless it is exactly 16 lowercase hex characters (8.4). */
export function decodeHopNonce(hex: string): bigint | null {
  return typeof hex === 'string' ? decodeNonce(hex) : null
}

/**
 * The `mp` tag's value (8.4): the openings in draw order with no separators,
 * each its block's 8 residues as 16 hex characters then its siblings from the
 * leaf level up as 64 hex characters.
 */
export function encodeHopOpenings(openings: readonly HopOpening[]): string {
  let out = ''
  for (const { residues, siblings } of openings) {
    if (residues.length !== RESIDUE_BLOCK) throw new Error('an opening holds one block of 8 residues')
    for (const r of residues) out += bytesToHex(be64(r))
    for (const s of siblings) {
      if (s.length !== 32) throw new Error('a sibling is 32 bytes')
      out += bytesToHex(s)
    }
  }
  return out
}

/**
 * The openings in an `mp` tag's value for a hop of Merkle depth `depth`, or
 * null when it is malformed (8.4): anything but exactly HOP_SAMPLES (128 + 64
 * depth) characters of 0-9 and a-f. No prefix, sign, separator, space or
 * uppercase letter is read past.
 */
export function decodeHopOpenings(mp: string, depth: number): HopOpening[] | null {
  if (typeof mp !== 'string' || mp.length !== hopOpeningsLength(depth) || !LOWER_HEX.test(mp)) return null
  const width = RESIDUE_BLOCK * RESIDUE_HEX + SIBLING_HEX * depth
  const out: HopOpening[] = []
  for (let k = 0; k < HOP_SAMPLES; k++) {
    const at = k * width
    const residues: bigint[] = []
    for (let i = 0; i < RESIDUE_BLOCK; i++) residues.push(BigInt('0x' + mp.slice(at + RESIDUE_HEX * i, at + RESIDUE_HEX * (i + 1))))
    const siblings: Uint8Array[] = []
    const off = at + RESIDUE_BLOCK * RESIDUE_HEX
    for (let d = 0; d < depth; d++) siblings.push(hexToBytes(mp.slice(off + SIBLING_HEX * d, off + SIBLING_HEX * (d + 1))))
    out.push({ residues, siblings })
  }
  return out
}

// ------------------------------------------------------------- the version 1 exemption list (5.13)

/**
 * One line of an exemption list (5.13, the format of 6.16): an empty line, a
 * comment starting with # in its first column, or a 64-character lowercase hex
 * event id at the start of the line, followed by nothing or by a space or tab
 * and commentary. Anything else (leading whitespace, an indented #, a line of
 * only whitespace, a carriage return) is refused, so this never accepts an id
 * that a port reading the format strictly would not. scripts/grandfathered.mjs
 * applies the same rule.
 */
const LIST_ENTRY = /^([0-9a-f]{64})(?:[ \t].*)?$/

/**
 * The ids in the text of a list in the format of grandfathered-v1-hops.txt.
 * Throws on any line that is not empty, a comment or an entry, and on an id
 * listed twice, as the generator does.
 */
export function parseGrandfatheredList(text: string): Set<string> {
  const ids = new Set<string>()
  text.split('\n').forEach((line, n) => {
    if (line === '' || line.startsWith('#')) return
    const entry = LIST_ENTRY.exec(line)
    if (!entry) throw new Error(`line ${n + 1} is not empty, a comment or a 64-hex event id at the start of the line: ${JSON.stringify(line)}`)
    if (ids.has(entry[1])) throw new Error(`line ${n + 1} lists ${entry[1]} twice`)
    ids.add(entry[1])
  })
  return ids
}

/** Whether an event is one of the version 1 hops exempt under spec 5.13, against `list` (the generated one by default). */
export function isGrandfatheredV1Hop(eventId: string | undefined, list: ReadonlySet<string> = GRANDFATHERED_V1_HOPS): boolean {
  return eventId !== undefined && list.has(eventId)
}

// ------------------------------------------------------------- the prover (5.9, 5.10)

/** The exact roots of a hop, in the backend's type. */
export interface HopRoots<N = bigint> {
  x: N
  y: N
  z: N
  /** cantor_t, the temporal root. */
  t: N
}

export interface HopResidueOptions<N = bigint> {
  kernel?: WordKernel
  backend?: BigBackend<N>
  /** Where the nonce search starts and ends; by default from 0, as in the golden vectors. */
  nonceSearch?: Omit<NonceSearch, 'onProgress'>
  onProgress?: ProgressFn
}

/** What the prover produces: the list it keeps, and the three tags it publishes. */
export interface HopResidueProof {
  /** p_0 to p_(m-1). */
  primes: WordList
  /** r_j = hop_n mod p_j. */
  residues: WordList
  seal: Uint8Array
  nonce: bigint
  /** The attempt whose nonce meets the price. */
  attempt: HopAttempt
  indices: bigint[]
  openings: HopOpening[]
  tags: { proof: string; mn: string; mp: string }
}

/**
 * Every residue r_j = hop_n mod p_j without hop_n (5.9), in the order the
 * reference's fast prover takes: the product tree once; the three axis roots
 * reduced modulo Q and paired modulo Q into region_n mod Q; one descent of the
 * remainder tree for it and one for the temporal root (a K = 0 root is t_base,
 * a word or two, reduced directly); then the temporal residues paired in,
 * modulo each prime. A still axis is a trivial tree whose root is its base,
 * so a single-axis hop takes the same path. Every big-number step goes
 * through `backend`; the roots stay the caller's, and the product tree and
 * the values modulo Q are released here (BigBackend.release).
 */
export function computeHopResidues<N>(
  primes: WordList,
  geometry: HopGeometry,
  roots: HopRoots<N>,
  kernel: WordKernel,
  backend: BigBackend<N>,
  onProgress?: ProgressFn,
): WordList {
  const m = primes.length / 2
  const regionResidues = wordList(m)
  const temporalResidues = wordList(m)
  const tree = backend.productTree(primes)
  try {
    onProgress?.(0.25)
    const xy = backend.pairModQ(tree, roots.x, roots.y)
    let region: N
    try {
      region = backend.pairModQ(tree, xy, roots.z)
    } finally {
      backend.release?.(xy)
    }
    try {
      backend.remainders(tree, region, regionResidues)
    } finally {
      backend.release?.(region)
    }
    onProgress?.(0.6)
    if (geometry.temporal.height > 0) backend.remainders(tree, roots.t, temporalResidues)
    else {
      const t = backend.toBigInt(roots.t)
      for (let j = 0; j < m; j++) setWord(temporalResidues, j, t % wordAt(primes, j))
    }
  } finally {
    backend.releaseTree?.(tree)
  }
  onProgress?.(0.85)
  const residues = wordList(m)
  kernel.combine(primes, [regionResidues, temporalResidues], residues)
  onProgress?.(1)
  return residues
}

/**
 * The residue extension of a hop (5.9, 5.10), given the roots the hop builds
 * anyway: derive the primes, compute every residue, seal, grind the nonce,
 * open the 16 drawn blocks. Bit for bit the reference's output.
 */
export function proveHopResidues<N = bigint>(
  previousEventId: Uint8Array,
  geometry: HopGeometry,
  roots: HopRoots<N>,
  options: HopResidueOptions<N> = {},
): HopResidueProof {
  const kernel = options.kernel ?? selectWordKernel()
  const backend = options.backend ?? (BIGINT_BACKEND as unknown as BigBackend<N>)
  if (geometry.m > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('a residue list this long cannot be held')
  const m = Number(geometry.m)
  const onProgress = options.onProgress
  // Weights of the phases in the bar, from where the time goes in this kernel.
  const weights = [3, 4, 1, 2, 0.2]
  const total = weights.reduce((a, b) => a + b, 0)
  let done = 0
  const phase = (i: number): ProgressFn | undefined => {
    if (!onProgress) return undefined
    const start = done / total
    const share = weights[i] / total
    done += weights[i]
    return (f) => onProgress(start + f * share)
  }

  const primes = deriveHopPrimes(previousEventId, m, kernel)
  phase(0)?.(1)
  const residues = computeHopResidues(primes, geometry, roots, kernel, backend, phase(1))
  const tree = hopSealTree(previousEventId, residues)
  phase(2)?.(1)
  const found = findHopNonce(previousEventId, tree.seal, geometry.A, wordAt(primes, 0), kernel, { ...options.nonceSearch, onProgress: phase(3) })
  if (!found) throw new Error('no nonce in the range meets the price')
  const indices = hopSampleIndices(found.attempt.G, geometry.m)
  const openings = indices.map((i) => openHopBlock(tree, residues, Number(i / BigInt(RESIDUE_BLOCK))))
  phase(4)?.(1)
  return {
    primes,
    residues,
    seal: tree.seal,
    nonce: found.nonce,
    attempt: found.attempt,
    indices,
    openings,
    tags: { proof: encodeSeal(tree.seal), mn: encodeHopNonce(found.nonce), mp: encodeHopOpenings(openings) },
  }
}

export interface HopProofV2Options<N = bigint> extends HopResidueOptions<N> {
  /** The tallest axis tree to build; the temporal tree is capped at TEMPORAL_MAX_COMPUTE_HEIGHT as for version 1. */
  maxComputeHeight?: number
}

/** A version 2 hop: the roots and region_n a client still uses for keys, and the three tags. Never hop_n. */
export interface HopProofV2 {
  cantorX: bigint
  cantorY: bigint
  cantorZ: bigint
  /** pi(pi(cantor_x, cantor_y), cantor_z) (4.7), for the region keys of 7.2. */
  regionN: bigint
  terrainK: number
  temporalSeed: bigint
  cantorT: bigint
  geometry: HopGeometry
  seal: Uint8Array
  nonce: bigint
  G: Uint8Array
  indices: bigint[]
  /** The `proof`, `mn` and `mp` tag values (8.4). */
  tags: { proof: string; mn: string; mp: string }
}

/**
 * Compute a full version 2 hop proof (5.9, 5.10): the three axis trees and the
 * temporal tree exactly as version 1 builds them, region_n from the axis roots
 * for the region keys, and the residue openings over hop_n, which is never
 * built (nor its hex). The nonce is the first meeting the price from 0 unless
 * options.nonceSearch says otherwise.
 */
export function computeHopProofV2<N = bigint>(
  x1: bigint, y1: bigint, z1: bigint,
  x2: bigint, y2: bigint, z2: bigint,
  plane: Plane,
  previousEventIdHex: string,
  options: HopProofV2Options<N> = {},
): HopProofV2 {
  if (!HEX64.test(previousEventIdHex)) throw new Error('previousEventIdHex must be exactly 64 lowercase hex chars')
  const prev = hexToBytes(previousEventIdHex)
  const backend = options.backend ?? (BIGINT_BACKEND as unknown as BigBackend<N>)
  const maxComputeHeight = options.maxComputeHeight ?? DEFAULT_MAX_COMPUTE_HEIGHT
  const geometry = hopGeometry(prev, { x: x1, y: y1, z: z1, plane }, { x: x2, y: y2, z: z2, plane })
  const onProgress = options.onProgress

  // The trees in levels as computeHopProof charges them, the region pairings,
  // and the residue extension at about a fifth of the trees (spec 5.12).
  const levels = (h: number): number => h + 1
  const trees = [...geometry.axes.map((a) => levels(a.height)), levels(geometry.K)]
  const treeWork = trees.reduce((a, b) => a + b, 0)
  const work = [...trees, 4, 8, Math.max(2, treeWork / 4)]
  const totalWork = work.reduce((a, b) => a + b, 0)
  let base = 0
  const stage = (i: number): ProgressFn | undefined => {
    if (!onProgress) return undefined
    const share = work[i] / totalWork
    const start = base
    base += share
    return (f) => onProgress(Math.min(1, start + f * share))
  }

  const [ax, ay, az] = geometry.axes
  // Every value made through the backend, released on the way out, thrown or not.
  const made: N[] = []
  const keep = (v: N): N => { made.push(v); return v }
  try {
    const rx = keep(backend.subtreeCantor(ax.base, ax.height, maxComputeHeight, stage(0)))
    const ry = keep(backend.subtreeCantor(ay.base, ay.height, maxComputeHeight, stage(1)))
    const rz = keep(backend.subtreeCantor(az.base, az.height, maxComputeHeight, stage(2)))
    const rt = keep(backend.subtreeCantor(geometry.temporal.base, geometry.K, TEMPORAL_MAX_COMPUTE_HEIGHT, stage(3)))
    const rxy = keep(backend.pair(rx, ry))
    stage(4)?.(1)
    const regionN = backend.toBigInt(keep(backend.pair(rxy, rz)))
    stage(5)?.(1)
    const proof = proveHopResidues(prev, geometry, { x: rx, y: ry, z: rz, t: rt }, { ...options, backend, onProgress: stage(6) })
    onProgress?.(1)
    return {
      cantorX: backend.toBigInt(rx),
      cantorY: backend.toBigInt(ry),
      cantorZ: backend.toBigInt(rz),
      regionN,
      terrainK: geometry.K,
      temporalSeed: geometry.temporalSeed,
      cantorT: backend.toBigInt(rt),
      geometry,
      seal: proof.seal,
      nonce: proof.nonce,
      G: proof.attempt.G,
      indices: proof.indices,
      tags: proof.tags,
    }
  } finally {
    if (backend.release) for (const v of made) backend.release(v)
  }
}

// ------------------------------------------------------------- verification (5.11, 8.7.1)

export interface HopClaim {
  /** The source, decoded from the `c` tag. */
  from: Xyz
  /** The destination, decoded from the `C` tag; its plane bit enters K. */
  to: Xyz
  /** The id in the `e` previous tag, 64 lowercase hex. */
  previousEventIdHex: string
  /** The `proof` tag's value, or null (or undefined) when the event has none. */
  proof: string | null | undefined
  /** The `mn` tag's value, or null (or undefined) when the event has none. */
  nonce: string | null | undefined
  /** The `mp` tag's value, or null (or undefined) when the event has none. */
  openings: string | null | undefined
  /**
   * The event's NIP-01 id, 64 lowercase hex, which decides whether a version 1
   * hop is exempt (5.13). Required, so that no caller can drop it by accident
   * and turn every listed hop into a rejected one.
   */
  eventId: string
  /** The version 1 exemption list; GRANDFATHERED_V1_HOPS by default. */
  grandfathered?: ReadonlySet<string>
}

export interface HopVerifyOptions {
  kernel?: WordKernel
  /**
   * Which failure a rejected proof reports, when it fails at more than one
   * sample or at both checks of one sample. The verdict is the same either way.
   *
   * - `spec` (the default): the first failure in the order of 5.11 step 5,
   *   residue then path for each sample in ascending i, which is the
   *   `first_failure` of the spec's vectors. Every path is climbed first,
   *   because a climb costs microseconds and a residue milliseconds, and
   *   residues are computed only up to the first sample whose path fails, so
   *   a junk tree costs at most one residue.
   * - `cost`: a failing path rejects at once, before any residue is computed,
   *   so a junk tree costs one attempt and 16 climbs. The step reported can
   *   then be a path where `spec` would report that sample's residue.
   */
  order?: 'spec' | 'cost'
  /**
   * Check every sample and report every failure, residue and path, in spec
   * order, instead of stopping at the first. For diagnostics: it always costs
   * 16 residues.
   */
  allFailures?: boolean
}

const present = (v: string | null | undefined): v is string => v !== null && v !== undefined

/**
 * Level 1 verification of a hop's proof (5.11, 8.7.1 steps 7 to 11): the
 * tags' form and width, one attempt and its price, the 16 indices from G, and
 * for each sample its path climbed to the seal and its residue recomputed in
 * word arithmetic. Never builds a root, region_n or hop_n. Returns what
 * failed, as `step` or `step:detail`: `event_id`, `previous_event_id`,
 * `form:proof`, `form:mn`, `form:mp` (every malformed tag is named),
 * `geometry`, `price`, `residue:i` and `path:i` for sample i. Past the form,
 * it stops at the first failure (see HopVerifyOptions for which one and for
 * reporting all). Empty means the proof is valid.
 *
 * A hop whose id is on the list is a version 1 hop exempt under 5.13: its
 * `proof` is accepted without steps 8 to 11, and only the form of the tags it
 * carries is checked (8.8). Any other hop must carry all three tags.
 * Everything else about a hop (links, sector tags, the count of its tags) is
 * the chain verifier's to check.
 */
export function verifyHopLevel1(claim: HopClaim, options: HopVerifyOptions = {}): string[] {
  const kernel = options.kernel ?? selectWordKernel()
  const order = options.order ?? 'spec'
  if (typeof claim.eventId !== 'string' || !HEX64.test(claim.eventId)) return ['event_id']
  if (!HEX64.test(claim.previousEventIdHex)) return ['previous_event_id']
  const prev = hexToBytes(claim.previousEventIdHex)
  const geometry = hopGeometry(prev, claim.from, claim.to)
  const failed: string[] = []

  // Step 7: a listed hop's proof stands; the tags it carries must still be well formed.
  if (isGrandfatheredV1Hop(claim.eventId, claim.grandfathered ?? GRANDFATHERED_V1_HOPS)) {
    if (!present(claim.proof) || decodeSeal(claim.proof) === null) failed.push('form:proof')
    if (present(claim.nonce) && decodeHopNonce(claim.nonce) === null) failed.push('form:mn')
    if (present(claim.openings) && decodeHopOpenings(claim.openings, geometry.depth) === null) failed.push('form:mp')
    return failed
  }

  // Step 7, otherwise: all three tags, each exactly of its form and width.
  const seal = present(claim.proof) ? decodeSeal(claim.proof) : null
  const nonce = present(claim.nonce) ? decodeHopNonce(claim.nonce) : null
  const openings = present(claim.openings) ? decodeHopOpenings(claim.openings, geometry.depth) : null
  if (seal === null) failed.push('form:proof')
  if (nonce === null) failed.push('form:mn')
  if (openings === null) failed.push('form:mp')
  if (seal === null || nonce === null || openings === null) return failed
  // Every index below m has a be64 (5.9); past h65 some would not.
  if (geometry.m > TWO_64) return ['geometry']

  // Step 8: one attempt, and its price.
  const attempt = hopAttempt(prev, seal, nonce, hopPrime(prev, 0, kernel), kernel)
  if (!meetsPrice(attempt.G, geometry.A)) return ['price']

  // Steps 9 and 10: the indices; every path, which is cheap; then the
  // residues, which are not, only as far as the order needs them.
  const indices = hopSampleIndices(attempt.G, geometry.m)
  const block = BigInt(RESIDUE_BLOCK)
  const pathHolds = indices.map((idx, i) => {
    const b = idx / block
    return verifyHopPath(hopLeafHash(prev, b, openings[i].residues), b, openings[i].siblings, seal)
  })
  const residueHolds = (i: number): boolean =>
    openings[i].residues[Number(indices[i] % block)] === hopResidue(geometry, hopPrime(prev, indices[i], kernel), kernel)

  if (options.allFailures) {
    for (let i = 0; i < HOP_SAMPLES; i++) {
      if (!residueHolds(i)) failed.push(`residue:${i}`)
      if (!pathHolds[i]) failed.push(`path:${i}`)
    }
    return failed
  }
  const firstBadPath = pathHolds.indexOf(false)
  if (order === 'cost' && firstBadPath >= 0) return [`path:${firstBadPath}`]
  // In spec order, no sample past the first bad path can be the first failure.
  const last = firstBadPath >= 0 ? firstBadPath : HOP_SAMPLES - 1
  for (let i = 0; i <= last; i++) {
    if (!residueHolds(i)) return [`residue:${i}`]
    if (!pathHolds[i]) return [`path:${i}`]
  }
  return []
}

export interface HopAuditOptions<N = bigint> {
  kernel?: WordKernel
  backend?: BigBackend<N>
  /** The tallest tree the audit builds. Default DEFAULT_MAX_COMPUTE_HEIGHT. */
  maxComputeHeight?: number
}

/**
 * Level 2, the full audit (5.11), for tests and the census. A version 1 hop
 * (no `mn` and no `mp`) is audited as 5.13 audits a hop before listing it: its
 * proof_hash recomputed per 5.6 from its own coordinates and previous event
 * id and compared with `proof`. Any other hop is checked at Level 1, the list
 * ignored, and then every root rebuilt, every residue computed and the seal
 * rebuilt and compared with `proof` (`seal` when it differs). Costs what
 * making the hop costs.
 */
export function auditHopLevel2<N = bigint>(claim: HopClaim, options: HopAuditOptions<N> = {}): string[] {
  const kernel = options.kernel ?? selectWordKernel()
  const backend = options.backend ?? (BIGINT_BACKEND as unknown as BigBackend<N>)
  const maxComputeHeight = options.maxComputeHeight ?? DEFAULT_MAX_COMPUTE_HEIGHT
  if (!HEX64.test(claim.previousEventIdHex)) return ['previous_event_id']
  if (!present(claim.nonce) && !present(claim.openings)) {
    if (!present(claim.proof) || decodeSeal(claim.proof) === null) return ['form:proof']
    const { from, to } = claim
    const v1 = computeHopProof(from.x, from.y, from.z, to.x, to.y, to.z, to.plane, claim.previousEventIdHex, maxComputeHeight)
    return v1.proofHash === claim.proof ? [] : ['proof']
  }
  // The list waives only Level 1's re-checking; an audit ignores it.
  const failed = verifyHopLevel1({ ...claim, grandfathered: new Set() }, { kernel })
  if (failed.length) return failed
  const prev = hexToBytes(claim.previousEventIdHex)
  const geometry = hopGeometry(prev, claim.from, claim.to)
  const [ax, ay, az] = geometry.axes
  const made: N[] = []
  const keep = (v: N): N => { made.push(v); return v }
  try {
    const roots: HopRoots<N> = {
      x: keep(backend.subtreeCantor(ax.base, ax.height, maxComputeHeight)),
      y: keep(backend.subtreeCantor(ay.base, ay.height, maxComputeHeight)),
      z: keep(backend.subtreeCantor(az.base, az.height, maxComputeHeight)),
      t: keep(backend.subtreeCantor(geometry.temporal.base, geometry.K, TEMPORAL_MAX_COMPUTE_HEIGHT)),
    }
    const primes = deriveHopPrimes(prev, Number(geometry.m), kernel)
    const residues = computeHopResidues(primes, geometry, roots, kernel, backend)
    return encodeSeal(hopSealTree(prev, residues).seal) === claim.proof ? [] : ['seal']
  } finally {
    if (backend.release) for (const v of made) backend.release(v)
  }
}
