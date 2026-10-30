/**
 * gmpBackend.ts - a TEST-ONLY BigBackend over GMP compiled to WebAssembly
 * (gmp-wasm 1.3.2, LGPL-3.0).
 *
 * It proves the seam and nothing more. Core never imports gmp-wasm: it is a
 * devDependency, pinned exactly, outside `files`, so the published package
 * neither contains nor installs it. test/residue.test.ts runs the whole
 * residue suite through this adapter with both word kernels and asserts the
 * same values and tags byte for byte as with BIGINT_BACKEND. A consumer that
 * wants GMP (ONOSENDAI, as its own lazy chunk) writes an adapter like this one
 * against the BigBackend interface; see the README.
 *
 * Lifted from the research adapter (cantor-verification,
 * browser-bench/gmpbig.mjs): the streaming Cantor tree whose level 1 is 2 x^2,
 * the pairing, the product tree and the remainder tree that descends to level
 * 2 and then reduces each prime from its group of four. New here: the BigBackend
 * shape, pairModQ for the multi-axis path, conversions through hex, progress,
 * the height checks of computeSubtreeCantor, and the release hooks.
 *
 * Values are mpz_t pointers into GMP's WebAssembly memory, which no garbage
 * collector sees. The adapter implements release and releaseTree and counts
 * the values alive, so the tests can assert that core gives back every value
 * it made and none it was given.
 */

import { init } from 'gmp-wasm'
import type { ProgressFn } from '../../src/movement.js'
import { setWord, type BigBackend, type ProductTree, type WordList } from '../../src/residue.js'

/** An mpz_t: a pointer into GMP's memory. */
type Mpz = number

/** The part of gmp-wasm's low-level binding this adapter calls, with plain types (the package brands its numbers). */
interface GmpBinding {
  malloc(size: number): number
  malloc_cstr(s: string): number
  free(ptr: number): void
  readonly mem: Uint8Array
  mpz_t(): Mpz
  mpz_init(z: Mpz): void
  mpz_clear(z: Mpz): void
  mpz_t_free(z: Mpz): void
  mpz_set(rop: Mpz, op: Mpz): void
  mpz_set_ui(rop: Mpz, op: number): void
  mpz_set_str(rop: Mpz, str: number, base: number): number
  mpz_get_str(str: number, base: number, op: Mpz): number
  mpz_sizeinbase(op: Mpz, base: number): number
  mpz_add(rop: Mpz, a: Mpz, b: Mpz): void
  mpz_add_ui(rop: Mpz, a: Mpz, b: number): void
  mpz_mul(rop: Mpz, a: Mpz, b: Mpz): void
  mpz_mul_2exp(rop: Mpz, a: Mpz, bits: number): void
  mpz_tdiv_q_2exp(q: Mpz, n: Mpz, bits: number): void
  mpz_tdiv_r(r: Mpz, n: Mpz, d: Mpz): void
  mpz_cmp(a: Mpz, b: Mpz): number
  /** Limb n of op; limbs are 64 bits in this build and come back as bigint. */
  mpz_getlimbn(op: Mpz, n: number): bigint
}

/** The adapter, with the two counters the tests read. */
export interface GmpBackend extends BigBackend<Mpz> {
  /** mpz_t values made and not yet released. */
  live(): number
  /** GMP's WebAssembly memory, in MiB (it grows and never shrinks). */
  memoryMB(): number
}

const TWO_32 = 2 ** 32
const PROGRESS_TICKS = 64

/** Instantiates GMP (the module is inside the package; nothing is fetched) and returns the adapter. */
export async function loadGmpBackend(): Promise<GmpBackend> {
  const b = (await init()).binding as unknown as GmpBinding
  let alive = 0
  const Z = (): Mpz => { const z = b.mpz_t(); b.mpz_init(z); alive++; return z }
  const kill = (z: Mpz): void => { b.mpz_clear(z); b.mpz_t_free(z); alive-- }

  const fromBigInt = (v: bigint): Mpz => {
    const z = Z()
    const s = b.malloc_cstr(v.toString(16))
    const bad = b.mpz_set_str(z, s, 16)
    b.free(s)
    if (bad !== 0) { kill(z); throw new Error('gmp: mpz_set_str refused a value') }
    return z
  }
  const toBigInt = (z: Mpz): bigint => {
    const room = b.mpz_sizeinbase(z, 16) + 2
    const buf = b.malloc(room)
    b.mpz_get_str(buf, 16, z)
    const mem = b.mem // read after the call: memory may have grown
    const end = mem.indexOf(0, buf)
    const hex = new TextDecoder().decode(mem.subarray(buf, end))
    b.free(buf)
    return hex.startsWith('-') ? -BigInt('0x' + hex.slice(1)) : BigInt('0x' + hex)
  }
  /** z = hi 2^32 + lo, for 32-bit words. */
  const setU64 = (z: Mpz, hi: number, lo: number): void => { b.mpz_set_ui(z, hi); b.mpz_mul_2exp(z, z, 32); b.mpz_add_ui(z, z, lo) }
  const T = Z()
  alive-- // scratch for the life of the adapter, not a value of core's
  /** rop = op + v for an integer 0 <= v < 2^53 (add_ui takes 32 bits). */
  const addSmall = (rop: Mpz, op: Mpz, v: number): void => {
    if (v < TWO_32) b.mpz_add_ui(rop, op, v)
    else { setU64(T, Math.floor(v / TWO_32), v >>> 0); b.mpz_add(rop, op, T) }
  }
  const S = Z()
  alive--
  /** out = pi(a, c); out may alias a, never c. */
  const pairInto = (out: Mpz, a: Mpz, c: Mpz): void => {
    b.mpz_add(S, a, c)
    b.mpz_mul(out, S, S)
    b.mpz_add(out, out, S)
    b.mpz_tdiv_q_2exp(out, out, 1)
    b.mpz_add(out, out, c)
  }
  /** out = v mod d, copying when v < d already. */
  const modInto = (out: Mpz, v: Mpz, d: Mpz): void => {
    if (b.mpz_cmp(v, d) < 0) b.mpz_set(out, v)
    else b.mpz_tdiv_r(out, v, d)
  }
  const top = (tree: ProductTree<Mpz>): Mpz => tree.levels[tree.levels.length - 1][0]

  const backend: GmpBackend = {
    name: 'gmp-wasm',
    fromBigInt,
    toBigInt,
    subtreeCantor(base, height, maxComputeHeight, onProgress?: ProgressFn) {
      if (height < 0) throw new Error('height must be >= 0')
      if (height > maxComputeHeight) throw new Error(`height ${height} exceeds maxComputeHeight ${maxComputeHeight}`)
      if (height === 0) { onProgress?.(1); return fromBigInt(base) }
      // Streaming, a stack of at most height partial roots. Leaves base + 2j
      // and base + 2j + 1 pair to pi(x - 1, x) = 2 x^2 with x = base + 2j + 1.
      const B = fromBigInt(base)
      const x = Z()
      const stack: Mpz[] = []
      const levels: number[] = []
      const pairs = 2 ** (height - 1)
      const tick = Math.max(1, Math.floor(pairs / PROGRESS_TICKS))
      for (let j = 0; j < pairs; j++) {
        addSmall(x, B, 2 * j + 1)
        let cur = Z()
        b.mpz_mul(cur, x, x)
        b.mpz_mul_2exp(cur, cur, 1)
        let level = 1
        while (levels.length > 0 && levels[levels.length - 1] === level) {
          const left = stack.pop()!
          levels.pop()
          pairInto(left, left, cur)
          kill(cur)
          cur = left
          level++
        }
        stack.push(cur)
        levels.push(level)
        if (onProgress && (j + 1) % tick === 0) onProgress((j + 1) / pairs)
      }
      kill(x)
      kill(B)
      onProgress?.(1)
      return stack[0]
    },
    pair(a, c) {
      const out = Z()
      pairInto(out, a, c)
      return out
    },
    productTree(primes: WordList) {
      const m = primes.length / 2
      const level0: Mpz[] = new Array(m)
      for (let j = 0; j < m; j++) { const z = Z(); setU64(z, primes[2 * j], primes[2 * j + 1]); level0[j] = z }
      const levels: Mpz[][] = [level0]
      while (levels[levels.length - 1].length > 1) {
        const below = levels[levels.length - 1]
        const next: Mpz[] = new Array((below.length + 1) >> 1)
        for (let i = 0; i < next.length; i++) {
          const z = Z()
          if (2 * i + 1 < below.length) b.mpz_mul(z, below[2 * i], below[2 * i + 1])
          else b.mpz_set(z, below[2 * i])
          next[i] = z
        }
        levels.push(next)
      }
      return { levels }
    },
    pairModQ(tree, a, c) {
      const Q = top(tree)
      const ra = Z(), rc = Z(), s = Z(), out = Z()
      modInto(ra, a, Q)
      modInto(rc, c, Q)
      b.mpz_add(s, ra, rc)
      modInto(s, s, Q)
      // Q is odd, so s(s + 1) / 2 modulo Q depends only on s modulo Q.
      b.mpz_add_ui(out, s, 1)
      b.mpz_mul(out, out, s)
      b.mpz_tdiv_q_2exp(out, out, 1)
      b.mpz_add(out, out, rc)
      b.mpz_tdiv_r(out, out, Q)
      kill(ra); kill(rc); kill(s)
      return out
    },
    remainders(tree, x, out) {
      const levels = tree.levels
      const L = levels.length
      const primes = levels[0]
      const m = primes.length
      if (out.length !== 2 * m) throw new Error('remainders writes one residue per prime')
      let current: Mpz[] = [Z()]
      modInto(current[0], x, levels[L - 1][0])
      let lowest = L - 1
      for (let l = L - 2; l >= 2; l--) {
        const nodes = levels[l]
        const next: Mpz[] = new Array(nodes.length)
        for (let i = 0; i < nodes.length; i++) {
          const z = Z()
          modInto(z, current[i >> 1], nodes[i])
          next[i] = z
        }
        for (const z of current) kill(z)
        current = next
        lowest = l
      }
      const t = Z()
      for (let j = 0; j < m; j++) {
        b.mpz_tdiv_r(t, current[Math.floor(j / 2 ** lowest)], primes[j])
        setWord(out, j, BigInt.asUintN(64, b.mpz_getlimbn(t, 0)))
      }
      kill(t)
      for (const z of current) kill(z)
    },
    release: kill,
    releaseTree(tree) {
      for (const level of tree.levels) for (const z of level) kill(z)
    },
    live: () => alive,
    memoryMB: () => b.mem.length / 1048576,
  }
  return Object.freeze(backend)
}
