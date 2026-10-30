/**
 * residue.test.ts - residue openings, version 2 of the hop proof, against the spec.
 *
 * fixtures/hop-residue-vectors.json is copied unchanged from arkin0x/cyberspace
 * at commit 06c287332651f99b75e609b7b098e165993750fd, sha256
 * 29b2222d3768b173b82887d9fb992cda23044ef84cfcfca48dd049766c7c4d33 (asserted
 * below), written from hop-residue-reference.py. Every value in it MUST be
 * reproduced exactly: the single values, the seven prover hops with every
 * intermediate value, the 16 Level 1 checks one at a time, every verifier
 * vector with its verdict and first failing step, the version 1 list vectors,
 * the prices and the sizes. No network, no timers.
 *
 * Every test runs twice, once through each word kernel (JS_WORD_KERNEL and
 * WASM_WORD_KERNEL), each pass guarded so that a call reaching the other
 * kernel fails. After them: the committed WASM module against its recorded
 * hashes and its source, kernel selection, and a differential test of the two
 * kernels on random inputs and on the edges of the Montgomery arithmetic.
 *
 * The file's own provenance.spec_commit field reads 8b45430: that is the
 * commit of hop-residue-reference.py, which the vectors were written from.
 * The file itself was added to the spec at 06c2873, the commit it is copied
 * from here. Both are asserted below.
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { bytesToHex, cantorPair, hexToBytes, intToBytesBE, sha256 } from '../src/cantor.js'
import { KERN_WASM_BASE64 } from '../src/residue/kernWasm.js'
import { coordToXyz, hexToCoord, xyzToCoord, type Xyz } from '../src/coords.js'
import { alignedBase, computeHopProof, computeSubtreeCantor } from '../src/movement.js'
import { GRANDFATHERED_V1_HOPS, GRANDFATHERED_V1_HOPS_COMMIT } from '../src/grandfathered_v1_hops.js'
import {
  BIGINT_BACKEND,
  HOP_GRIND_HEIGHT,
  HOP_REROLL_BUDGET,
  HOP_RESIDUE_GRIND_DOMAIN,
  HOP_RESIDUE_LEAF_DOMAIN,
  HOP_RESIDUE_PRIME_DOMAIN,
  HOP_RESIDUE_SAMPLE_DOMAIN,
  HOP_SAMPLES,
  JS_WORD_KERNEL,
  PAD_LEAF,
  PRIME_BITS,
  RESIDUE_BLOCK,
  SMALL_ODD_PRIMES,
  WASM_WORD_KERNEL,
  WIDTH_DIVISOR,
  auditHopLevel2,
  computeHopProofV2,
  computeHopResidues,
  decodeHopNonce,
  decodeHopOpenings,
  decodeSeal,
  deriveHopPrimes,
  encodeHopNonce,
  encodeHopOpenings,
  encodeSeal,
  findHopNonce,
  hopAttempt,
  hopGeometry,
  hopLeafHash,
  hopMerkleDepth,
  hopOpeningsLength,
  hopPrime,
  hopPrimeStart,
  hopRerollAttempts,
  hopRerollBudget,
  hopResidue,
  hopResidueCount,
  hopRootResidues,
  hopSampleIndices,
  hopSealTree,
  isGrandfatheredV1Hop,
  loadWasmWordKernel,
  openHopBlock,
  pairModP,
  parseGrandfatheredList,
  proveHopResidues,
  residueEngine,
  residueTree,
  selectWordKernel,
  setWord,
  verifyHopLevel1,
  verifyHopPath,
  wasmWordKernelBytes,
  wasmWordKernelReady,
  wordAt,
  wordList,
  wordListSha256,
  wordsOf,
  type HopClaim,
  type HopGeometry,
  type HopResidueProof,
  type HopVerifyOptions,
  type WordKernel,
} from '../src/residue.js'

const FIXTURE_SHA256 = '29b2222d3768b173b82887d9fb992cda23044ef84cfcfca48dd049766c7c4d33'
const SPEC_COMMIT = '06c287332651f99b75e609b7b098e165993750fd'
const RAW = readFileSync(new URL('./fixtures/hop-residue-vectors.json', import.meta.url))
const V = JSON.parse(RAW.toString('utf8'))

interface Tags { proof?: string; mn?: string; mp?: string }
interface ProverVector {
  name: string
  previous_event_id: string
  c: string
  C: string
  from: { x: string; y: string; z: string; plane: number }
  to: { x: string; y: string; z: string; plane: number }
  axes: { axis: string; base: string; height: number }[]
  K: number
  t_base: string
  h_max: number
  m: number
  blocks: number
  depth: number
  A: string
  primes_first_8: string[]
  prime_last: string
  primes_sha256: string
  residues_first_8: string[]
  residues_sha256: string
  roots_mod_p0: { x: string; y: string; z: string; t: string; hop_n: string }
  leaf_0: string
  seal: string
  nonce: number
  G: string
  attempt: { nonce: number; seed: string; g_base: string; r_g: string; G: string }
  attempt_nonce_0: string
  indices: number[]
  tags: Required<Tags>
  mp_length: number
  mp_sha256: string
}
interface VerifierVector {
  name: string
  previous_event_id: string
  c: string
  C: string
  tags: Tags
  expected: 'accept' | 'reject'
  first_failure: { step: string; sample?: number } | null
}
const PROVER: ProverVector[] = V.prover
const VERIFIER: VerifierVector[] = V.verifier
const prover = (name: string): ProverVector => PROVER.find((v) => v.name === name)!

const decodeCoord = (hex: string): Xyz => coordToXyz(hexToCoord(hex))
const ascii = (b: Uint8Array): string => new TextDecoder().decode(b)
const hexSha = (s: string): string => bytesToHex(sha256(new TextEncoder().encode(s)))

/** A stand-in event id for the vectors that carry none: no list contains it. */
const STAND_IN_ID = hexSha('cyberspace-core residue.test.ts stand-in event id')

function claimOf(v: { previous_event_id: string; c: string; C: string; tags: Tags }, extra: Partial<HopClaim> = {}): HopClaim {
  return {
    from: decodeCoord(v.c),
    to: decodeCoord(v.C),
    previousEventIdHex: v.previous_event_id,
    proof: v.tags.proof,
    nonce: v.tags.mn,
    openings: v.tags.mp,
    eventId: STAND_IN_ID,
    ...extra,
  }
}

/** The exact roots of a hop, from its geometry, in BigInt. */
function exactRoots(g: HopGeometry): { x: bigint; y: bigint; z: bigint; t: bigint } {
  const [ax, ay, az] = g.axes
  return {
    x: computeSubtreeCantor(ax.base, ax.height, 30),
    y: computeSubtreeCantor(ay.base, ay.height, 30),
    z: computeSubtreeCantor(az.base, az.height, 30),
    t: computeSubtreeCantor(g.temporal.base, g.temporal.height, 30),
  }
}

/** A deterministic 64-bit generator (splitmix64), so the property tests repeat exactly. */
function rng(seed: bigint): () => bigint {
  let s = seed & ((1n << 64n) - 1n)
  return () => {
    s = (s + 0x9e3779b97f4a7c15n) & ((1n << 64n) - 1n)
    let z = s
    z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & ((1n << 64n) - 1n)
    z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & ((1n << 64n) - 1n)
    return z ^ (z >> 31n)
  }
}

// ------------------------------------------------------------- both kernels

const KERNELS: readonly WordKernel[] = [JS_WORD_KERNEL, WASM_WORD_KERNEL]

/**
 * The kernel the current pass may use. Every method of both kernels is
 * wrapped so that a call into the other one fails the test: a call that
 * forgot its kernel would otherwise take the default (WASM in Node) and pass
 * unnoticed in the JavaScript pass. null where a test uses both on purpose.
 */
let ACTIVE: string | null = null
for (const kernel of KERNELS) {
  const methods = kernel as unknown as Record<string, unknown>
  for (const key of Object.keys(methods)) {
    const f = methods[key]
    if (typeof f !== 'function') continue
    methods[key] = (...args: unknown[]): unknown => {
      if (ACTIVE !== null && ACTIVE !== kernel.name) throw new Error(`the ${kernel.name} kernel was called in the ${ACTIVE} pass`)
      return (f as (...a: unknown[]) => unknown)(...args)
    }
  }
}

/** A describe whose tests use both kernels. */
function describeBothKernels(name: string, fn: () => void): void {
  describe(name, () => {
    ACTIVE = null
    beforeAll(() => { ACTIVE = null })
    fn()
  })
}

interface CountedRoot { base: bigint; height: number }

/**
 * A kernel that passes every call on to `inner` and counts: each rootResidue
 * with its base and height, primes searched, and the whole steps it has.
 */
function counting(inner: WordKernel): { kernel: WordKernel; roots: CountedRoot[]; primes: number; attempts: number; primeLists: number; nonceSearches: number } {
  const c = { kernel: inner, roots: [] as CountedRoot[], primes: 0, attempts: 0, primeLists: 0, nonceSearches: 0 }
  const kernel: WordKernel = {
    name: `counting ${inner.name}`,
    searchPrimes(starts, out) { c.primes += starts.length / 2; inner.searchPrimes(starts, out) },
    rootResidue(p, base, height) { c.roots.push({ base, height }); return inner.rootResidue(p, base, height) },
    pairMod: (p, a, b) => inner.pairMod(p, a, b),
    combine: (primes, parts, out) => inner.combine(primes, parts, out),
  }
  const { hopPrimes, attempt, findNonce } = inner
  if (hopPrimes) kernel.hopPrimes = (prev, out) => { c.primeLists++; hopPrimes(prev, out) }
  if (attempt) kernel.attempt = (prev, seal, nonce, p0) => { c.attempts++; return attempt(prev, seal, nonce, p0) }
  if (findNonce) kernel.findNonce = (prev, seal, a, p0, start, end) => { c.nonceSearches++; return findNonce(prev, seal, a, p0, start, end) }
  c.kernel = kernel
  return c
}

// ------------------------------------------------------------- every test, through each kernel

describe.each(KERNELS.map((k) => [k.name, k] as const))('the %s word kernel', (_name, K) => {
  ACTIVE = K.name
  beforeAll(() => { ACTIVE = K.name })
  afterAll(() => { ACTIVE = null })

  // ------------------------------------------------------------- the fixture itself

  describe('the fixture', () => {
    it('is the spec file of commit 06c2873, byte for byte', () => {
      expect(RAW.length).toBe(422489)
      expect(bytesToHex(sha256(new Uint8Array(RAW)))).toBe(FIXTURE_SHA256)
      expect(V.provenance.chain_rules_revision).toBe('2026-10-08-residue-openings')
      // The commit of the reference the vectors were written from, not the commit the file was copied from (06c2873).
      expect(V.provenance.spec_commit).toBe('8b45430af330f6e93ee763716d33868706cc2879')
    })

    it('states the constants this module uses', () => {
      const c = V.constants
      expect(ascii(HOP_RESIDUE_PRIME_DOMAIN)).toBe(c.HOP_RESIDUE_PRIME_DOMAIN)
      expect(ascii(HOP_RESIDUE_LEAF_DOMAIN)).toBe(c.HOP_RESIDUE_LEAF_DOMAIN)
      expect(ascii(HOP_RESIDUE_GRIND_DOMAIN)).toBe(c.HOP_RESIDUE_GRIND_DOMAIN)
      expect(ascii(HOP_RESIDUE_SAMPLE_DOMAIN)).toBe(c.HOP_RESIDUE_SAMPLE_DOMAIN)
      expect([HOP_RESIDUE_PRIME_DOMAIN.length, HOP_RESIDUE_LEAF_DOMAIN.length, HOP_RESIDUE_GRIND_DOMAIN.length, HOP_RESIDUE_SAMPLE_DOMAIN.length]).toEqual([31, 30, 31, 32])
      expect(HOP_SAMPLES).toBe(c.HOP_SAMPLES)
      expect(RESIDUE_BLOCK).toBe(c.RESIDUE_BLOCK)
      expect(PRIME_BITS).toBe(c.PRIME_BITS)
      expect(WIDTH_DIVISOR).toBe(c.WIDTH_DIVISOR)
      expect(HOP_GRIND_HEIGHT).toBe(c.HOP_GRIND_HEIGHT)
      expect([...SMALL_ODD_PRIMES]).toEqual(c.SMALL_ODD_PRIMES)
      expect(HOP_REROLL_BUDGET.map(String)).toEqual(c.HOP_REROLL_BUDGET)
      expect(bytesToHex(PAD_LEAF)).toBe(c.PAD_LEAF)
    })
  })

  // ------------------------------------------------------------- single values

  describe('single values', () => {
    const ZERO = new Uint8Array(32)
    it('reproduces every one', () => {
      expect(V.single).toHaveLength(7)
      for (const s of V.single) {
        const a = s.arguments
        const prev = hexToBytes(a.previous_event_id)
        let got: string
        switch (s.function) {
          case 'hop_prime':
            got = hopPrime(prev, BigInt(a.j), K).toString()
            break
          case 'compute_subtree_cantor mod p_0': {
            const p0 = hopPrime(prev, 0, K)
            got = K.rootResidue(p0, BigInt(a.base), a.height).toString()
            expect(got).toBe((computeSubtreeCantor(BigInt(a.base), a.height) % p0).toString())
            break
          }
          case 'leaf_hash':
            got = bytesToHex(hopLeafHash(prev, a.block, a.residues.map(BigInt)))
            break
          case 'attempt': {
            const G = hopAttempt(prev, hexToBytes(a.seal), BigInt(a.nonce), hopPrime(prev, 0, K), K).G
            got = bytesToHex(G)
            break
          }
          default:
            throw new Error(`unknown single function ${s.function}`)
        }
        expect(got, `${s.function} ${JSON.stringify(a)}`).toBe(s.value)
      }
    })

    it('does not wrap the prime index at 2^32 (j = 2^32 + 1 is not j = 1)', () => {
      const trap = V.single.find((s: { note?: string }) => s.note !== undefined)
      const prev = hexToBytes(trap.arguments.previous_event_id)
      expect(trap.arguments.j).toBe(2 ** 32 + 1)
      expect(hopPrime(prev, 2n ** 32n + 1n, K).toString()).toBe(trap.value)
      expect(hopPrime(prev, 1, K).toString()).toBe('3291094162111226063')
      expect(hopPrime(prev, 2n ** 32n + 1n, K)).not.toBe(hopPrime(prev, 1, K))
      expect(hopPrime(ZERO, 0, K)).toBe(2501841973170584791n)
    })
  })

  // ------------------------------------------------------------- prover vectors

  describe('prover vectors', () => {
    expect(PROVER.map((v) => v.name)).toEqual([
      'golden-5.7', 'multi-axis-earth', 'plane-only-k-positive', 'k-zero-axis-h6', 'h0-k-zero', 'into-plane-1', 'h16-one-axis',
    ])

    for (const v of PROVER) {
      it(`${v.name}: every value on the way to the tags`, { timeout: 120_000 }, () => {
        const prev = hexToBytes(v.previous_event_id)
        const from = decodeCoord(v.c), to = decodeCoord(v.C)
        expect([from.x, from.y, from.z, from.plane].map(String)).toEqual([v.from.x, v.from.y, v.from.z, String(v.from.plane)])
        expect([to.x, to.y, to.z, to.plane].map(String)).toEqual([v.to.x, v.to.y, v.to.z, String(v.to.plane)])

        // Geometry, from the event alone.
        const g = hopGeometry(prev, from, to)
        expect(g.axes.map((a, i) => ({ axis: 'xyz'[i], base: a.base.toString(), height: a.height }))).toEqual(v.axes)
        expect(g.K).toBe(v.K)
        expect(g.temporal.base.toString()).toBe(v.t_base)
        expect(g.hMax).toBe(v.h_max)
        expect(g.m).toBe(BigInt(v.m))
        expect(g.blocks).toBe(BigInt(v.blocks))
        expect(g.depth).toBe(v.depth)
        expect(g.A.toString()).toBe(v.A)

        // The roots modulo p_0, from the geometry and from the exact roots.
        const roots = exactRoots(g)
        const p0 = hopPrime(prev, 0, K)
        const r0 = hopRootResidues(g, p0, K)
        const want0 = { x: r0.x, y: r0.y, z: r0.z, t: r0.t, hop_n: r0.hopN }
        expect(Object.fromEntries(Object.entries(want0).map(([k, x]) => [k, x.toString()]))).toEqual(v.roots_mod_p0)
        expect([roots.x % p0, roots.y % p0, roots.z % p0, roots.t % p0]).toEqual([r0.x, r0.y, r0.z, r0.t])

        // The whole prover.
        const proof: HopResidueProof = proveHopResidues(prev, g, roots, { kernel: K })
        expect(wordsOf(proof.primes).slice(0, 8).map(String)).toEqual(v.primes_first_8)
        expect(wordAt(proof.primes, v.m - 1).toString()).toBe(v.prime_last)
        expect(bytesToHex(wordListSha256(proof.primes))).toBe(v.primes_sha256)
        expect(wordsOf(proof.residues).slice(0, 8).map(String)).toEqual(v.residues_first_8)
        expect(bytesToHex(wordListSha256(proof.residues))).toBe(v.residues_sha256)
        expect(wordAt(proof.residues, 0)).toBe(r0.hopN)
        expect(bytesToHex(hopLeafHash(prev, 0, wordsOf(proof.residues).slice(0, 8)))).toBe(v.leaf_0)
        expect(bytesToHex(proof.seal)).toBe(v.seal)
        expect(proof.nonce).toBe(BigInt(v.nonce))
        expect(bytesToHex(proof.attempt.G)).toBe(v.G)
        expect(proof.attempt.G).toEqual(hexToBytes(v.attempt.G))
        expect(bytesToHex(proof.attempt.seed)).toBe(v.attempt.seed)
        expect(proof.attempt.gBase.toString()).toBe(v.attempt.g_base)
        expect(proof.attempt.rG.toString()).toBe(v.attempt.r_g)
        expect(v.attempt.nonce).toBe(v.nonce)
        expect(bytesToHex(hopAttempt(prev, proof.seal, 0n, p0, K).G)).toBe(v.attempt_nonce_0)
        expect(proof.indices.map(Number)).toEqual(v.indices)
        expect(proof.tags).toEqual(v.tags)
        expect(proof.tags.mp.length).toBe(v.mp_length)
        expect(hexSha(proof.tags.mp)).toBe(v.mp_sha256)

        // The tags verify, and a depth-0 tree's seal is its single leaf.
        expect(verifyHopLevel1(claimOf(v), { kernel: K })).toEqual([])
        if (v.depth === 0) expect(v.seal).toBe(v.leaf_0)
      })
    }

    it('computeHopProofV2 gives the same tags, roots and region_n, end to end', { timeout: 120_000 }, () => {
      for (const v of PROVER) {
        const from = decodeCoord(v.c), to = decodeCoord(v.C)
        const p = computeHopProofV2(from.x, from.y, from.z, to.x, to.y, to.z, to.plane, v.previous_event_id, { kernel: K })
        expect(p.tags, v.name).toEqual(v.tags)
        expect(bytesToHex(p.seal)).toBe(v.seal)
        expect(p.nonce).toBe(BigInt(v.nonce))
        expect(bytesToHex(p.G)).toBe(v.G)
        expect(p.indices.map(Number)).toEqual(v.indices)
        expect(p.terrainK).toBe(v.K)
        const roots = exactRoots(p.geometry)
        expect([p.cantorX, p.cantorY, p.cantorZ, p.cantorT]).toEqual([roots.x, roots.y, roots.z, roots.t])
        expect(p.regionN).toBe(cantorPair(cantorPair(roots.x, roots.y), roots.z))
        expect(Object.keys(p)).not.toContain('hopN')
      }
    })

    it('reports progress that rises to 1', () => {
      const v = prover('golden-5.7')
      const seen: number[] = []
      computeHopProofV2(0n, 0n, 0n, 4104n, 0n, 0n, 0, v.previous_event_id, { kernel: K, onProgress: (f) => seen.push(f) })
      expect(seen.length).toBeGreaterThan(5)
      for (let i = 1; i < seen.length; i++) expect(seen[i]).toBeGreaterThanOrEqual(seen[i - 1])
      expect(seen[seen.length - 1]).toBe(1)
    })

    it('a split nonce search finds the same golden nonce in its range, and none below it', () => {
      const v = prover('golden-5.7')
      const prev = hexToBytes(v.previous_event_id)
      const seal = hexToBytes(v.seal)
      const p0 = hopPrime(prev, 0, K)
      expect(findHopNonce(prev, seal, BigInt(v.A), p0, K, { start: 0n, end: BigInt(v.nonce) })).toBeNull()
      expect(findHopNonce(prev, seal, BigInt(v.A), p0, K, { start: 50n, end: 100n })?.nonce).toBe(87n)
    })
  })

  // ------------------------------------------------------------- the 16 checks, one at a time

  describe('the 16 Level 1 checks of the 5.7 hop', () => {
    const v = prover(V.checks.hop)
    const prev = hexToBytes(v.previous_event_id)
    const g = hopGeometry(prev, decodeCoord(v.c), decodeCoord(v.C))
    const seal = hexToBytes(v.seal)
    const openings = decodeHopOpenings(v.tags.mp, v.depth)!
    const G = hopAttempt(prev, seal, BigInt(v.nonce), hopPrime(prev, 0, K), K).G
    const indices = hopSampleIndices(G, g.m)

    expect(V.checks.samples).toHaveLength(16)
    for (const s of V.checks.samples) {
      it(`sample ${s.i}: index ${s.index}, block ${s.block}, position ${s.position}`, () => {
        expect(indices[s.i]).toBe(BigInt(s.index))
        expect(s.block).toBe(Math.floor(s.index / 8))
        expect(s.position).toBe(s.index % 8)
        const p = hopPrime(prev, s.index, K)
        expect(p.toString()).toBe(s.prime)
        expect(hopResidue(g, p, K).toString()).toBe(s.residue)
        const opening = openings[s.i]
        expect(opening.residues.map(String)).toEqual(s.block_residues)
        expect(opening.residues[s.position].toString()).toBe(s.residue)
        const leaf = hopLeafHash(prev, s.block, opening.residues)
        expect(bytesToHex(leaf)).toBe(s.leaf)
        expect(opening.siblings.map(bytesToHex)).toEqual(s.siblings)
        expect(s.mp_offset).toBe(s.i * (128 + 64 * v.depth))
        expect(v.tags.mp.slice(s.mp_offset, s.mp_offset + 16)).toBe(BigInt(s.block_residues[0]).toString(16).padStart(16, '0'))
        expect(verifyHopPath(leaf, BigInt(s.block), opening.siblings, seal)).toBe(true)
      })
    }
  })

  // ------------------------------------------------------------- verifier vectors

  describe('verifier vectors', () => {
    expect(VERIFIER).toHaveLength(26)
    for (const v of VERIFIER) {
      it(`${v.name}: ${v.expected}${v.first_failure ? ` at ${v.first_failure.step}${v.first_failure.sample !== undefined ? ` ${v.first_failure.sample}` : ''}` : ''}`, () => {
        const failed = verifyHopLevel1(claimOf(v), { kernel: K })
        const all = verifyHopLevel1(claimOf(v), { kernel: K, allFailures: true })
        const cheap = verifyHopLevel1(claimOf(v), { kernel: K, order: 'cost' })
        for (const verdict of [failed, all, cheap]) expect(verdict.length === 0).toBe(v.expected === 'accept')
        if (v.first_failure === null) return
        const { step, sample } = v.first_failure
        if (step === 'form') expect(failed.every((f) => /^form:(proof|mn|mp)$/.test(f))).toBe(true)
        else expect(failed).toEqual([sample === undefined ? step : `${step}:${sample}`])
        // Spec order stops where the full report starts.
        expect(all[0]).toBe(failed[0])
        // Cost order fails at the same sample or at an earlier path.
        if (step === 'residue' || step === 'path') {
          const [cs, ci] = cheap[0].split(':')
          expect(cs === step && Number(ci) === sample || (cs === 'path' && Number(ci) <= sample!)).toBe(true)
        } else expect(cheap).toEqual(failed)
      })
    }

    it('names the tag whose form fails', () => {
      const name = (n: string) => verifyHopLevel1(claimOf(VERIFIER.find((v) => v.name === n)!), { kernel: K })
      expect(name('proof-uppercase')).toEqual(['form:proof'])
      expect(name('proof-with-space')).toEqual(['form:proof'])
      expect(name('mn-0x-prefix')).toEqual(['form:mn'])
      expect(name('mn-missing')).toEqual(['form:mn'])
      expect(name('mp-letter-g')).toEqual(['form:mp'])
      expect(name('mp-missing')).toEqual(['form:mp'])
    })

    it('stops at the first failure by default, and reports every failing sample on request', () => {
      const claim = claimOf(VERIFIER.find((v) => v.name === 'two-openings-swapped')!)
      expect(verifyHopLevel1(claim, { kernel: K })).toEqual(['residue:3'])
      expect(verifyHopLevel1(claim, { kernel: K, order: 'cost' })).toEqual(['path:3'])
      expect(verifyHopLevel1(claim, { kernel: K, allFailures: true })).toEqual(['residue:3', 'path:3', 'residue:4', 'path:4'])
    })

    it('rejects a hop with no proof tag, a malformed previous id or a malformed event id', () => {
      expect(verifyHopLevel1(claimOf(VERIFIER[0], { proof: undefined }), { kernel: K })).toEqual(['form:proof'])
      expect(verifyHopLevel1(claimOf(VERIFIER[0], { previousEventIdHex: 'ab' }), { kernel: K })).toEqual(['previous_event_id'])
      expect(verifyHopLevel1(claimOf(VERIFIER[0], { eventId: STAND_IN_ID.toUpperCase() }), { kernel: K })).toEqual(['event_id'])
      expect(verifyHopLevel1(claimOf(VERIFIER[0], { eventId: '' }), { kernel: K })).toEqual(['event_id'])
    })

    it('requires the event id in the claim type', () => {
      const v = VERIFIER[0]
      const { eventId: _dropped, ...withoutId } = claimOf(v)
      // @ts-expect-error eventId is required: a claim without it does not typecheck.
      const claim: HopClaim = withoutId
      // A JavaScript caller that drops it anyway is refused, never silently unlisted.
      expect(verifyHopLevel1(claim, { kernel: K })).toEqual(['event_id'])
      expect(_dropped).toBe(STAND_IN_ID)
    })
  })

  // ------------------------------------------------------------- version 1 hops and the list

  describe('version 1 hops and the grandfathered list', () => {
    expect(V.grandfathered_v1).toHaveLength(4)
    for (const v of V.grandfathered_v1) {
      it(`${v.name}: ${v.expected}`, () => {
        const list = parseGrandfatheredList(v.grandfathered_v1_hops)
        const failed = verifyHopLevel1(claimOf(v, { eventId: v.event_id, grandfathered: list }), { kernel: K })
        expect(failed.length === 0).toBe(v.expected === 'accept')
        expect(isGrandfatheredV1Hop(v.event_id, list)).toBe(v.expected === 'accept')
      })
    }

    it('the real list is generated from the spec commit, and empty until the census', () => {
      expect(GRANDFATHERED_V1_HOPS_COMMIT).toBe(SPEC_COMMIT)
      expect(GRANDFATHERED_V1_HOPS.size).toBe(0)
      const v = V.grandfathered_v1[0]
      expect(verifyHopLevel1(claimOf(v, { eventId: v.event_id }), { kernel: K })).toEqual(['form:mn', 'form:mp'])
    })

    it('a listed version 1 hop is accepted through its event id, and only through it', () => {
      const v = V.grandfathered_v1[0]
      const list = parseGrandfatheredList(v.grandfathered_v1_hops)
      expect(verifyHopLevel1(claimOf(v, { eventId: v.event_id, grandfathered: list }), { kernel: K })).toEqual([])
      expect(verifyHopLevel1(claimOf(v, { grandfathered: list }), { kernel: K })).toEqual(['form:mn', 'form:mp'])
    })

    it('a listed hop still needs its tags well formed', () => {
      const v = V.grandfathered_v1[0]
      const list = new Set([v.event_id])
      expect(verifyHopLevel1(claimOf(v, { eventId: v.event_id, grandfathered: list, proof: v.tags.proof.toUpperCase() }), { kernel: K })).toEqual(['form:proof'])
      expect(verifyHopLevel1(claimOf(v, { eventId: v.event_id, grandfathered: list, nonce: '0x00000000000057' }), { kernel: K })).toEqual(['form:mn'])
      expect(verifyHopLevel1(claimOf(v, { eventId: v.event_id, grandfathered: list, openings: 'ab' }), { kernel: K })).toEqual(['form:mp'])
    })

    it('parses the list format and refuses anything else, loudly', () => {
      const id = 'ab'.repeat(32)
      const other = 'cd'.repeat(32)
      expect([...parseGrandfatheredList(`# header\n\n${id} pubkey 2026-10-30T00:00:00Z 0,13,0 11 L2-clean\n# ${other}\n${other}\tnote\n`)]).toEqual([id, other])
      expect([...parseGrandfatheredList(id)]).toEqual([id])
      for (const bad of [
        ` ${id}`, `\t${id}`, // leading whitespace
        ` # comment`, `\t#comment`, // an indented #
        ' ', '\t', '   \t ', // whitespace only
        `${id}\r`, '\r', // a carriage return
        id.toUpperCase(), id.slice(1), `${id}0`, `${id}x note`, `0x${id}`,
        `${id}\n${id}`, // listed twice
      ]) {
        expect(() => parseGrandfatheredList(`# ok\n${bad}\n`), JSON.stringify(bad)).toThrow()
      }
    })

    it('the 5.7 version 1 proof_hash still holds (5.6, 5.7), and audits as the census would', () => {
      const v1 = computeHopProof(0n, 0n, 0n, 4104n, 0n, 0n, 0, '0'.repeat(64))
      expect(v1.proofHash).toBe('ed9d09ca697b2da29c9d042207ac8ef7aab40f6dde550e6467452aa0e2e8cac6')
      expect(v1.terrainK).toBe(11)
      const v = V.grandfathered_v1[0]
      expect(v.tags.proof).toBe(v1.proofHash)
      expect(auditHopLevel2(claimOf(v), { kernel: K })).toEqual([])
      expect(auditHopLevel2(claimOf(v, { proof: '0'.repeat(64) }), { kernel: K })).toEqual(['proof'])
    })
  })

  // ------------------------------------------------------------- Level 2

  describe('Level 2 audit', () => {
    it('accepts every honest prover hop up to h13 and rejects the fabricated commitment', { timeout: 60_000 }, () => {
      for (const v of PROVER.filter((x) => x.h_max <= 13)) expect(auditHopLevel2(claimOf(v), { kernel: K }), v.name).toEqual([])
      const fab = VERIFIER.find((v) => v.name === 'fabricated-commitment')!
      const level1 = verifyHopLevel1(claimOf(fab), { kernel: K })
      expect(level1[0]).toBe('residue:0')
      expect(auditHopLevel2(claimOf(fab), { kernel: K })).toEqual(level1)
    })

    it('catches a seal over a list that is wrong only where no sample looked', () => {
      // A list wrong at one residue that the draw never opens passes Level 1 and fails Level 2.
      const v = prover('golden-5.7')
      const prev = hexToBytes(v.previous_event_id)
      const g = hopGeometry(prev, decodeCoord(v.c), decodeCoord(v.C))
      const primes = deriveHopPrimes(prev, v.m, K)
      const residues = computeHopResidues(primes, g, exactRoots(g), K, BIGINT_BACKEND)
      for (let wrong = 0; wrong < v.m; wrong++) {
        const mixed = residues.slice()
        setWord(mixed, wrong, (wordAt(mixed, wrong) + 1n) % (1n << 62n))
        const tree = hopSealTree(prev, mixed)
        const found = findHopNonce(prev, tree.seal, g.A, wordAt(primes, 0), K)!
        const idx = hopSampleIndices(found.attempt.G, g.m)
        if (idx.some((i) => Number(i) === wrong)) continue
        const tags = {
          proof: encodeSeal(tree.seal),
          mn: encodeHopNonce(found.nonce),
          mp: encodeHopOpenings(idx.map((i) => openHopBlock(tree, mixed, Number(i / 8n)))),
        }
        const claim = claimOf({ ...v, tags })
        expect(verifyHopLevel1(claim, { kernel: K })).toEqual([])
        expect(auditHopLevel2(claim, { kernel: K })).toEqual(['seal'])
        return
      }
      throw new Error('every position was sampled')
    })
  })

  // ------------------------------------------------------------- prices and sizes

  describe('prices', () => {
    it('B(h) for h from 0 to 60, exact', () => {
      expect(V.prices.budgets).toHaveLength(61)
      for (const { h, B } of V.prices.budgets) expect(hopRerollBudget(h).toString(), `h${h}`).toBe(B)
    })
    it('the budgets the reference prints, above h22', () => {
      for (const { h, B } of V.prices.reference_printed_budgets) expect(hopRerollBudget(h).toString()).toBe(B)
    })
    it('A for every set of heights', () => {
      expect(V.prices.attempts).toHaveLength(11)
      for (const { heights, A } of V.prices.attempts) expect(hopRerollAttempts(heights).toString(), heights.join(',')).toBe(A)
    })
  })

  describe('sizes', () => {
    it('m, depth and the mp length for h_max from 0 to 47', () => {
      expect(V.sizes).toHaveLength(48)
      for (const s of V.sizes) {
        const m = hopResidueCount(s.h_max)
        expect(m, `h${s.h_max}`).toBe(BigInt(s.m))
        expect(hopMerkleDepth(m)).toBe(s.depth)
        expect(hopOpeningsLength(s.depth)).toBe(s.mp_length)
      }
    })
    it('the h20 and h30 sizes of spec 5.12', () => {
      expect(hopResidueCount(20)).toBe(365288n)
      expect(hopMerkleDepth(365288n)).toBe(16)
      expect(hopOpeningsLength(16)).toBe(18432)
      expect(hopResidueCount(30)).toBe(374049408n)
      expect(hopMerkleDepth(374049408n)).toBe(26)
    })
  })

  // ------------------------------------------------------------- tag strictness

  describe('tag encoding and decoding', () => {
    const v = prover('golden-5.7')
    const seal = v.tags.proof
    const mn = v.tags.mn
    const mp = v.tags.mp

    it('round-trips', () => {
      expect(encodeSeal(decodeSeal(seal)!)).toBe(seal)
      expect(decodeHopNonce(mn)).toBe(87n)
      expect(encodeHopNonce(87n)).toBe(mn)
      expect(encodeHopNonce(2n ** 64n - 1n)).toBe('f'.repeat(16))
      expect(() => encodeHopNonce(2n ** 64n)).toThrow()
      expect(encodeHopOpenings(decodeHopOpenings(mp, v.depth)!)).toBe(mp)
    })

    it('the proof tag is exactly 64 lowercase hex characters', () => {
      for (const bad of [seal.toUpperCase(), '0x' + seal.slice(2), '+' + seal.slice(1), ' ' + seal.slice(1), seal.slice(0, 32) + '_' + seal.slice(33), seal.slice(1), seal + '0', '', 'g' + seal.slice(1)]) {
        expect(decodeSeal(bad), JSON.stringify(bad)).toBeNull()
      }
    })

    it('the mn tag is exactly 16 lowercase hex characters', () => {
      for (const bad of ['0x00000000000057', '+000000000000057', '0000000_00000057', ' 000000000000057', '00000000000000AB', mn.slice(1), mn + '0', '', '000000000000005g', '-000000000000057']) {
        expect(decodeHopNonce(bad), JSON.stringify(bad)).toBeNull()
      }
    })

    it('the mp tag is exactly 16 (128 + 64 depth) characters of 0-9 and a-f', () => {
      expect(mp.length).toBe(hopOpeningsLength(v.depth))
      for (const bad of [mp.toUpperCase(), '0x' + mp.slice(2), '+' + mp.slice(1), ' ' + mp.slice(1), mp.slice(0, 100) + '_' + mp.slice(101), mp.slice(1), mp + '0', mp.slice(0, -64), mp.slice(0, -1) + 'g', '']) {
        expect(decodeHopOpenings(bad, v.depth), `${bad.slice(0, 8)} (${bad.length})`).toBeNull()
      }
      expect(decodeHopOpenings(mp, v.depth - 1)).toBeNull()
      expect(decodeHopOpenings(mp, v.depth + 1)).toBeNull()
    })

    it('a depth-0 hop carries 16 openings of 128 characters and no siblings', () => {
      const z = prover('h0-k-zero')
      const openings = decodeHopOpenings(z.tags.mp, 0)!
      expect(z.tags.mp.length).toBe(2048)
      expect(openings.every((o) => o.siblings.length === 0)).toBe(true)
    })
  })

  // ------------------------------------------------------------- properties at small heights

  describe('properties', () => {
    const next = rng(3333n)
    const prev = new Uint8Array(32).map((_, i) => i)
    const primes = wordsOf(deriveHopPrimes(prev, 64, K))

    it('a root modulo p is the same tree carried modulo p (5.9), for random bases and primes', () => {
      for (let trial = 0; trial < 60; trial++) {
        const h = Number(next() % 11n)
        const base = alignedBase(next() & ((1n << 85n) - 1n), h)
        const p = primes[Number(next() % 64n)]
        const exact = computeSubtreeCantor(base, h, 30) % p
        expect(residueTree(base, h, p), `h${h}`).toBe(exact)
        expect(residueEngine(base, h, p), `h${h}`).toBe(exact)
        expect(K.rootResidue(p, base, h), `h${h}`).toBe(exact)
      }
    })

    it('the difference engine equals the residue tree at every level k', () => {
      for (const h of [4, 7, 10]) {
        const base = alignedBase(next() & ((1n << 85n) - 1n), h)
        const p = primes[Number(next() % 64n)]
        const want = residueTree(base, h, p)
        for (let k = 0; k <= h; k++) expect(residueEngine(base, h, p, k), `h${h} k${k}`).toBe(want)
      }
    })

    it('the kernel agrees with BigInt above the property heights, unaligned bases included', () => {
      for (const h of [12, 14, 16]) {
        const base = next() & ((1n << 85n) - 1n)
        const p = primes[Number(next() % 64n)]
        expect(K.rootResidue(p, base, h), `h${h}`).toBe(residueEngine(base, h, p))
      }
    })

    it('pairing modulo p is the pairing reduced modulo p, in BigInt and in the kernel', () => {
      for (let trial = 0; trial < 200; trial++) {
        const p = primes[trial % 64]
        const a = next() >> BigInt(Number(next() % 64n))
        const b = next() >> BigInt(Number(next() % 64n))
        const want = cantorPair(a, b) % p
        expect(pairModP(a, b, p)).toBe(want)
        expect(K.pairMod(p, a % p, b % p)).toBe(want)
      }
    })

    it('the kernel combine is the pairings folded from the left, modulo each prime', () => {
      const m = 64
      const list = deriveHopPrimes(prev, m, K)
      const parts = [0, 1, 2, 3].map(() => {
        const part = wordList(m)
        for (let j = 0; j < m; j++) setWord(part, j, next() % wordAt(list, j))
        return part
      })
      const out = wordList(m)
      K.combine(list, parts, out)
      const two = wordList(m)
      K.combine(list, parts.slice(0, 2), two)
      for (let j = 0; j < m; j++) {
        const p = wordAt(list, j)
        const [a, b, c, d] = parts.map((x) => wordAt(x, j))
        expect(wordAt(out, j)).toBe(pairModP(pairModP(pairModP(a, b, p), c, p), d, p))
        expect(wordAt(two, j)).toBe(pairModP(a, b, p))
      }
    })

    it('every hop prime is the first candidate of the 5.9 search, in BigInt', () => {
      const sprp2 = (n: bigint): boolean => {
        let d = n - 1n, r = 0
        while ((d & 1n) === 0n) { d >>= 1n; r++ }
        let x = 1n, b = 2n, e = d
        while (e > 0n) { if (e & 1n) x = (x * b) % n; b = (b * b) % n; e >>= 1n }
        if (x === 1n || x === n - 1n) return true
        for (let i = 1; i < r; i++) { x = (x * x) % n; if (x === n - 1n) return true }
        return false
      }
      const reference = (start: bigint): bigint => {
        let n = start
        while (SMALL_ODD_PRIMES.some((q) => n % BigInt(q) === 0n) || !sprp2(n)) n += 2n
        return n
      }
      for (let j = 0; j < 64; j++) {
        const start = hopPrimeStart(prev, j)
        expect(start & 1n).toBe(1n)
        const p = reference(start)
        expect(primes[j]).toBe(p)
        expect(p >= 1n << 61n && p < 1n << 62n).toBe(true)
      }
      // An index far above 2^32 uses its own midstate block and its own prime.
      expect(hopPrime(prev, 2n ** 60n, K)).toBe(reference(hopPrimeStart(prev, 2n ** 60n)))
    })

    it('every residue the prover seals is hop_n modulo its prime, for small hops on every path', { timeout: 60_000 }, () => {
      const cases: Array<[Xyz, Xyz]> = [
        [{ x: 5n, y: 9n, z: 1n, plane: 0 }, { x: 6n, y: 9n, z: 1n, plane: 0 }],
        [{ x: 1021n, y: 77n, z: 5n, plane: 0 }, { x: 1024n, y: 128n, z: 260n, plane: 0 }],
        [{ x: 3n, y: 3n, z: 3n, plane: 0 }, { x: 3n, y: 3n, z: 3n, plane: 1 }],
        [{ x: 0n, y: 200n, z: 0n, plane: 1 }, { x: 0n, y: 17n, z: 40n, plane: 1 }],
      ]
      for (const [from, to] of cases) {
        const id = sha256(intToBytesBE(xyzToCoord(to.x, to.y, to.z, to.plane)))
        const g = hopGeometry(id, from, to)
        const roots = exactRoots(g)
        const hopN = cantorPair(cantorPair(cantorPair(roots.x, roots.y), roots.z), roots.t)
        const list = deriveHopPrimes(id, Number(g.m), K)
        const residues = computeHopResidues(list, g, roots, K, BIGINT_BACKEND)
        for (let j = 0; j < Number(g.m); j++) expect(wordAt(residues, j)).toBe(hopN % wordAt(list, j))
        expect(hopResidue(g, wordAt(list, 5), K)).toBe(hopN % wordAt(list, 5))
      }
    })

    it('the remainder tree descends to every prime, and region_n mod Q pairs exactly', () => {
      const m = 40
      const list = deriveHopPrimes(prev, m, K)
      const tree = BIGINT_BACKEND.productTree(list)
      const Q = tree.levels[tree.levels.length - 1][0]
      expect(Q).toBe(wordsOf(list).reduce((a, b) => a * b, 1n))
      const x = computeSubtreeCantor(0n, 12)
      const out = wordList(m)
      BIGINT_BACKEND.remainders(tree, x, out)
      for (let j = 0; j < m; j++) expect(wordAt(out, j)).toBe(x % wordAt(list, j))
      const y = computeSubtreeCantor(4096n, 11)
      expect(BIGINT_BACKEND.pairModQ(tree, x, y)).toBe(cantorPair(x, y) % Q)
    })

    it('a copied proof shares no primes with another chain position', () => {
      const other = deriveHopPrimes(new Uint8Array(32).map((_, i) => 32 + i), 64, K)
      const mine = new Set(primes)
      expect(wordsOf(other).filter((p) => mine.has(p))).toEqual([])
    })
  })

  // ------------------------------------------------------------- what a forgery costs the verifier

  describe('a junk tree under a paid price (the review of PR #9)', () => {
    // A random seal at h20 on one axis, the nonce ground for it (8475, the
    // first from 0 that meets A, about a second of JavaScript), and an mp of
    // zeros. Replayable across events, so its cost to a verifier is what matters.
    const prev = '5a'.repeat(32)
    const E = 1n << 84n
    const from: Xyz = { x: E, y: E, z: E, plane: 0 }
    const to: Xyz = { x: E ^ (1n << 19n), y: E, z: E, plane: 0 }
    const g = hopGeometry(hexToBytes(prev), from, to)
    const seal = new Uint8Array(32).fill(7)
    const claim: HopClaim = {
      from, to, previousEventIdHex: prev, eventId: STAND_IN_ID,
      proof: encodeSeal(seal), nonce: encodeHopNonce(8475n), openings: '0'.repeat(hopOpeningsLength(g.depth)),
    }

    it('is a real forgery: the nonce meets the price at h20', () => {
      expect(g.hMax).toBe(20)
      expect(g.A).toBe(44856n)
      const G = hopAttempt(hexToBytes(prev), seal, 8475n, hopPrime(hexToBytes(prev), 0, K), K).G
      expect(G[0]).toBe(0) // a cheap necessary condition first
      expect(verifyHopLevel1(claim, { kernel: K, order: 'cost' })).not.toContain('price')
    })

    it('costs no residue in cost order, one in spec order and 16 for every failure, counted', () => {
      // Counted, not timed: a residue is the four component roots of one sample
      // (the h20 axis among them), a prime is one search, and the attempt is
      // one height-12 root over g_base (or one whole attempt in the kernel).
      const gBase = hopAttempt(hexToBytes(prev), seal, 8475n, hopPrime(hexToBytes(prev), 0, K), K).gBase
      const run = (options: Omit<HopVerifyOptions, 'kernel'>): { verdict: string[]; tall: number; sampleRoots: number; attempts: number; primes: number } => {
        const c = counting(K)
        const verdict = verifyHopLevel1(claim, { ...options, kernel: c.kernel })
        const isAttempt = (r: CountedRoot): boolean => r.height === HOP_GRIND_HEIGHT && r.base === gBase
        return {
          verdict,
          tall: c.roots.filter((r) => r.height === 20 && r.base === g.axes[0].base).length,
          sampleRoots: c.roots.filter((r) => !isAttempt(r)).length,
          attempts: c.roots.filter(isAttempt).length + c.attempts,
          primes: c.primes,
        }
      }
      expect(run({ order: 'cost' })).toEqual({ verdict: ['path:0'], tall: 0, sampleRoots: 0, attempts: 1, primes: 1 })
      expect(run({})).toEqual({ verdict: ['residue:0'], tall: 1, sampleRoots: 4, attempts: 1, primes: 2 })
      const all = run({ allFailures: true })
      expect(all.verdict).toHaveLength(32)
      expect({ ...all, verdict: undefined }).toEqual({ verdict: undefined, tall: 16, sampleRoots: 64, attempts: 1, primes: 17 })
    })
  })
})

// ------------------------------------------------------------- the committed WASM module

describeBothKernels('the committed WASM kernel', () => {
  const dir = new URL('../src/residue/', import.meta.url)
  const recorded: string = readFileSync(new URL('kern.sha256', dir), 'utf8')
  const hashOf = (file: string): string => {
    const line = recorded.split('\n').find((l: string) => l.split(/\s+/)[1] === file)
    if (!line) throw new Error(`kern.sha256 records no ${file}`)
    return line.split(/\s+/)[0]
  }

  it('is the module recorded in kern.sha256, built from the source recorded there', () => {
    const bytes = wasmWordKernelBytes()
    expect(bytesToHex(sha256(bytes))).toBe(hashOf('kern.wasm'))
    expect(recorded).toContain(`the ${bytes.length} bytes of KERN_WASM_BASE64`)
    expect(bytesToHex(sha256(new Uint8Array(readFileSync(new URL('kern.ts', dir)))))).toBe(hashOf('kern.ts'))
    expect(btoa(String.fromCharCode(...bytes))).toBe(KERN_WASM_BASE64)
    expect(WebAssembly.validate(bytes.buffer as ArrayBuffer)).toBe(true)
  })

  it('rebuilds byte for byte from kern.ts with the pinned AssemblyScript', { timeout: 60_000 }, async () => {
    // The build script's own functions, so the test and the script cannot drift apart.
    const script = new URL('../scripts/build-kernel.mjs', import.meta.url).href
    const { compileKernel, moduleText, hashesText } = await import(/* @vite-ignore */ script)
    const wasm: Uint8Array = await compileKernel()
    expect(bytesToHex(sha256(wasm))).toBe(hashOf('kern.wasm'))
    expect(moduleText(wasm)).toBe(readFileSync(new URL('kernWasm.ts', dir), 'utf8'))
    expect(hashesText(readFileSync(new URL('kern.ts', dir)), wasm)).toBe(recorded)
  })

  it('instantiates from its bytes alone: one import (env.abort), memory and the kernel exported, nothing fetched', async () => {
    const module = await WebAssembly.compile(wasmWordKernelBytes().buffer as ArrayBuffer)
    expect(WebAssembly.Module.imports(module)).toEqual([{ module: 'env', name: 'abort', kind: 'function' }])
    const exports = WebAssembly.Module.exports(module).map((e) => e.name)
    for (const name of ['memory', 'searchBatch', 'primesBatch', 'residue', 'hopResidue', 'pairMod', 'combineBatch', 'combine2Batch', 'attempt', 'grind']) {
      expect(exports).toContain(name)
    }
  })
})

describeBothKernels('choosing a kernel', () => {
  it('an explicit choice, and a default that is WASM wherever WebAssembly runs', async () => {
    expect(selectWordKernel('js')).toBe(JS_WORD_KERNEL)
    expect(selectWordKernel('wasm')).toBe(WASM_WORD_KERNEL)
    expect(wasmWordKernelReady()).toBe(true)
    expect(selectWordKernel()).toBe(WASM_WORD_KERNEL)
    expect(selectWordKernel('auto')).toBe(WASM_WORD_KERNEL)
    expect(await loadWasmWordKernel()).toBe(WASM_WORD_KERNEL)
    expect([JS_WORD_KERNEL.name, WASM_WORD_KERNEL.name]).toEqual(['js', 'wasm'])
  })

  it('the default reaches every function that takes a kernel', () => {
    const v = prover('golden-5.7')
    const prev = hexToBytes(v.previous_event_id)
    // In Node the default is WASM: the defaults give the vectors' values.
    expect(hopPrime(prev, 0)).toBe(2501841973170584791n)
    expect(bytesToHex(hopAttempt(prev, hexToBytes(v.seal), BigInt(v.nonce), hopPrime(prev, 0)).G)).toBe(v.G)
    expect(verifyHopLevel1(claimOf(v))).toEqual([])
    expect(findHopNonce(prev, hexToBytes(v.seal), BigInt(v.A), hopPrime(prev, 0))?.nonce).toBe(BigInt(v.nonce))
  })
})

// ------------------------------------------------------------- the two kernels against each other

describeBothKernels('the two kernels agree', () => {
  const next = rng(0x5eed2n)
  const TWO_61 = 1n << 61n
  const TWO_62 = 1n << 62n
  const TWO_64 = 1n << 64n
  const bytes32 = (): Uint8Array => {
    const out = new Uint8Array(32)
    for (let i = 0; i < 4; i++) out.set(be64Bytes(next()), 8 * i)
    return out
  }
  const be64Bytes = (v: bigint): Uint8Array => {
    const out = new Uint8Array(8)
    new DataView(out.buffer).setBigUint64(0, v)
    return out
  }
  const isPrime = (n: bigint): boolean => {
    // Deterministic Miller-Rabin for n < 3.3e24 with these bases.
    if (n % 2n === 0n) return false
    let d = n - 1n, r = 0
    while ((d & 1n) === 0n) { d >>= 1n; r++ }
    const pow = (b: bigint, e: bigint): bigint => { let x = 1n; b %= n; while (e > 0n) { if (e & 1n) x = (x * b) % n; b = (b * b) % n; e >>= 1n } return x }
    outer: for (const a of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n]) {
      let x = pow(a, d)
      if (x === 1n || x === n - 1n) continue
      for (let i = 1; i < r; i++) { x = (x * x) % n; if (x === n - 1n) continue outer }
      return false
    }
    return true
  }
  // The moduli at both ends of the kernels' range, and random hop primes between.
  const LOW: bigint[] = []
  for (let n = TWO_61 + 1n; LOW.length < 3; n += 2n) if (isPrime(n)) LOW.push(n)
  const HIGH: bigint[] = []
  for (let n = TWO_62 - 1n; HIGH.length < 3; n -= 2n) if (isPrime(n)) HIGH.push(n)
  const randomPrimes = wordsOf(deriveHopPrimes(bytes32(), 24, JS_WORD_KERNEL))
  const MODULI = [...LOW, ...HIGH, ...randomPrimes]
  const edges = (p: bigint): bigint[] => [0n, 1n, 2n, p - 1n, p - 2n, (p - 1n) / 2n, (p + 1n) / 2n, TWO_61 % p, (TWO_64 - 1n) % p, next() % p]

  it('the moduli at the ends of the range are what they should be', () => {
    for (const p of [...LOW, ...HIGH]) expect(isPrime(p) && p > TWO_61 && p < TWO_62).toBe(true)
    expect(HIGH[0]).toBe(TWO_62 - 57n) // the largest prime below 2^62
  })

  it('pairMod on the edges of every modulus, against the definition', () => {
    for (const p of MODULI) {
      for (const a of edges(p)) for (const b of edges(p)) {
        const want = pairModP(a, b, p)
        expect(JS_WORD_KERNEL.pairMod(p, a, b), `${p} ${a} ${b}`).toBe(want)
        expect(WASM_WORD_KERNEL.pairMod(p, a, b), `${p} ${a} ${b}`).toBe(want)
      }
    }
  })

  it('rootResidue on random and edge bases, heights 0 to 16, every modulus', () => {
    for (const p of MODULI) {
      const bases = [0n, 1n, p - 1n, p, p + 1n, 2n * p - 1n, (1n << 85n) - 1n, next() & ((1n << 85n) - 1n), alignedBase(next() & ((1n << 85n) - 1n), 10)]
      for (const base of bases) {
        const h = Number(next() % 17n)
        const js = JS_WORD_KERNEL.rootResidue(p, base, h)
        expect(WASM_WORD_KERNEL.rootResidue(p, base, h), `${p} ${base} h${h}`).toBe(js)
        if (h <= 8) expect(js).toBe(residueTree(base, h, p))
      }
      // The attempt's height, which both kernels give its own engine level.
      const base = alignedBase(next() & ((1n << 85n) - 1n), HOP_GRIND_HEIGHT)
      expect(WASM_WORD_KERNEL.rootResidue(p, base, HOP_GRIND_HEIGHT)).toBe(JS_WORD_KERNEL.rootResidue(p, base, HOP_GRIND_HEIGHT))
    }
  })

  it('the prime search from random starts and from both ends of the range', () => {
    const starts: bigint[] = [TWO_61 + 1n, TWO_61 + 3n, TWO_62 - 1001n, TWO_62 - 59n, TWO_62 - 57n]
    for (let i = 0; i < 40; i++) starts.push(TWO_61 + ((next() >> 4n) | 1n)) // where hop prime searches start
    const list = wordList(starts.length)
    starts.forEach((v, j) => setWord(list, j, v))
    const a = wordList(starts.length), b = wordList(starts.length)
    JS_WORD_KERNEL.searchPrimes(list, a)
    WASM_WORD_KERNEL.searchPrimes(list, b)
    expect(wordsOf(b)).toEqual(wordsOf(a))
    expect(wordAt(a, 3)).toBe(TWO_62 - 57n)
    expect(wordAt(a, 4)).toBe(TWO_62 - 57n)
    for (const p of wordsOf(a)) expect(isPrime(p)).toBe(true)
  })

  it('the primes of random ids, through each kernel whole and through the composition', () => {
    for (let trial = 0; trial < 6; trial++) {
      const prev = bytes32()
      const m = 8 + Number(next() % 300n)
      const js = deriveHopPrimes(prev, m, JS_WORD_KERNEL)
      expect(wordsOf(deriveHopPrimes(prev, m, WASM_WORD_KERNEL))).toEqual(wordsOf(js))
      // The WASM kernel's whole step, against its own prime search under residue.ts's hashing.
      const composed = counting(WASM_WORD_KERNEL)
      const plain: WordKernel = { name: 'plain', searchPrimes: composed.kernel.searchPrimes, rootResidue: composed.kernel.rootResidue, pairMod: composed.kernel.pairMod, combine: composed.kernel.combine }
      expect(wordsOf(deriveHopPrimes(prev, m, plain))).toEqual(wordsOf(js))
      expect(composed.primes).toBe(m)
      for (const j of [0n, 1n, 255n, 256n, (1n << 32n) + 1n, (1n << 56n) - 1n, 1n << 56n, (1n << 56n) + 3n, TWO_64 - 1n]) {
        expect(hopPrime(prev, j, WASM_WORD_KERNEL), `j ${j}`).toBe(hopPrime(prev, j, JS_WORD_KERNEL))
      }
    }
  })

  it('combine of 1 to 5 parts, edge and random entries, against the pairings folded', () => {
    const m = 70
    const list = deriveHopPrimes(bytes32(), m, JS_WORD_KERNEL)
    for (let n = 1; n <= 5; n++) {
      const parts = Array.from({ length: n }, () => {
        const part = wordList(m)
        for (let j = 0; j < m; j++) {
          const p = wordAt(list, j)
          const e = edges(p)
          setWord(part, j, e[Number(next() % BigInt(e.length))])
        }
        return part
      })
      const a = wordList(m), b = wordList(m)
      JS_WORD_KERNEL.combine(list, parts, a)
      WASM_WORD_KERNEL.combine(list, parts, b)
      expect(wordsOf(b), `${n} parts`).toEqual(wordsOf(a))
      for (let j = 0; j < m; j++) {
        const p = wordAt(list, j)
        expect(wordAt(a, j)).toBe(parts.map((x) => wordAt(x, j)).reduce((acc, v) => pairModP(acc, v, p)))
      }
    }
  })

  it('attempts for random ids, seals and nonces across the whole 64-bit range', () => {
    const nonces = [0n, 1n, 87n, (1n << 32n) - 1n, 1n << 32n, (1n << 56n) - 1n, 1n << 56n, 1n << 63n, TWO_64 - 2n, TWO_64 - 1n]
    for (let trial = 0; trial < 8; trial++) {
      const prev = bytes32(), seal = bytes32()
      const p0 = hopPrime(prev, 0, JS_WORD_KERNEL)
      for (const nonce of [...nonces, next()]) {
        const js = hopAttempt(prev, seal, nonce, p0, JS_WORD_KERNEL)
        const wasm = hopAttempt(prev, seal, nonce, p0, WASM_WORD_KERNEL)
        expect(wasm, `nonce ${nonce}`).toEqual(js)
      }
    }
  })

  it('the nonce search: the same first nonce and attempt, every range, every price', () => {
    for (let trial = 0; trial < 6; trial++) {
      const prev = bytes32(), seal = bytes32()
      const p0 = hopPrime(prev, 0, JS_WORD_KERNEL)
      for (const A of [1n, 3n, 179n, 1000n]) {
        const js = findHopNonce(prev, seal, A, p0, JS_WORD_KERNEL)
        expect(findHopNonce(prev, seal, A, p0, WASM_WORD_KERNEL), `A ${A}`).toEqual(js)
      }
      // A range that ends at 2^64, and one that is empty.
      const top = { start: TWO_64 - 40n, end: TWO_64 }
      expect(findHopNonce(prev, seal, 7n, p0, WASM_WORD_KERNEL, top)).toEqual(findHopNonce(prev, seal, 7n, p0, JS_WORD_KERNEL, top))
      expect(findHopNonce(prev, seal, 1n, p0, WASM_WORD_KERNEL, { start: 5n, end: 5n })).toBeNull()
    }
  })

  it('the price at its boundary, G A against 2^256 exactly, and prices past 2^64', () => {
    const v = prover('golden-5.7')
    const prev = hexToBytes(v.previous_event_id), seal = hexToBytes(v.seal)
    const p0 = hopPrime(prev, 0, JS_WORD_KERNEL)
    const nonce = BigInt(v.nonce)
    const G = BigInt('0x' + v.G)
    const most = ((1n << 256n) - 1n) / G // the largest A this G meets
    const one = { start: nonce, end: nonce + 1n }
    for (const kernel of KERNELS) {
      expect(findHopNonce(prev, seal, most, p0, kernel, one)?.nonce, kernel.name).toBe(nonce)
      expect(findHopNonce(prev, seal, most + 1n, p0, kernel, one), kernel.name).toBeNull()
    }
    // The module's price is a u64: 2^64 - 1 still runs in it, 2^64 and above take the composed search.
    const range = { start: 0n, end: 300n }
    for (const A of [TWO_64 - 1n, TWO_64, TWO_64 + 12345n, 1n << 100n]) {
      expect(findHopNonce(prev, seal, A, p0, WASM_WORD_KERNEL, range), `A ${A}`).toEqual(findHopNonce(prev, seal, A, p0, JS_WORD_KERNEL, range))
    }
  })

  it('progress reports through a kernel that searches whole ranges', () => {
    const v = prover('golden-5.7')
    const prev = hexToBytes(v.previous_event_id)
    const seen: number[] = []
    const found = findHopNonce(prev, hexToBytes(v.seal), BigInt(v.A), hopPrime(prev, 0, JS_WORD_KERNEL), WASM_WORD_KERNEL, { onProgress: (f) => seen.push(f) })
    expect(found?.nonce).toBe(BigInt(v.nonce))
    expect(seen.length).toBeGreaterThan(5)
    for (let i = 1; i < seen.length; i++) expect(seen[i]).toBeGreaterThanOrEqual(seen[i - 1])
    expect(seen[seen.length - 1]).toBe(1)
  })

  it('the module as lifted: hopResidue and the plain tree (k < 0) give the residues', async () => {
    const { instance } = await WebAssembly.instantiate(wasmWordKernelBytes().buffer as ArrayBuffer, { env: { abort: () => { throw new Error('abort') } } })
    const X = instance.exports as unknown as {
      hopResidue(p: bigint, ...args: (bigint | number)[]): bigint
      residue(p: bigint, baseMod: bigint, h: number, k: number): bigint
    }
    for (let trial = 0; trial < 12; trial++) {
      const from: Xyz = { x: next() >> 171n, y: next() >> 171n, z: next() >> 171n, plane: 0 }
      const to: Xyz = { x: from.x ^ (next() & 0xfffn), y: from.y ^ (next() & 0xffn), z: from.z ^ (next() & 0x3fn), plane: Number(next() & 1n) as 0 | 1 }
      const g = hopGeometry(bytes32(), from, to)
      const p = MODULI[trial % MODULI.length]
      const args: (bigint | number)[] = []
      for (const t of [...g.axes, g.temporal]) args.push(t.base % p, t.height, Math.max(0, (t.height - 2) >> 1))
      expect(X.hopResidue(p, ...args), `trial ${trial}`).toBe(hopResidue(g, p, JS_WORD_KERNEL))
      const h = Number(next() % 11n)
      const base = next() & ((1n << 85n) - 1n)
      expect(X.residue(p, base % p, h, -1)).toBe(residueTree(base, h, p))
    }
  })
})
