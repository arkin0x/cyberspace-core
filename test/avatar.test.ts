/**
 * avatar.test.ts - the work an avatar owes (spec 8.10), pinned to the spec's
 * golden vectors, fixtures/avatar-vectors.json, which the Python core shares.
 */
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import {
  AVATAR_CONTENT_MAX, AVATAR_DETAIL_BITS, AVATAR_DETAIL_FREE, AVATAR_FLOOR_BITS, AVATAR_KIND, AVATAR_SIZE_BITS,
  avatarBits, avatarContentBytes, avatarReach, avatarWork, leadingZeroBits, verifyAvatarWork,
  type AvatarPayload,
} from '../src/avatar.js'

const RAW = readFileSync(new URL('./fixtures/avatar-vectors.json', import.meta.url), 'utf8')
/** The spec commit the file was copied from, and its hash: copy it again to update, never edit it here. */
export const AVATAR_VECTORS_SPEC_COMMIT = '9caa0c4'
const AVATAR_VECTORS_SHA256 = '8ba4852221e3ebb8a4f88d63c1ce36cba959e250b691cc2a212f27393760b955'

interface PriceRow { reach: number; detail?: number; vertices?: number; faces?: number; required: number; required_before_2026_11: number; name?: string; refused?: boolean; bytes?: number }
interface Verdict { ok: boolean; required: number; committed: number | null; zeros: number; reason: string }
interface Ev { kind: number; id: string; pubkey: string; created_at: number; tags: string[][]; content: string | null; content_recipe?: { prefix: string; fill: string; count: number; suffix: string } }
export interface AvatarVectors {
  constants: { kind: number; floor_bits: number; size_bits: number; detail_bits: number; detail_free: number; content_max: number }
  price: Array<PriceRow & { name: string; payload: AvatarPayload; detail: number }>
  bits: Array<PriceRow & { detail: number }>
  corpus: Array<PriceRow & { name: string; vertices: number; faces: number; bytes: number; refused: boolean }>
  content_limit: Array<{ bytes: number; refused: boolean }>
  verdicts: Array<{ name: string; event: Ev; verdict: Verdict }>
  mined: Array<{ name: string; template: { pubkey: string; created_at: number; kind: number; tags: string[][]; content: string }; target: number; lead: string; tries: number; event: Ev & { content: string }; verdict: Verdict }>
}
const V: AvatarVectors = JSON.parse(RAW)
const content = (e: Ev): string => e.content ?? `${e.content_recipe!.prefix}${e.content_recipe!.fill.repeat(e.content_recipe!.count)}${e.content_recipe!.suffix}`

describe('the vectors', () => {
  it('are the spec file, unchanged', () => {
    expect(createHash('sha256').update(RAW).digest('hex')).toBe(AVATAR_VECTORS_SHA256)
  })
  it('carry the constants this module uses', () => {
    expect(V.constants).toMatchObject({ kind: AVATAR_KIND, floor_bits: AVATAR_FLOOR_BITS, size_bits: AVATAR_SIZE_BITS, detail_bits: AVATAR_DETAIL_BITS, detail_free: AVATAR_DETAIL_FREE, content_max: AVATAR_CONTENT_MAX })
  })
})

describe('avatarWork', () => {
  for (const v of V.price) {
    it(`${v.name}: reach ${v.reach}, ${v.required} bits`, () => {
      expect(avatarReach(v.payload)).toBeCloseTo(v.reach, 9)
      expect(avatarWork(v.payload)).toBe(v.required)
    })
  }
})

describe('avatarBits', () => {
  for (const v of V.bits) {
    it(`reach ${v.reach}, detail ${v.detail}: ${v.required} bits`, () => expect(avatarBits(v.reach, v.detail)).toBe(v.required))
  }
  it('rounds the sum up once, not each term', () => {
    // 2 log2(1.5) + 1.5 log2(48 / 32) is 1.17 + 0.88: 10 + 2.05 rounds up to 13, not 12.
    expect(avatarBits(1.5, 48)).toBe(13)
  })
  it('prices the ladder the spec quotes, and nothing under a gibson or under 32', () => {
    expect([1, 2, 4, 16, 1000].map((r) => avatarBits(r, 32))).toEqual([10, 12, 14, 18, 30])
    expect(avatarBits(0.25, 8)).toBe(10)
    expect(avatarBits(2 ** 85, 32)).toBe(180)
  })
  it('never asks more than the rule before 2026-11', () => {
    for (const v of [...V.price, ...V.bits, ...V.corpus]) expect(v.required).toBeLessThanOrEqual(v.required_before_2026_11)
  })
})

describe('the avatar study corpus', () => {
  for (const v of V.corpus) {
    it(`${v.name}: ${v.required} bits${v.refused ? ', refused' : ''}`, () => {
      expect(avatarBits(v.reach, v.vertices + v.faces)).toBe(v.required)
      expect(v.bytes > AVATAR_CONTENT_MAX).toBe(v.refused)
    })
  }
})

describe('leadingZeroBits', () => {
  it('counts as NIP-13 does', () => {
    expect(leadingZeroBits('0000ffff')).toBe(16)
    expect(leadingZeroBits('000f')).toBe(12)
    expect(leadingZeroBits('00')).toBe(8)
    expect(leadingZeroBits('1abc')).toBe(3)
    expect(leadingZeroBits('ffff')).toBe(0)
    expect(leadingZeroBits('')).toBe(0)
  })
})

describe('verifyAvatarWork', () => {
  for (const v of V.verdicts) {
    it(`${v.name}: ${v.verdict.reason}`, () => {
      expect(verifyAvatarWork({ ...v.event, content: content(v.event) })).toEqual(v.verdict)
    })
  }
  it('counts the limit in UTF-8 bytes, not characters', () => {
    const prefix = '{"vertices":[[0,0,0]],"faces":[],"pad":"'
    // 2-byte characters: under the limit in characters, over it in bytes.
    const body = `${prefix}${'é'.repeat((AVATAR_CONTENT_MAX - prefix.length) / 2 + 1)}"}`
    expect(body.length).toBeLessThan(AVATAR_CONTENT_MAX)
    expect(avatarContentBytes(body)).toBeGreaterThan(AVATAR_CONTENT_MAX)
    expect(verifyAvatarWork({ kind: AVATAR_KIND, id: '0'.repeat(64), tags: [['nonce', '0', '10']], content: body }).reason).toBe('too-large')
  })
  it('is not fooled by a lucky id claimed against a lower bar', () => {
    const v = V.verdicts.find((x) => x.name === 'committed below the price')!
    expect(v.verdict.zeros).toBeGreaterThan(v.verdict.required)
    expect(verifyAvatarWork({ ...v.event, content: content(v.event) }).ok).toBe(false)
  })
})
