/**
 * avatar.test.ts - what a reader checks on an avatar (spec 8.10), pinned to
 * the spec's golden vectors, fixtures/avatar-vectors.json, which the Python
 * core shares. An avatar carries no proof of work: no verdict reads a tag.
 */
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import * as core from '../src/index.js'
import {
  AVATAR_CONTENT_MAX, AVATAR_CONTENT_WARN, AVATAR_KIND,
  avatarContentBytes, avatarReach, avatarReadable, leadingZeroBits, verifyAvatar, verifyAvatarWork,
} from '../src/avatar.js'

const RAW = readFileSync(new URL('./fixtures/avatar-vectors.json', import.meta.url), 'utf8')
/** The spec commit the file was copied from (PR #109's branch; re-pin to its merge commit), and its hash. */
export const AVATAR_VECTORS_SPEC_COMMIT = '938b1050320de6afce5d3646a1c2c06166744e02'
const AVATAR_VECTORS_SHA256 = '22830c6e13ef4f259337197624ba52e8cdf96f5ef66449adb2386939ae84725f'

interface Ev { kind: number; id: string; pubkey: string; created_at: number; tags: string[][]; content: string | null; content_recipe?: { prefix: string; fill: string; count: number; suffix: string } }
interface Vectors {
  constants: { kind: number; content_max: number }
  content_limit: Array<{ bytes: number; refused: boolean }>
  corpus: Array<{ name: string; bytes: number; vertices: number; faces: number; refused: boolean }>
  verdicts: Array<{ name: string; event: Ev; verdict: { ok: boolean; reason: string } }>
}
const V: Vectors = JSON.parse(RAW)
const content = (e: Ev): string => e.content ?? `${e.content_recipe!.prefix}${e.content_recipe!.fill.repeat(e.content_recipe!.count)}${e.content_recipe!.suffix}`

describe('the vectors', () => {
  it('are the spec file, unchanged', () => {
    expect(createHash('sha256').update(RAW).digest('hex')).toBe(AVATAR_VECTORS_SHA256)
  })
  it('carry the constants this module uses', () => {
    expect(V.constants).toEqual({ kind: AVATAR_KIND, content_max: AVATAR_CONTENT_MAX })
  })
})

describe('verifyAvatar', () => {
  for (const v of V.verdicts) {
    it(`${v.name}: ${v.verdict.reason}`, () => {
      const e = { ...v.event, content: content(v.event) }
      expect(verifyAvatar(e)).toEqual(v.verdict)
      // No verdict reads a tag.
      expect(verifyAvatar({ ...e, tags: [] } as typeof e)).toEqual(v.verdict)
    })
  }
  for (const v of V.content_limit) {
    it(`${v.bytes} bytes: ${v.refused ? 'refused' : 'drawn'}`, () => {
      const prefix = '{"vertices":[[0,0,0]],"pad":"'
      const body = v.bytes < prefix.length + 2 ? '{"vertices":[[0,0,0]]}' : `${prefix}${'a'.repeat(v.bytes - prefix.length - 2)}"}`
      expect(verifyAvatar({ kind: AVATAR_KIND, content: body }).reason === 'too-large').toBe(v.refused)
    })
  }
  it('counts the limit in UTF-8 bytes, not characters', () => {
    const prefix = '{"vertices":[[0,0,0]],"pad":"'
    const body = `${prefix}${'é'.repeat((AVATAR_CONTENT_MAX - prefix.length) / 2 + 1)}"}`
    expect(body.length).toBeLessThan(AVATAR_CONTENT_MAX)
    expect(avatarContentBytes(body)).toBeGreaterThan(AVATAR_CONTENT_MAX)
    expect(verifyAvatar({ kind: AVATAR_KIND, content: body }).reason).toBe('too-large')
  })
  it('stops a long run of ticks at the vertex count', () => {
    const t0 = Date.now()
    expect(verifyAvatar({ kind: AVATAR_KIND, content: '{"vertices":[[0,0,0]],"ticks":[-1e300]}' }).ok).toBe(true)
    expect(Date.now() - t0).toBeLessThan(1000)
  })
  it('the warning sits under the limit', () => {
    expect(AVATAR_CONTENT_WARN).toBe(64_000)
    expect(AVATAR_CONTENT_WARN).toBeLessThan(AVATAR_CONTENT_MAX)
  })
})

describe('the avatar study corpus', () => {
  for (const v of V.corpus) {
    it(`${v.name}: ${v.bytes} bytes, ${v.refused ? 'refused' : 'drawn'}`, () => expect(v.bytes > AVATAR_CONTENT_MAX).toBe(v.refused))
  }
})

describe('verifyAvatarWork (deprecated)', () => {
  it('never checks work: the same verdict as verifyAvatar, for display the tag and the zeros', () => {
    for (const v of V.verdicts) {
      const e = { ...v.event, content: content(v.event) }
      const r = verifyAvatarWork(e)
      expect({ ok: r.ok, reason: r.reason }).toEqual(v.verdict)
      expect(r.required).toBe(0)
      expect(r.zeros).toBe(leadingZeroBits(e.id))
    }
    const old = V.verdicts.find((x) => x.name.startsWith('published before 2026-11'))!
    expect(verifyAvatarWork({ ...old.event, content: content(old.event) })).toMatchObject({ ok: true, committed: 16, zeros: 16 })
  })
})

describe('the price is gone', () => {
  it('exports no work function and no miner', () => {
    for (const name of ['avatarWork', 'avatarBits', 'AVATAR_FLOOR_BITS', 'AVATAR_DETAIL_BITS', 'AvatarTailMiner', 'mineAvatarTail']) {
      expect((core as Record<string, unknown>)[name]).toBeUndefined()
    }
  })
})

describe('avatarReach and avatarReadable', () => {
  it('reach reads unit, vertices and packed ticks', () => {
    expect(avatarReach({ unit: 0, vertices: [[0, 0, 0], [-1, -1, -1]], ticks: [[60, 60, 60], [60, 60, 60]] })).toBeCloseTo(0.5, 9)
    expect(avatarReach({ unit: 2, vertices: [[4, 0, 0]] })).toBe(16)
    expect(avatarReach({ vertices: [[3, 0, 0], [0, 0, 0]], ticks: [-2] })).toBe(3)
  })
  it('readable refuses what is not a payload', () => {
    expect(avatarReadable({ vertices: [[0, 0, 0]] })).toBe(true)
    for (const p of [null, [], { vertices: 'no' }, { vertices: [null] }, { vertices: [['x', 0, 0]] }, { vertices: [[0, 0, 0]], faces: 5 }, { vertices: [[0, 0, 0]], ticks: [true] }]) {
      expect(avatarReadable(p)).toBe(false)
    }
  })
})

describe('leadingZeroBits', () => {
  it('counts as NIP-13 does', () => {
    expect(leadingZeroBits('0000ffff')).toBe(16)
    expect(leadingZeroBits('000f')).toBe(12)
    expect(leadingZeroBits('1abc')).toBe(3)
    expect(leadingZeroBits('')).toBe(0)
  })
})
