/**
 * avatarMine.test.ts - the midstate miner finds what the spec's reference
 * miner found (avatar-vectors.json, "mined"), its ids are real SHA-256
 * ids of the events it returns, and what it mines is paid.
 */
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { AVATAR_CONTENT_MAX, avatarContentBytes, avatarWork, verifyAvatarWork } from '../src/avatar.js'
import { AVATAR_NONCE_ROOM, AvatarTailMiner, avatarTailContent, avatarTailEvent, avatarTailSplit, mineAvatarTail } from '../src/avatarMine.js'
import type { AvatarVectors } from './avatar.test.js'

const V: AvatarVectors = JSON.parse(readFileSync(new URL('./fixtures/avatar-vectors.json', import.meta.url), 'utf8'))
const idOf = (e: { pubkey: string; created_at: number; kind: number; tags: string[][]; content: string }): string =>
  createHash('sha256').update(JSON.stringify([0, e.pubkey, e.created_at, e.kind, e.tags, e.content])).digest('hex')

describe('the miner against the reference (avatar-vectors.json, mined)', () => {
  for (const v of V.mined) {
    it(v.name, () => {
      expect(avatarTailSplit(v.template, v.target).lead).toBe(v.lead)
      const r = mineAvatarTail(v.template, v.target)!
      expect(r.tries).toBe(v.tries)
      expect(r.found.id).toBe(v.event.id)
      const { id: _id, ...rest } = v.event
      expect(r.event).toEqual(rest)
      expect(idOf(r.event)).toBe(v.event.id)
      expect(verifyAvatarWork({ ...r.event, id: r.found.id })).toEqual(v.verdict)
    })
  }
})

describe('AvatarTailMiner', () => {
  const ship = V.mined.find((m) => m.name.startsWith('Ship, nonce at the end, at its price'))!.template
  it('finds real ids from any start, with and without leading zeros on the nonce', () => {
    for (const name of ['Ship', 'x'.repeat(7), 'a much longer name that moves the nonce elsewhere']) {
      const t = { ...ship, tags: [['name', name]] }
      for (const start of [0, 999_999_990, 7 * 10 ** 12]) {
        const split = avatarTailSplit(t, 8)
        const found = new AvatarTailMiner(split, start).run(1 << 16, 8)!
        expect(found).not.toBeNull()
        const ev = avatarTailEvent(t, found.nonce, 8)
        expect(idOf(ev)).toBe(found.id)
        expect(found.id.startsWith('00')).toBe(true)
        expect(found.nonce.endsWith(String(Number(found.nonce.slice(split.lead.length))))).toBe(true)
      }
    }
  })
  it('makes every try one block: the bytes before the digits leave room for 16 digits, the end and the padding', () => {
    for (const len of Array.from({ length: 70 }, (_, i) => i)) {
      const s = avatarTailSplit({ ...ship, tags: [['name', 'n'.repeat(len)]] }, 25)
      expect(((s.pre.length + s.lead.length) % 64) + 16 + s.post.length + 9).toBeLessThanOrEqual(64)
    }
  })
  it('mines a large avatar: a real id, the nonce read back from the content, judged on its commitment', () => {
    const vertices = Array.from({ length: 3000 }, (_, i) => [i % 3 - 1, (i >> 2) % 3 - 1, (i >> 4) % 3 - 1])
    const faces = Array.from({ length: 3000 }, (_, i) => [i, (i + 1) % 3000, (i + 2) % 3000])
    const payload = { v: 2, name: 'big', unit: 0, vertices, faces }
    const t = { pubkey: ship.pubkey, created_at: ship.created_at, kind: 11333, tags: [['name', 'big']], content: JSON.stringify(payload) }
    const target = avatarWork(payload)
    expect(target).toBe(22) // 10 + 1.5 log2(6000 / 32) = 21.33, reach 1
    const r = mineAvatarTail(t, 14)! // the full 22 bits is four million tries; the id check is the same
    expect(idOf(r.event)).toBe(r.found.id)
    expect(verifyAvatarWork({ ...r.event, id: r.found.id }).reason).toBe('under-committed')
    expect(JSON.parse(r.event.content).nonce).toBe(r.found.nonce)
  })
  it('hashes right at every offset of the nonce in its block, with and without leading zeros', () => {
    for (let len = 0; len < 130; len++) {
      const t = { ...ship, tags: [['name', 'q'.repeat(len)]] }
      const split = avatarTailSplit(t, 4)
      const found = new AvatarTailMiner(split, len * 1000).run(1 << 12, 4)!
      expect(idOf(avatarTailEvent(t, found.nonce, 4))).toBe(found.id)
    }
  })
  it('refuses a split that would need more than one block per try', () => {
    const split = avatarTailSplit(ship, 4)
    expect(() => new AvatarTailMiner({ ...split, post: new Uint8Array(60) })).toThrow()
  })
  it('refuses to mine content that would be over the limit once mined', () => {
    const prefix = '{"vertices":[[0,0,0]],"faces":[],"pad":"'
    const body = `${prefix}${'a'.repeat(AVATAR_CONTENT_MAX - prefix.length - 2)}"}`
    expect(() => avatarTailSplit({ ...ship, content: body }, 10)).toThrow(/limit/)
  })
  it('takes only safe starts, which keep every nonce within 16 digits for 10^15 tries', () => {
    expect(() => new AvatarTailMiner(avatarTailSplit(ship, 4), 2 ** 53)).toThrow()
    expect(() => new AvatarTailMiner(avatarTailSplit(ship, 4), Number.MAX_SAFE_INTEGER)).not.toThrow()
  })
  it('keeps a mined content byte for byte when mining it again', () => {
    const odd = '{"vertices":[[0,0,0]],"scale":1.0,"tiny":1e-7,"b":1,"1":2,"nonce":"0042"}'
    expect(avatarTailContent(odd, '7')).toBe('{"vertices":[[0,0,0]],"scale":1.0,"tiny":1e-7,"b":1,"1":2,"nonce":"7"}')
  })
  it('refuses a target beyond what it reads and a bad start', () => {
    expect(() => new AvatarTailMiner(avatarTailSplit(ship, 10)).run(1, 65)).toThrow()
    expect(() => new AvatarTailMiner(avatarTailSplit(ship, 10), -1)).toThrow()
  })
})

describe('avatarTailContent', () => {
  it('puts nonce last, drops an earlier nonce, and keeps the rest', () => {
    expect(avatarTailContent('{"vertices":[]}', '42')).toBe('{"vertices":[],"nonce":"42"}')
    expect(avatarTailContent('{}', '7')).toBe('{"nonce":"7"}')
    expect(avatarTailContent('{"nonce":"1","vertices":[]}', '9')).toBe('{"vertices":[],"nonce":"9"}')
    expect(JSON.parse(avatarTailContent('{"a":1}  \n', '3'))).toEqual({ a: 1, nonce: '3' })
    expect(() => avatarTailContent('[1,2]', '1')).toThrow()
    expect(() => avatarTailContent('not json', '1')).toThrow()
  })
  it('leaves room: content within the limit less AVATAR_NONCE_ROOM fits once mined', () => {
    const prefix = '{"vertices":[[0,0,0]],"faces":[],"pad":"'
    const body = `${prefix}${'a'.repeat(AVATAR_CONTENT_MAX - AVATAR_NONCE_ROOM - prefix.length - 2)}"}`
    expect(avatarContentBytes(body)).toBe(AVATAR_CONTENT_MAX - AVATAR_NONCE_ROOM)
    const worst = avatarTailContent(body, '0'.repeat(29) + '9'.repeat(16)) // the most zeros a lead can be, and 16 digits
    expect(avatarContentBytes(worst)).toBe(AVATAR_CONTENT_MAX)
  })
})
