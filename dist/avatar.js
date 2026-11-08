/**
 * avatar.ts - the work an avatar owes (kind 11333).
 *
 * An avatar is drawn on every screen near its owner whether they like it or
 * not, so its size and its detail are paid for in proof of work on the event
 * itself, NIP-13 style: the event id must carry `required` leading zero bits,
 * with the target committed in a `nonce` tag. Any viewer verifies with one
 * hash and a walk over the vertices, and draws the dodecahedron instead for
 * an avatar that has not paid.
 *
 *   required = ceil(FLOOR + SIZE_BITS * log2(reach) + DETAIL_BITS * log2(detail / 32))
 *
 * reach is the farthest vertex from the build origin in gibsons at true
 * scale (a model unit is 2^unit gibsons), never below one; detail is the
 * vertex count plus the face count, never below 32. The floor is planned on
 * a hundred-year horizon of growing hash power; reach is priced hardest
 * because a large avatar is the one that gets in everyone's way. Bytes are
 * charged as well without a term, since every nonce hashes the whole event.
 */
/** Bits every avatar owes, whatever its shape. */
export const AVATAR_FLOOR_BITS = 16;
/** Bits per doubling of reach. */
export const AVATAR_SIZE_BITS = 2;
/** Bits per doubling of vertices plus faces beyond DETAIL_FREE. */
export const AVATAR_DETAIL_BITS = 3;
/** Vertices plus faces that cost nothing. */
export const AVATAR_DETAIL_FREE = 32;
/**
 * Replaceable: one avatar per pubkey, the newest wins, no `d` tag.
 *
 * This was 33331, addressable with a `d` fixed at "avatar", which is
 * emulating replaceable semantics with the wrong tool: a constant `d` asks
 * every reader to trust a convention where the relay could enforce the rule.
 * Spec 8.10. The break was clean because nothing was published: a query for
 * 33331 across four relays returned nothing while the same query returned
 * bags and movement events. 33331 now belongs to a standalone SNO object
 * (DECK-0004), where a `d` the author chooses is a real key.
 */
export const AVATAR_KIND = 11333;
/** Ticks in a model unit, as the shard payload divides them. */
const TICKS_PER_UNIT = 120;
/** The ticks column unpacked to one triple per vertex. */
export function unpackTicks(packed, count) {
    const out = [];
    for (const item of packed ?? []) {
        if (typeof item === 'number') {
            for (let i = 0; i < -item; i++)
                out.push([0, 0, 0]);
        }
        else
            out.push([item[0] ?? 0, item[1] ?? 0, item[2] ?? 0]);
    }
    while (out.length < count)
        out.push([0, 0, 0]);
    return out.slice(0, count);
}
/** The farthest any vertex reaches from the build origin, in gibsons at true scale. */
export function avatarReach(payload) {
    const unit = Number.isFinite(payload.unit) ? payload.unit : 0;
    const ticks = unpackTicks(payload.ticks, payload.vertices.length);
    let reach = 0;
    payload.vertices.forEach((p, i) => {
        for (let a = 0; a < 3; a++)
            reach = Math.max(reach, Math.abs((p[a] ?? 0) + (ticks[i][a] ?? 0) / TICKS_PER_UNIT));
    });
    return reach * 2 ** unit;
}
/** The leading zero bits the avatar's event id must carry. */
export function avatarWork(payload) {
    const reach = Math.max(1, avatarReach(payload));
    const detail = Math.max(AVATAR_DETAIL_FREE, payload.vertices.length + (payload.faces?.length ?? 0));
    return Math.ceil(AVATAR_FLOOR_BITS + AVATAR_SIZE_BITS * Math.log2(reach) + AVATAR_DETAIL_BITS * Math.log2(detail / AVATAR_DETAIL_FREE));
}
/** Leading zero bits of a hex string, as NIP-13 counts them. */
export function leadingZeroBits(hex) {
    let n = 0;
    for (const ch of hex) {
        const nib = parseInt(ch, 16);
        if (Number.isNaN(nib))
            break;
        if (nib === 0) {
            n += 4;
            continue;
        }
        n += Math.clz32(nib) - 28;
        break;
    }
    return n;
}
/**
 * Whether an avatar event has paid for its shape (NIP-13): the nonce tag's
 * committed target covers what the shape owes, and the id carries at least
 * the committed zeros. Committing matters: a lucky id must not be claimed
 * against a lower bar than it was mined for.
 */
export function verifyAvatarWork(event) {
    const zeros = leadingZeroBits(event.id);
    if (event.kind !== AVATAR_KIND)
        return { ok: false, required: 0, committed: null, zeros, reason: 'not-an-avatar' };
    let payload;
    try {
        const raw = JSON.parse(event.content);
        if (!raw || !Array.isArray(raw.vertices))
            return { ok: false, required: 0, committed: null, zeros, reason: 'not-an-avatar' };
        payload = raw;
    }
    catch {
        return { ok: false, required: 0, committed: null, zeros, reason: 'not-an-avatar' };
    }
    const required = avatarWork(payload);
    const nonce = event.tags.find((t) => t[0] === 'nonce');
    const committed = nonce && /^\d+$/.test(nonce[2] ?? '') ? Number(nonce[2]) : null;
    if (committed === null)
        return { ok: false, required, committed, zeros, reason: 'no-nonce' };
    if (committed < required)
        return { ok: false, required, committed, zeros, reason: 'under-committed' };
    if (zeros < committed)
        return { ok: false, required, committed, zeros, reason: 'unpaid' };
    return { ok: true, required, committed, zeros, reason: 'ok' };
}
//# sourceMappingURL=avatar.js.map