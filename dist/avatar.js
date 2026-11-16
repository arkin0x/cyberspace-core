/**
 * avatar.ts - what a reader checks on an avatar (kind 11333, spec 8.10).
 *
 * An avatar carries no proof of work (owner ruling 2026-11-16). A reader
 * draws it when its content is within AVATAR_CONTENT_MAX bytes of UTF-8 and
 * holds a payload the reader can read, and draws its default avatar for that
 * identity otherwise. A `nonce` tag, which avatars published before 2026-11
 * carry, is ignored: no verdict reads a tag. Relays limit how often one key
 * replaces its avatar; viewers mute.
 *
 * Until 2026-11 an avatar paid NIP-13 work priced by its reach and detail
 * (16 bits, 2 per doubling of reach, 3 per doubling of vertices plus faces
 * beyond 32). A miner that varies the end of the content hashes one SHA-256
 * block per try at any size, which made that price meaningless, so it was
 * dropped. avatarWork and the price constants are gone; verifyAvatarWork
 * stays one release as a deprecated alias of verifyAvatar that never
 * checks work.
 */
/**
 * The most bytes an avatar's content may hold, counted as UTF-8 (128 KiB).
 * A reader draws the default avatar for a larger one.
 */
export const AVATAR_CONTENT_MAX = 131_072;
/**
 * Above this many bytes of content a publishing client warns that some
 * remote signers (NIP-46) may refuse the event: older NIP-44 libraries
 * encrypt at most 65,535 bytes, and the request carries the whole event
 * with its content escaped again, so such a signer fails near 65,200
 * bytes of content. Spec 8.10, non-normative.
 */
export const AVATAR_CONTENT_WARN = 64_000;
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
/**
 * The ticks column unpacked to one triple per vertex. Stops at `count`
 * triples, so a run of a billion zero triples costs nothing.
 */
export function unpackTicks(packed, count) {
    const out = [];
    for (const item of packed ?? []) {
        if (out.length >= count)
            break;
        if (typeof item === 'number') {
            const n = Math.min(-item, count - out.length);
            for (let i = 0; i < n; i++)
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
    return reach === 0 ? 0 : reach * 2 ** unit;
}
const isNum = (x) => typeof x === 'number' && Number.isFinite(x);
const isTriple = (v) => Array.isArray(v) && v.slice(0, 3).every(isNum);
/**
 * Whether the work can be read from a payload at all (spec 8.10: content a
 * client cannot read is not an avatar). `vertices` is a list of lists whose
 * first three entries, where present, are numbers; `ticks`, where present,
 * holds runs (whole numbers, zero or below) and such lists; `faces`, where
 * present, is a list. Without this a coordinate that is not a number would
 * price the avatar at NaN, which passes every comparison.
 */
export function avatarReadable(payload) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload))
        return false;
    const p = payload;
    if (!Array.isArray(p.vertices) || !p.vertices.every(isTriple))
        return false;
    if (p.ticks != null && !(Array.isArray(p.ticks) && p.ticks.every((t) => (isNum(t) && t <= 0 && Number.isInteger(t)) || isTriple(t))))
        return false;
    return p.faces == null || Array.isArray(p.faces);
}
const utf8 = new TextEncoder();
/** The content's length as the limit counts it: UTF-8 bytes (a lone surrogate counts three). */
export function avatarContentBytes(content) {
    return utf8.encode(content).length;
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
 * Whether a reader draws this avatar event (spec 8.10): the kind is 11333,
 * the content is within AVATAR_CONTENT_MAX (checked before parsing) and it
 * holds a payload the reader can read (avatarReadable). Tags are not read.
 * Empty content is the default avatar, the caller's to handle first; here it
 * is not-an-avatar, as any content that is not a payload is.
 */
export function verifyAvatar(event) {
    if (event.kind !== AVATAR_KIND || typeof event.content !== 'string')
        return { ok: false, reason: 'not-an-avatar' };
    // UTF-8 never takes fewer bytes than UTF-16 code units, and never more than three per unit.
    const len = event.content.length;
    if (len > AVATAR_CONTENT_MAX || (len * 3 > AVATAR_CONTENT_MAX && avatarContentBytes(event.content) > AVATAR_CONTENT_MAX)) {
        return { ok: false, reason: 'too-large' };
    }
    let raw;
    try {
        raw = JSON.parse(event.content);
    }
    catch {
        return { ok: false, reason: 'not-an-avatar' };
    }
    return avatarReadable(raw) ? { ok: true, reason: 'ok' } : { ok: false, reason: 'not-an-avatar' };
}
/**
 * @deprecated An avatar carries no proof of work (spec 8.10, 2026-11-16).
 * Use verifyAvatar. This alias reaches verifyAvatar's verdict and never
 * checks work; it reports the nonce tag and the id's zeros for display only.
 */
export function verifyAvatarWork(event) {
    // Display only, so it never throws on what the verdict does not read.
    const tags = Array.isArray(event.tags) ? event.tags : [];
    const nonce = tags.find((t) => Array.isArray(t) && t[0] === 'nonce');
    const target = nonce?.[2];
    const committed = typeof target === 'string' && /^[0-9]{1,15}$/.test(target) ? Number(target) : null;
    return { ...verifyAvatar(event), required: 0, committed, zeros: typeof event.id === 'string' ? leadingZeroBits(event.id) : 0 };
}
//# sourceMappingURL=avatar.js.map