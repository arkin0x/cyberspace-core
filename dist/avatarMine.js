/**
 * avatarMine.ts - mining an avatar's work with the nonce at the end of the content.
 *
 * Spec 8.10 counts the work on the event id and reads only the committed
 * target, so a miner may vary the nonce anywhere in the event. The id is the
 * SHA-256 of the serialized event, SHA-256 reads its input front to back in
 * 64-byte blocks, and the content is the last field serialized. So this
 * miner writes the nonce as a trailing `nonce` field of the payload, hashes
 * everything before it once (the midstate), and per try hashes only the last
 * block: one compression, whatever the avatar's size. A 98 KB avatar mined
 * with the nonce in the tags hashes about 1,500 blocks per try instead.
 *
 * When the last partial block before the nonce leaves too little room for
 * up to 16 digits, the end of the serialization and the padding, the nonce
 * is led with zeros up to the next block boundary (still a string of
 * decimal digits), so every try is exactly one compression. The nonce tag
 * carries "0" as its first value and the committed target as its second.
 *
 * This is the same miner as the spec's avatar-reference.py (mine_tail): for
 * the same template, target and first nonce it finds the same nonce, and the
 * spec's avatar-vectors.json pins that. Pure JavaScript, no allocation in
 * the hot loop, int32 words throughout, so it runs the same in node, in a
 * browser and in a phone's Web Worker (about two million tries a second on
 * one desktop core).
 */
/** Digits a try's nonce may have; the last block keeps room for them. */
export const AVATAR_NONCE_DIGITS_MAX = 16;
/**
 * The bytes of the serialization after the nonce's digits: the content's
 * closing `"}`, escaped inside the event's JSON as `\"}`, then `"]`.
 */
const POST_BYTES = 5;
/**
 * The most bytes mining adds to a content that holds no nonce yet:
 * `,"nonce":"` and `"` (11), the zeros that lead the digits (fewer than
 * 64 - (64 - AVATAR_NONCE_DIGITS_MAX - POST_BYTES - 9), so at most 29) and
 * AVATAR_NONCE_DIGITS_MAX digits: 56. A content within AVATAR_CONTENT_MAX
 * less this always fits the limit once mined; avatarTailSplit refuses one
 * that would not.
 */
export const AVATAR_NONCE_ROOM = 11 + (AVATAR_NONCE_DIGITS_MAX + POST_BYTES + 9 - 1) + AVATAR_NONCE_DIGITS_MAX;
import { AVATAR_CONTENT_MAX, avatarContentBytes } from './avatar.js';
const MARK = '\u0000NONCE\u0000';
const enc = new TextEncoder();
const MINED_TAIL = /,"nonce":"[0-9]+"(\}\s*)$/;
const MINED_ONLY = /^(\{\s*)"nonce":"[0-9]+"(\}\s*)$/;
/**
 * The content with `nonce` as the last field of its payload. A nonce this
 * miner wrote before (the content ends with it) is cut off as text, so the
 * rest stays byte for byte; any other `nonce` field is dropped by writing
 * the payload again. Throws when the content is not a JSON object.
 */
export function avatarTailContent(content, nonce) {
    const cut = content.replace(MINED_TAIL, '$1').replace(MINED_ONLY, '$1$2');
    const payload = JSON.parse(cut);
    if (!payload || typeof payload !== 'object' || Array.isArray(payload))
        throw new Error('the content is not a JSON object');
    let text = cut;
    if (Object.prototype.hasOwnProperty.call(payload, 'nonce')) {
        delete payload.nonce;
        text = JSON.stringify(payload);
    }
    const stripped = text.trimEnd();
    const body = stripped.slice(0, -1);
    const sep = body.trimEnd().endsWith('{') ? '' : ',';
    return `${body}${sep}"nonce":"${nonce}"}`;
}
/** The template's tags with its nonce tag set to ["nonce", first, target], replacing any earlier one. */
function withNonceTag(tags, first, target) {
    return [...tags.filter((t) => t[0] !== 'nonce'), ['nonce', first, String(target)]];
}
/**
 * The event to sign once `nonce` is found: the content with the nonce at
 * its end and the nonce tag committing to `target`. Its id is the find's.
 */
export function avatarTailEvent(template, nonce, target) {
    return { ...template, tags: withNonceTag(template.tags, '0', target), content: avatarTailContent(template.content, nonce) };
}
/** NIP-01 serialization: the id is the SHA-256 of this JSON array. */
function serialize(t) {
    return JSON.stringify([0, t.pubkey, t.created_at, t.kind, t.tags, t.content]);
}
export function avatarTailSplit(template, target) {
    const ser = serialize({ ...template, tags: withNonceTag(template.tags, '0', target), content: avatarTailContent(template.content, MARK) });
    const mark = JSON.stringify(MARK).slice(1, -1);
    const at = ser.indexOf(mark);
    if (at < 0 || ser.indexOf(mark, at + 1) >= 0)
        throw new Error('the nonce marker must appear exactly once');
    const pre = enc.encode(ser.slice(0, at));
    const post = enc.encode(ser.slice(at + mark.length));
    const rem = pre.length % 64;
    const lead = rem + AVATAR_NONCE_DIGITS_MAX + post.length + 9 > 64 ? '0'.repeat(64 - rem) : '';
    const worst = avatarTailContent(template.content, lead + '9'.repeat(AVATAR_NONCE_DIGITS_MAX));
    if (avatarContentBytes(worst) > AVATAR_CONTENT_MAX)
        throw new Error(`the content is over the ${AVATAR_CONTENT_MAX}-byte limit once mined`);
    return { pre, post, lead };
}
// ------------------------------------------------------------------ SHA-256
const K = new Int32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
/** Fold the 64-byte block at bytes[off] into state s, with W as scratch. */
function compress(s, W, bytes, off) {
    for (let i = 0; i < 16; i++, off += 4) {
        W[i] = (bytes[off] << 24) | (bytes[off + 1] << 16) | (bytes[off + 2] << 8) | bytes[off + 3];
    }
    for (let i = 16; i < 64; i++) {
        const x = W[i - 15], y = W[i - 2];
        const g0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
        const g1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
        W[i] = (g1 + W[i - 7] + g0 + W[i - 16]) | 0;
    }
    let a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
    for (let i = 0; i < 64; i++) {
        const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        const t1 = (h + S1 + ((e & f) ^ (~e & g)) + K[i] + W[i]) | 0;
        const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        const t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;
        h = g;
        g = f;
        f = e;
        e = (d + t1) | 0;
        d = c;
        c = b;
        b = a;
        a = (t1 + t2) | 0;
    }
    s[0] = (s[0] + a) | 0;
    s[1] = (s[1] + b) | 0;
    s[2] = (s[2] + c) | 0;
    s[3] = (s[3] + d) | 0;
    s[4] = (s[4] + e) | 0;
    s[5] = (s[5] + f) | 0;
    s[6] = (s[6] + g) | 0;
    s[7] = (s[7] + h) | 0;
}
/** SHA-256 padding for a message of totalLen bytes whose last `rem` bytes are in buf; returns 64 or 128. */
function pad(buf, rem, totalLen) {
    const L = rem + 9 <= 64 ? 64 : 128;
    buf.fill(0, rem, L);
    buf[rem] = 0x80;
    const bits = totalLen * 8;
    const hi = Math.floor(bits / 4294967296);
    buf[L - 8] = hi >>> 24;
    buf[L - 7] = (hi >>> 16) & 255;
    buf[L - 6] = (hi >>> 8) & 255;
    buf[L - 5] = hi & 255;
    buf[L - 4] = bits >>> 24;
    buf[L - 3] = (bits >>> 16) & 255;
    buf[L - 2] = (bits >>> 8) & 255;
    buf[L - 1] = bits & 255;
    return L;
}
/** Leading zero bits of a state's first two words (enough for any target up to 64). */
function zerosOf(s) {
    const z = Math.clz32(s[0]);
    return z < 32 ? z : 32 + Math.clz32(s[1]);
}
function stateHex(s) {
    let out = '';
    for (let i = 0; i < 8; i++)
        out += (s[i] >>> 0).toString(16).padStart(8, '0');
    return out;
}
/** The most leading zero bits this miner can aim for (it reads two words of the hash). */
export const AVATAR_MINE_MAX_TARGET = 64;
/**
 * The midstate miner over one split. Nonces are tried in order from
 * `start`: start, start + 1, ... as decimal digits, each led by the split's
 * `lead`. Give each worker its own `start` far from the others' (worker i
 * of n at i * 10^12, say); 16 digits are room for 10^16 nonces.
 */
export class AvatarTailMiner {
    /** Nonces tried so far. */
    tries = 0;
    mid;
    W = new Int32Array(64);
    s = new Int32Array(8);
    buf;
    remLen;
    hashed;
    post;
    lead;
    digits;
    constructor(split, start = 0) {
        if (!Number.isSafeInteger(start) || start < 0)
            throw new Error('start must be a safe non-negative integer');
        const head = new Uint8Array(split.pre.length + split.lead.length);
        head.set(split.pre);
        head.fill(48, split.pre.length);
        this.hashed = head.length - (head.length % 64);
        this.mid = Int32Array.from(IV);
        for (let off = 0; off < this.hashed; off += 64)
            compress(this.mid, this.W, head, off);
        const rem = head.subarray(this.hashed);
        this.remLen = rem.length;
        // Every try must be one block: the bytes before the digits, the digits, the end and the padding.
        if (rem.length + AVATAR_NONCE_DIGITS_MAX + split.post.length + 9 > 64)
            throw new Error('this split does not leave one block per try');
        this.buf = new Uint8Array(rem.length + AVATAR_NONCE_DIGITS_MAX + 8 + split.post.length + 128);
        this.buf.set(rem);
        this.post = split.post;
        this.lead = split.lead;
        this.digits = Array.from(String(start), (c) => c.charCodeAt(0));
    }
    /** Try up to `count` nonces; the first whose id carries `target` leading zero bits, or null. */
    run(count, target) {
        if (!(target >= 0 && target <= AVATAR_MINE_MAX_TARGET))
            throw new Error(`target must be 0 to ${AVATAR_MINE_MAX_TARGET} bits`);
        const { buf, post, s, W, mid, digits } = this;
        for (let k = 0; k < count; k++) {
            if (digits.length > AVATAR_NONCE_DIGITS_MAX)
                throw new Error('nonce space exhausted');
            let p = this.remLen;
            for (let i = 0; i < digits.length; i++)
                buf[p++] = digits[i];
            for (let i = 0; i < post.length; i++)
                buf[p++] = post[i];
            const L = pad(buf, p, this.hashed + p);
            s.set(mid);
            for (let o = 0; o < L; o += 64)
                compress(s, W, buf, o);
            this.tries++;
            const hit = zerosOf(s) >= target;
            const nonce = hit ? this.lead + String.fromCharCode(...digits) : '';
            // next nonce, in place
            let i = digits.length - 1;
            while (i >= 0 && digits[i] === 57) {
                digits[i] = 48;
                i--;
            }
            if (i < 0)
                digits.unshift(49);
            else
                digits[i]++;
            if (hit)
                return { nonce, id: stateHex(s) };
        }
        return null;
    }
}
/**
 * Mine `template` to `target` bits on this thread, from nonce `start`, at
 * most `limit` tries; the event to sign (avatarTailEvent) and the find, or
 * null when the limit runs out. For tests and small targets: a client mines
 * in workers, each with its own AvatarTailMiner and start.
 */
export function mineAvatarTail(template, target, start = 0, limit = 2 ** 32) {
    const miner = new AvatarTailMiner(avatarTailSplit(template, target), start);
    const chunk = 1 << 16;
    while (miner.tries < limit) {
        const found = miner.run(Math.min(chunk, limit - miner.tries), target);
        if (found)
            return { event: avatarTailEvent(template, found.nonce, target), found, tries: miner.tries };
    }
    return null;
}
//# sourceMappingURL=avatarMine.js.map