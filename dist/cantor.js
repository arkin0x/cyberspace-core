/**
 * cantor.ts — Cantor pairing and hashing primitives.
 *
 * All integers here are bigint since Cyberspace coordinates exceed 2^53.
 * SHA-256 is a pure-JS synchronous implementation so that this module has zero
 * runtime dependencies and works identically in Node, browsers and workers.
 * (Web Crypto's digest() is async, which would poison every call site.)
 */
/**
 * Cantor pairing function: (a, b) -> N
 */
export function cantorPair(a, b) {
    const s = a + b;
    return (s * (s + 1n)) / 2n + b;
}
/** ASCII code point to nibble, for the hex digits and nothing else. */
const NIBBLE = (() => {
    const table = new Uint8Array(103);
    for (let c = 0; c < 10; c++)
        table[48 + c] = c;
    for (let c = 0; c < 6; c++) {
        table[97 + c] = 10 + c;
        table[65 + c] = 10 + c;
    }
    return table;
})();
/**
 * Convert a non-negative bigint to minimal big-endian bytes.
 *
 * The values this runs on are not small. A hop proof at LCA height 18 ends
 * with a 21 MB integer, so this loop runs 22 million times, and the obvious
 * `parseInt(hex.substring(i * 2, i * 2 + 2), 16)` allocates a two-character
 * string and runs a general-purpose number parser on every one of them: 750 ms
 * of the six seconds that hop takes. Reading the two code points and looking
 * their nibbles up in a table is the same answer 3.7 times faster, and it
 * allocates nothing.
 *
 * toString(16) stays because hex is a power of two, so V8 reinterprets the
 * digits rather than dividing, which makes it linear and cheap.
 */
export function intToBytesBE(n) {
    if (n < 0n)
        throw new Error('expected non-negative bigint');
    if (n === 0n)
        return new Uint8Array([0]);
    let hex = n.toString(16);
    if (hex.length % 2 !== 0)
        hex = '0' + hex;
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0, j = 0; j < bytes.length; j++, i += 2) {
        bytes[j] = (NIBBLE[hex.charCodeAt(i)] << 4) | NIBBLE[hex.charCodeAt(i + 1)];
    }
    return bytes;
}
export function bytesToHex(bytes) {
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex;
}
export function hexToBytes(hex) {
    if (hex.length % 2 !== 0)
        hex = '0' + hex;
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}
// ---------- Pure-JS SHA-256 (synchronous) ----------
const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const rotr = (n, x) => ((x >>> n) | (x << (32 - n))) >>> 0;
const ch = (x, y, z) => ((x & y) ^ (~x & z)) >>> 0;
const maj = (x, y, z) => ((x & y) ^ (x & z) ^ (y & z)) >>> 0;
const sigma0 = (x) => (rotr(2, x) ^ rotr(13, x) ^ rotr(22, x)) >>> 0;
const sigma1 = (x) => (rotr(6, x) ^ rotr(11, x) ^ rotr(25, x)) >>> 0;
const gamma0 = (x) => (rotr(7, x) ^ rotr(18, x) ^ (x >>> 3)) >>> 0;
const gamma1 = (x) => (rotr(17, x) ^ rotr(19, x) ^ (x >>> 10)) >>> 0;
const W = new Uint32Array(64);
const IV = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
/** One SHA-256 compression: folds the 64-byte block at `offset` into `state`. */
function compress(state, view, offset) {
    for (let i = 0; i < 16; i++)
        W[i] = view.getUint32(offset + i * 4);
    for (let i = 16; i < 64; i++)
        W[i] = (gamma1(W[i - 2]) + W[i - 7] + gamma0(W[i - 15]) + W[i - 16]) >>> 0;
    let a = state[0], b = state[1], c = state[2], d = state[3], e = state[4], f = state[5], g = state[6], h = state[7];
    for (let i = 0; i < 64; i++) {
        const t1 = (h + sigma1(e) + ch(e, f, g) + K[i] + W[i]) >>> 0;
        const t2 = (sigma0(a) + maj(a, b, c)) >>> 0;
        h = g;
        g = f;
        f = e;
        e = (d + t1) >>> 0;
        d = c;
        c = b;
        b = a;
        a = (t1 + t2) >>> 0;
    }
    state[0] = (state[0] + a) >>> 0;
    state[1] = (state[1] + b) >>> 0;
    state[2] = (state[2] + c) >>> 0;
    state[3] = (state[3] + d) >>> 0;
    state[4] = (state[4] + e) >>> 0;
    state[5] = (state[5] + f) >>> 0;
    state[6] = (state[6] + g) >>> 0;
    state[7] = (state[7] + h) >>> 0;
}
/** The padded message for `data` as the tail of a message `consumed` bytes long already. */
function padded(data, consumed) {
    const msgLen = data.length;
    const bitLen = BigInt(consumed + msgLen) * 8n;
    const padLen = 64 - ((msgLen + 9) % 64);
    const totalLen = msgLen + 1 + (padLen === 64 ? 0 : padLen) + 8;
    const out = new Uint8Array(totalLen);
    out.set(data);
    out[msgLen] = 0x80;
    const view = new DataView(out.buffer);
    view.setUint32(totalLen - 8, Number(bitLen >> 32n));
    view.setUint32(totalLen - 4, Number(bitLen & 0xffffffffn));
    return out;
}
function digest(state) {
    const result = new Uint8Array(32);
    const rv = new DataView(result.buffer);
    for (let i = 0; i < 8; i++)
        rv.setUint32(i * 4, state[i]);
    return result;
}
/**
 * Synchronous SHA-256. Returns 32 bytes.
 */
export function sha256(data) {
    const state = new Uint32Array(IV);
    const msg = padded(data, 0);
    const view = new DataView(msg.buffer);
    for (let offset = 0; offset < msg.length; offset += 64)
        compress(state, view, offset);
    return digest(state);
}
/**
 * The compression state after exactly one 64-byte block, to hash many
 * messages that share that block as their prefix (spec 6.5, the midstate
 * optimization): resume from it with sha256FromMidstate for each tail.
 */
export function sha256Midstate(block) {
    if (block.length !== 64)
        throw new Error('a midstate is taken over exactly one 64-byte block');
    const state = new Uint32Array(IV);
    compress(state, new DataView(block.buffer, block.byteOffset, 64), 0);
    return state;
}
/**
 * SHA-256 of (the 64-byte block behind `midstate` || tail), for a tail of at
 * most 55 bytes so that one more compression finishes the hash.
 */
export function sha256FromMidstate(midstate, tail) {
    if (tail.length > 55)
        throw new Error('a midstate tail must fit one block with its padding (55 bytes)');
    const state = new Uint32Array(midstate);
    const msg = padded(tail, 64);
    compress(state, new DataView(msg.buffer), 0);
    return digest(state);
}
export function sha256Hex(data) {
    return bytesToHex(sha256(data));
}
/**
 * SHA-256 of a bigint's minimal big-endian representation, as hex.
 */
export function sha256IntHex(n) {
    return sha256Hex(intToBytesBE(n));
}
//# sourceMappingURL=cantor.js.map