/**
 * terrain.ts — Deterministic terrain-derived temporal height K.
 *
 * K ∈ [0, 16] via popcount of 16 pseudo-random bits (Binomial(16, 0.5)).
 * Spatial correlation via multi-scale cell alignment.
 */
import { sha256 } from './cantor.js';
import { xyzToCoord } from './coords.js';
export const TERRAIN_DOMAIN_V2 = new TextEncoder().encode('CYBERSPACE_TERRAIN_K_V2');
export const DEFAULT_CELL_BITS = [3, 7, 9, 11];
/**
 * Align a value down to a cell boundary.
 */
export function aligned(v, cellBits) {
    if (cellBits <= 0)
        return v;
    const shift = BigInt(cellBits);
    return (v >> shift) << shift;
}
/**
 * Convert a bigint to exactly 32 big-endian bytes.
 */
export function bigintTo32Bytes(n) {
    const bytes = new Uint8Array(32);
    let val = n;
    for (let i = 31; i >= 0; i--) {
        bytes[i] = Number(val & 0xffn);
        val >>= 8n;
    }
    return bytes;
}
/**
 * Count the number of set bits in a number.
 */
export function popcount(n) {
    let count = 0;
    while (n) {
        count += n & 1;
        n >>>= 1;
    }
    return count;
}
/**
 * Compute terrain K for a destination coordinate. Returns K in [0, 16].
 */
export function terrainK(x, y, z, plane, cellBits = DEFAULT_CELL_BITS) {
    if (cellBits.length !== 4) {
        throw new Error('cellBits must have exactly 4 entries');
    }
    if (plane !== 0 && plane !== 1) {
        throw new Error('plane must be 0 or 1');
    }
    let word = 0;
    for (const bits of cellBits) {
        if (bits < 0 || bits > 84) {
            throw new Error('cellBits entries must be within [0, 84]');
        }
        const bx = aligned(x, bits);
        const by = aligned(y, bits);
        const bz = aligned(z, bits);
        const coordBytes = bigintTo32Bytes(xyzToCoord(bx, by, bz, plane));
        // Domain separation: TERRAIN_DOMAIN_V2 + cell_bits byte + coord bytes
        const input = new Uint8Array(TERRAIN_DOMAIN_V2.length + 1 + 32);
        input.set(TERRAIN_DOMAIN_V2, 0);
        input[TERRAIN_DOMAIN_V2.length] = bits;
        input.set(coordBytes, TERRAIN_DOMAIN_V2.length + 1);
        const digest = sha256(input);
        const nibble = digest[0] & 0x0f;
        word = (word << 4) | nibble;
    }
    return popcount(word);
}
//# sourceMappingURL=terrain.js.map