/**
 * coords.ts — Cyberspace coordinate system.
 *
 * 256-bit interleaved coordinates:
 *   bit 0 = plane (0=dataspace, 1=ideaspace)
 *   bits 1..255 = interleaved Z, Y, X (85 bits each)
 *
 * All axis values are bigint (85-bit unsigned).
 */
export const AXIS_BITS = 85;
export const AXIS_UNITS = 1n << 85n; // 2^85
export const AXIS_MAX = AXIS_UNITS - 1n; // 2^85 - 1
export const AXIS_CENTER = 1n << 84n; // 2^84
export const PLANE_DATASPACE = 0;
export const PLANE_IDEASPACE = 1;
/**
 * Convert (x, y, z, plane) to a 256-bit interleaved coordinate.
 */
export function xyzToCoord(x, y, z, plane = 0) {
    let coord = BigInt(plane) & 1n;
    for (let i = 0; i < AXIS_BITS; i++) {
        const bi = BigInt(i);
        coord |= ((z >> bi) & 1n) << (1n + bi * 3n);
        coord |= ((y >> bi) & 1n) << (2n + bi * 3n);
        coord |= ((x >> bi) & 1n) << (3n + bi * 3n);
    }
    return coord;
}
/**
 * Convert a 256-bit interleaved coordinate back to (x, y, z, plane).
 */
export function coordToXyz(coord) {
    const plane = Number(coord & 1n);
    let x = 0n, y = 0n, z = 0n;
    for (let i = 0; i < AXIS_BITS; i++) {
        const bi = BigInt(i);
        z |= ((coord >> (1n + bi * 3n)) & 1n) << bi;
        y |= ((coord >> (2n + bi * 3n)) & 1n) << bi;
        x |= ((coord >> (3n + bi * 3n)) & 1n) << bi;
    }
    return { x, y, z, plane };
}
/**
 * Convert a 256-bit coordinate to a zero-padded 64-char hex string.
 */
export function coordToHex(coord) {
    return coord.toString(16).padStart(64, '0');
}
/**
 * Parse a hex string (with or without 0x prefix) to a 256-bit bigint coord.
 */
export function hexToCoord(hex) {
    const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
    return BigInt('0x' + clean.padStart(64, '0'));
}
/**
 * Normalize a hex string to 64 lowercase hex chars (no prefix).
 */
export function normalizeHex32(hex) {
    const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
    return clean.toLowerCase().padStart(64, '0');
}
/**
 * Clamp an axis value into the valid u85 range.
 */
export function clampAxis(v) {
    if (v < 0n)
        return 0n;
    if (v > AXIS_MAX)
        return AXIS_MAX;
    return v;
}
//# sourceMappingURL=coords.js.map