/**
 * coords.ts — Cyberspace coordinate system.
 *
 * 256-bit interleaved coordinates:
 *   bit 0 = plane (0=dataspace, 1=ideaspace)
 *   bits 1..255 = interleaved Z, Y, X (85 bits each)
 *
 * All axis values are bigint (85-bit unsigned).
 */
export declare const AXIS_BITS = 85;
export declare const AXIS_UNITS: bigint;
export declare const AXIS_MAX: bigint;
export declare const AXIS_CENTER: bigint;
export declare const PLANE_DATASPACE = 0;
export declare const PLANE_IDEASPACE = 1;
export type Plane = 0 | 1;
export interface Xyz {
    x: bigint;
    y: bigint;
    z: bigint;
    plane: Plane;
}
/**
 * Convert (x, y, z, plane) to a 256-bit interleaved coordinate.
 */
export declare function xyzToCoord(x: bigint, y: bigint, z: bigint, plane?: Plane): bigint;
/**
 * Convert a 256-bit interleaved coordinate back to (x, y, z, plane).
 */
export declare function coordToXyz(coord: bigint): Xyz;
/**
 * Convert a 256-bit coordinate to a zero-padded 64-char hex string.
 */
export declare function coordToHex(coord: bigint): string;
/**
 * Parse a hex string (with or without 0x prefix) to a 256-bit bigint coord.
 */
export declare function hexToCoord(hex: string): bigint;
/**
 * Normalize a hex string to 64 lowercase hex chars (no prefix).
 */
export declare function normalizeHex32(hex: string): string;
/**
 * Clamp an axis value into the valid u85 range.
 */
export declare function clampAxis(v: bigint): bigint;
//# sourceMappingURL=coords.d.ts.map