/**
 * terrain.ts — Deterministic terrain-derived temporal height K.
 *
 * K ∈ [0, 16] via popcount of 16 pseudo-random bits (Binomial(16, 0.5)).
 * Spatial correlation via multi-scale cell alignment.
 */
import { type Plane } from './coords.js';
export declare const TERRAIN_DOMAIN_V2: Uint8Array<ArrayBuffer>;
export declare const DEFAULT_CELL_BITS: number[];
/**
 * Align a value down to a cell boundary.
 */
export declare function aligned(v: bigint, cellBits: number): bigint;
/**
 * Convert a bigint to exactly 32 big-endian bytes.
 */
export declare function bigintTo32Bytes(n: bigint): Uint8Array;
/**
 * Count the number of set bits in a number.
 */
export declare function popcount(n: number): number;
/**
 * Compute terrain K for a destination coordinate. Returns K in [0, 16].
 */
export declare function terrainK(x: bigint, y: bigint, z: bigint, plane: Plane, cellBits?: number[]): number;
//# sourceMappingURL=terrain.d.ts.map