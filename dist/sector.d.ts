/**
 * sector.ts — Sector utilities for spatial partitioning.
 *
 * Sectors are fixed-size cubic cells in the axis space.
 * Default: 2^30 axis-units per sector side.
 */
import { type Plane } from './coords.js';
export declare const SECTOR_BITS_DEFAULT = 30;
export interface SectorId {
    sx: bigint;
    sy: bigint;
    sz: bigint;
}
export interface SectorBounds {
    xRange: [bigint, bigint];
    yRange: [bigint, bigint];
    zRange: [bigint, bigint];
}
/**
 * Compute the sector ID for (x, y, z).
 */
export declare function xyzToSectorId(x: bigint, y: bigint, z: bigint, sectorBits?: number): SectorId;
/**
 * Get sector tag string.
 */
export declare function sectorTag(sid: SectorId): string;
/**
 * Get sector ID and plane from a 256-bit coord.
 */
export declare function coordToSectorId(coord: bigint, sectorBits?: number): {
    sector: SectorId;
    plane: Plane;
};
/**
 * Get inclusive bounds for the sector containing (x, y, z).
 */
export declare function xyzToSectorBounds(x: bigint, y: bigint, z: bigint, sectorBits?: number): SectorBounds;
//# sourceMappingURL=sector.d.ts.map