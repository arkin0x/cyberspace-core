/**
 * sector.ts — Sector utilities for spatial partitioning.
 *
 * Sectors are fixed-size cubic cells in the axis space.
 * Default: 2^30 axis-units per sector side.
 */
import { coordToXyz } from './coords.js';
export const SECTOR_BITS_DEFAULT = 30;
/**
 * Compute the sector ID for (x, y, z).
 */
export function xyzToSectorId(x, y, z, sectorBits = SECTOR_BITS_DEFAULT) {
    const shift = BigInt(sectorBits);
    return { sx: x >> shift, sy: y >> shift, sz: z >> shift };
}
/**
 * Get sector tag string.
 */
export function sectorTag(sid) {
    return `${sid.sx}-${sid.sy}-${sid.sz}`;
}
/**
 * Get sector ID and plane from a 256-bit coord.
 */
export function coordToSectorId(coord, sectorBits = SECTOR_BITS_DEFAULT) {
    const { x, y, z, plane } = coordToXyz(coord);
    return { sector: xyzToSectorId(x, y, z, sectorBits), plane };
}
/**
 * Get inclusive bounds for the sector containing (x, y, z).
 */
export function xyzToSectorBounds(x, y, z, sectorBits = SECTOR_BITS_DEFAULT) {
    const shift = BigInt(sectorBits);
    const size = 1n << shift;
    const bx = (x >> shift) << shift;
    const by = (y >> shift) << shift;
    const bz = (z >> shift) << shift;
    return {
        xRange: [bx, bx + size - 1n],
        yRange: [by, by + size - 1n],
        zRange: [bz, bz + size - 1n],
    };
}
//# sourceMappingURL=sector.js.map