/**
 * location_encryption.ts — Location-based encryption key derivation.
 *
 * Derives region keys from Cantor tree roots at various heights.
 * Encryption uses AES-256-GCM (not implemented here, key derivation only).
 */
export interface RegionKeys {
    locationDecryptionKey: Uint8Array;
    lookupIdHex: string;
}
export interface RegionKeyMaterial extends RegionKeys {
    height: number;
    regionN: bigint;
}
/**
 * Derive region_n for a given height from (x, y, z).
 */
export declare function deriveRegionN(x: bigint, y: bigint, z: bigint, height: number, maxComputeHeight?: number): bigint;
/**
 * Derive encryption key and lookup ID from a region_n.
 */
export declare function deriveRegionKeys(regionN: bigint): RegionKeys;
/**
 * Derive full key material for a given height.
 */
export declare function deriveRegionKeyMaterial(x: bigint, y: bigint, z: bigint, height: number, maxComputeHeight?: number): RegionKeyMaterial;
/**
 * Scan a range of heights and derive key material for each.
 */
export declare function deriveRegionKeyMaterialScan(x: bigint, y: bigint, z: bigint, minHeight: number, maxHeight: number, maxComputeHeight?: number): RegionKeyMaterial[];
//# sourceMappingURL=location_encryption.d.ts.map