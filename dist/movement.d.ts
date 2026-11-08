/**
 * movement.ts — Movement proofs and Cantor tree computation.
 *
 * Core operations:
 * - LCA height between two axis values
 * - Subtree Cantor root computation (O(2^h))
 * - Spatial movement proof (3D: region_n)
 * - Full 4D hop proof (spatial + temporal, per spec §5.5–§5.7)
 */
import { type Plane } from './coords.js';
export declare const DEFAULT_MAX_COMPUTE_HEIGHT = 20;
export declare const TEMPORAL_MAX_COMPUTE_HEIGHT = 17;
/**
 * Progress reporter for long-running Cantor tree computation. Called
 * periodically with a 0..1 fraction so a worker can stream live stats without
 * blocking the UI thread. Kept optional so consensus paths stay allocation-free.
 */
export type ProgressFn = (fraction: number) => void;
/**
 * Find the LCA height between two axis values.
 * Height = bit_length(v1 XOR v2).
 */
export declare function findLcaHeight(v1: bigint, v2: bigint): number;
/**
 * Number of leaves in the aligned subtree for a given LCA height.
 * This is the dominant cost term: computing the tree is O(2^h).
 */
export declare function subtreeLeafCount(height: number): number;
/**
 * Total Cantor pairings required to reduce a height-h subtree to its root.
 * A full binary tree with 2^h leaves needs 2^h - 1 internal pairings.
 */
export declare function subtreeCantorOps(height: number): number;
/**
 * The aligned base of the subtree containing v at the given height.
 */
export declare function alignedBase(v: bigint, height: number): bigint;
/**
 * Compute the Cantor number for a subtree rooted at (base, height).
 * O(2^h) computation.
 */
export declare function computeSubtreeCantor(base: bigint, height: number, maxComputeHeight?: number, onProgress?: ProgressFn): bigint;
/**
 * Compute the axis Cantor root for two axis values.
 */
export declare function computeAxisCantor(v1: bigint, v2: bigint, maxComputeHeight?: number, onProgress?: ProgressFn): bigint;
export interface MovementProof {
    cantorX: bigint;
    cantorY: bigint;
    cantorZ: bigint;
    combined: bigint;
    proofHash: string;
}
/**
 * Compute the spatial-only movement proof (region_n).
 */
export declare function computeMovementProof(x1: bigint, y1: bigint, z1: bigint, x2: bigint, y2: bigint, z2: bigint, maxComputeHeight?: number): MovementProof;
export interface HopProof {
    cantorX: bigint;
    cantorY: bigint;
    cantorZ: bigint;
    regionN: bigint;
    terrainK: number;
    temporalSeed: bigint;
    cantorT: bigint;
    hopN: bigint;
    proofHash: string;
}
/**
 * Compute the full 4D hop proof (spatial + temporal) per spec §5.5–§5.7.
 *
 * @param plane destination plane bit (0 or 1)
 * @param previousEventIdHex 64-char lowercase hex
 */
export declare function computeHopProof(x1: bigint, y1: bigint, z1: bigint, x2: bigint, y2: bigint, z2: bigint, plane: Plane, previousEventIdHex: string, maxComputeHeight?: number, onProgress?: ProgressFn): HopProof;
export interface HopCostEstimate {
    lcaX: number;
    lcaY: number;
    lcaZ: number;
    terrainK: number;
    /** Largest single-axis LCA height; drives peak memory. */
    maxHeight: number;
    /** Total Cantor pairings across all four trees. */
    totalOps: number;
    /** True if any tree exceeds the configured compute ceiling. */
    exceedsLimit: boolean;
}
/**
 * Estimate the cost of a hop without computing it. Used by the UI to warn
 * before a move that would take minutes, and to drive the live cost readout.
 */
export declare function estimateHopCost(x1: bigint, y1: bigint, z1: bigint, x2: bigint, y2: bigint, z2: bigint, plane: Plane, maxComputeHeight?: number): HopCostEstimate;
//# sourceMappingURL=movement.d.ts.map