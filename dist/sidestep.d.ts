/**
 * sidestep.ts - Merkle sidestep proofs, version 3 (spec section 6).
 *
 * A sidestep crosses an LCA boundary with a Merkle hash tree instead of a
 * Cantor pairing tree. SHA-256 is fixed-size, so there is no storage
 * bottleneck: the cost of a sidestep is purely time (2^(h+1) - 1 hashes per
 * crossing axis). It exists to cross the walls that Cantor computation
 * cannot, at heights where intermediate pairing values would not fit in any
 * machine.
 *
 * Version 2 (spec 6.15) makes the sidestep a toll. Every leaf is seeded with
 * the mover's previous event id and the axis (6.4), so the tree is unique to
 * one chain position and nobody's published proof shortens anyone else's
 * crossing. With no canonical root left to compare against, the prover also
 * publishes openings (6.10): the destination leaf's path and eight more at
 * sampled positions, which a verifier recomputes from scratch. The seed
 * prefix is exactly one SHA-256 block, so its compression state is taken once
 * per axis and every leaf costs one compression, as before (6.5).
 *
 * Version 3 (spec 6.16) puts a price on the samples. Under version 2 they
 * came from the root, so a prover that built part of a tree could change one
 * fabricated node and draw fresh samples for about h hashes, until they all
 * missed the part it skipped. Now they come from G, a hash over a nonce and
 * the three roots that must fall below 2^256 / A, where A is the crossing's
 * leaves over eight: a fresh set of samples costs one eighth of the tree, the
 * smallest price at which skipping work never pays (6.11). The nonce is
 * published in the `mn` tag.
 *
 * Checked against the spec's sidestep-reference.py golden vectors.
 */
import { type Plane } from './coords.js';
import { type ProgressFn } from './movement.js';
/** Domain separation for the seeded leaves (spec 6.4). Bumped from V1 with the seed. */
export declare const SIDESTEP_DOMAIN: Uint8Array<ArrayBuffer>;
/** Nine zero bytes, so the seed prefix fills one 64-byte block exactly (spec 6.4, 6.5). */
export declare const SEED_PAD: Uint8Array<ArrayBuffer>;
/** Domain separation for the re-roll price hash G (spec 6.10). 28 bytes. */
export declare const SIDESTEP_GRIND_DOMAIN: Uint8Array<ArrayBuffer>;
/** Domain separation for the sampled opening indices, drawn from G (spec 6.10). V1 drew them from the root. */
export declare const SIDESTEP_SAMPLE_DOMAIN: Uint8Array<ArrayBuffer>;
/** Sampled openings per non-trivial axis, after the destination's (spec 6.10). */
export declare const SIDESTEP_SAMPLES = 8;
export type AxisName = 'x' | 'y' | 'z';
/** The axis byte in the seed: X 0, Y 1, Z 2 (spec 6.4). */
export declare const AXIS_BYTE: Record<AxisName, number>;
/**
 * The per-axis seed prefix (spec 6.4): domain, the 32 raw bytes of the
 * previous event id, the axis byte, and the pad, 64 bytes in all.
 */
export declare function seedPrefix(previousEventId: Uint8Array, axisByte: number): Uint8Array;
/** A leaf hasher for one seed prefix, resuming from the prefix's midstate (spec 6.5). */
export declare function leafHasher(prefix: Uint8Array): (value: bigint) => Uint8Array;
/** Merkle leaf hash: SHA256(seed_prefix || int_to_bytes_be_min(value)). */
export declare function merkleLeaf(prefix: Uint8Array, value: bigint): Uint8Array;
/** Merkle internal node: SHA256(left || right). */
export declare function merkleParent(left: Uint8Array, right: Uint8Array): Uint8Array;
/**
 * The sampled positions for an axis (spec 6.10): eight indices within the
 * aligned subtree drawn from G, the re-roll price hash, never from the root.
 * Collisions stand; the count is fixed.
 */
export declare function sampleIndices(G: Uint8Array, axisByte: number, height: number): number[];
/**
 * A, the price in attempts (spec 6.10): the leaves of every axis that moves,
 * over SIDESTEP_SAMPLES, rounded up, and at least 1. An attempt is three
 * SHA-256 compressions, one leaf's share of the tree, so the A attempts a
 * prover makes on average cost one eighth of the crossing.
 */
export declare function sidestepAttempts(heights: readonly number[]): bigint;
/**
 * G = SHA256(SIDESTEP_GRIND_DOMAIN || be64(nonce) || previous_event_id ||
 * M_x || M_y || M_z) (spec 6.10), with each M the axis root, or for a trivial
 * axis its single seeded leaf. Three blocks with the nonce in the first, so no
 * midstate survives from one attempt to the next.
 */
export declare function sidestepGrindHash(previousEventId: Uint8Array, roots: readonly Uint8Array[], nonce: bigint): Uint8Array;
/** The price (spec 6.10): G, read as a 256-bit big-endian integer, times A is below 2^256. */
export declare function meetsPrice(G: Uint8Array, attempts: bigint): boolean;
export interface SidestepNonce {
    nonce: bigint;
    /** G for that nonce, the source of the sample indices. */
    G: Uint8Array;
}
export interface NonceSearch {
    /** The first nonce to try. Default 0, which is what the golden vectors use. */
    start?: bigint;
    /** One past the last nonce to try. Default 2^64. */
    end?: bigint;
    /**
     * Called with 1 - e^(-tried / A), the chance a search this long has found a
     * nonce: about 63% at the expected A attempts, and never stuck at 100% while
     * the search goes on, as tried / A would be on an unlucky run.
     */
    onProgress?: ProgressFn;
}
/**
 * The first nonce from `start` upward and below `end` whose G meets the price
 * (spec 6.10), or null when that range holds none. Any such nonce verifies,
 * so a caller can split the search over workers by giving each a disjoint
 * range and keeping whichever finds one first.
 */
export declare function findSidestepNonce(previousEventId: Uint8Array, roots: readonly Uint8Array[], attempts: bigint, search?: NonceSearch): SidestepNonce | null;
/** The `mn` tag's value (spec 8.5): the nonce as exactly 16 lowercase hex characters, big-endian. */
export declare function encodeNonce(nonce: bigint): string;
/** The nonce in an `mn` tag's value, or null unless it is exactly 16 lowercase hex characters (spec 8.5). */
export declare function decodeNonce(hex: string): bigint | null;
/**
 * Whether an event is one of the version 2 sidesteps exempt under spec 6.16,
 * which carry no `mn` tag and keep their roots and openings unchecked.
 */
export declare function isGrandfatheredV2Sidestep(eventId: string | undefined): boolean;
export interface AxisMerkleResult {
    /** 32-byte Merkle root over the LCA subtree; for a trivial axis, its single seeded leaf. */
    root: Uint8Array;
    /** LCA height of the crossing; 0 when v1 === v2. */
    height: number;
    /**
     * The openings (spec 6.10), once G is known: the destination leaf's path
     * first, then the paths at sampleIndices(G, axisByte, height) in order, each
     * `height` siblings leaf level first. Empty for a trivial axis.
     */
    openingsFor(G: Uint8Array): Uint8Array[][];
}
/**
 * Merkle root for the LCA subtree between two axis values, in streaming
 * memory, and the means to open it at the destination and the eight sampled
 * leaves once G is known.
 *
 * The sampled positions depend on G, which depends on all three roots, so
 * they are not known during the pass that produces this one. Rather than a
 * second full pass, the top KEPT_LEVELS levels of nodes are kept from the
 * first, and each opening's lower siblings come from rebuilding only the
 * small subtree under that leaf: nine subtrees of 2^(h - 16) leaves, a
 * negligible fraction of the work. The kept levels live as long as the
 * result does, 4 MB at most per axis.
 */
export declare function computeAxisMerkleRoot(prefix: Uint8Array, axisByte: number, v1: bigint, v2: bigint, onProgress?: ProgressFn): AxisMerkleResult;
/**
 * Whether `siblings` carry the leaf at `leafValue` up to `expectedRoot` in a
 * tree of `height` over the subtree at `base`. The leaf is recomputed from
 * the seed, never taken from the proof.
 */
export declare function verifyMerkleInclusion(prefix: Uint8Array, leafValue: bigint, siblings: Uint8Array[], expectedRoot: Uint8Array, height: number, base: bigint): boolean;
/**
 * Level 1 for one axis (spec 6.11, 8.7.2 step 5): the destination's path,
 * then each leaf sampled from G recomputed from the seed and carried to the
 * root. G is the caller's to derive and price-check (sidestepGrindHash,
 * meetsPrice); this checks the paths only.
 */
export declare function verifyAxisOpenings(prefix: Uint8Array, axisByte: number, v1: bigint, v2: bigint, root: Uint8Array, openings: Uint8Array[][], G: Uint8Array): boolean;
/** The `mp` segment for one axis (spec 8.5): every opening's siblings, leaf first, as one hex string. */
export declare function encodeOpenings(openings: Uint8Array[][]): string;
/**
 * The openings from an `mp` segment for an axis of LCA height `height`
 * (spec 8.5). Null when malformed, and null for a v1 segment (one path
 * rather than nine), which spec 6.15 says must be rejected.
 */
export declare function decodeOpenings(segment: string, height: number): Uint8Array[][] | null;
export interface SidestepCostEstimate {
    lcaX: number;
    lcaY: number;
    lcaZ: number;
    maxHeight: number;
    /** Total SHA-256 evaluations across all three axes (leaves + internals): the trees alone. */
    totalHashes: number;
    /**
     * A, the expected attempts at the re-roll price (spec 6.10), not in
     * totalHashes. Each is three compressions against a tree hash's one and a
     * half on average, so they weigh 2 × attempts hashes: one eighth more work.
     */
    attempts: number;
}
/**
 * Closed-form cost of a sidestep. Unlike the hop estimate there is no
 * feasibility ceiling: a sidestep is always storable, only ever slow. The
 * openings add nine small rebuilds per axis, not counted here.
 */
export declare function estimateSidestepCost(x1: bigint, y1: bigint, z1: bigint, x2: bigint, y2: bigint, z2: bigint): SidestepCostEstimate;
/**
 * The landing coordinate for a sidestep from v1 across the highest boundary
 * toward `target`: exactly 1 gibson past that boundary (spec 6.3). Upward
 * that is the adjacent subtree's first leaf; downward its last.
 */
export declare function sidestepLanding(v1: bigint, target: bigint): bigint;
/**
 * Spec 6.3 on one axis: with h the LCA height of the pair, the source touches
 * the wall on its side (base + half - 1 going up, base + half going down) and
 * the destination is exactly one gibson past it. An axis that does not move
 * is a valid trivial crossing.
 */
export declare function validCrossing(v1: bigint, v2: bigint): boolean;
export interface SidestepProof {
    merkleX: Uint8Array;
    merkleY: Uint8Array;
    merkleZ: Uint8Array;
    /** pi(pi(mx, my), mz) over the roots as big-endian integers (spec 6.6). */
    regionM: bigint;
    terrainK: number;
    temporalSeed: bigint;
    cantorT: bigint;
    /** pi(region_m, cantor_t) (spec 6.8). */
    sidestepN: bigint;
    /** double-SHA256(sidestep_n), lowercase hex. */
    proofHash: string;
    lcaHeights: [number, number, number];
    /** The re-roll nonce (spec 6.10); the `mn` tag is encodeNonce(nonce). */
    nonce: bigint;
    /** G for that nonce, which the sample indices were drawn from. */
    G: Uint8Array;
    /** Per-axis openings (spec 6.10): destination path first, then the samples. */
    openings: {
        x: Uint8Array[][];
        y: Uint8Array[][];
        z: Uint8Array[][];
    };
}
/**
 * Compute a full sidestep proof: per-axis seeded Merkle roots, the re-roll
 * nonce, and the openings sampled from its G, with the roots combined into
 * region_m, plus the temporal Cantor binding identical to hop proofs (spec
 * 6.4 - 6.10). The nonce is the first meeting the price searching upward
 * from 0 on this thread, as in the golden vectors. The search is one eighth
 * of the tree's work, and the tree itself runs on this thread too.
 */
export declare function computeSidestepProof(x1: bigint, y1: bigint, z1: bigint, x2: bigint, y2: bigint, z2: bigint, plane: Plane, previousEventIdHex: string, onProgress?: ProgressFn): SidestepProof;
export interface SidestepClaim {
    from: {
        x: bigint;
        y: bigint;
        z: bigint;
    };
    to: {
        x: bigint;
        y: bigint;
        z: bigint;
    };
    plane: Plane;
    previousEventIdHex: string;
    /** The `mr` tag's three segments. */
    merkleRoots: [string, string, string];
    /** The `mp` tag's three segments. */
    openings: [string, string, string];
    /** The `mn` tag's value, or null when the event has no `mn` tag (a version 2 proof, spec 6.16). */
    nonce: string | null;
    /**
     * The event's id. Consulted only when `nonce` is null: a version 2 sidestep
     * stands only if its id is in GRANDFATHERED_V2_SIDESTEPS.
     */
    eventId?: string;
    /** The `hx`, `hy`, `hz` tags. */
    lcaHeights: [number, number, number];
    proofHash: string;
}
/**
 * Level 1 verification of a sidestep event (spec 8.7.2), everything a
 * verifier can check in seconds: geometry, heights, the re-roll price, each
 * axis's openings against the seeded leaves at the positions G draws, and
 * the proof hash rebuilt from the roots and the temporal root. Returns the
 * names of what failed; empty means valid.
 *
 * A v1 event fails on its openings (spec 6.15). An event without a nonce is
 * version 2 and fails on `mn` (6.16) unless its id is listed, in which case
 * its roots and openings are accepted unchecked and everything else is
 * checked as usual. A version 2 proof given some nonce still fails, because
 * its samples were drawn from the roots rather than from G.
 */
export declare function verifySidestepLevel1(claim: SidestepClaim): string[];
//# sourceMappingURL=sidestep.d.ts.map