/**
 * movement.ts — Movement proofs and Cantor tree computation.
 *
 * Core operations:
 * - LCA height between two axis values
 * - Subtree Cantor root computation (O(2^h))
 * - Spatial movement proof (3D: region_n)
 * - Full 4D hop proof (spatial + temporal, per spec §5.5–§5.7)
 */
import { cantorPair, intToBytesBE, sha256, sha256IntHex, hexToBytes, bytesToHex } from './cantor.js';
import { AXIS_BITS } from './coords.js';
import { terrainK } from './terrain.js';
export const DEFAULT_MAX_COMPUTE_HEIGHT = 20;
export const TEMPORAL_MAX_COMPUTE_HEIGHT = 17;
/** Report progress roughly this many times over a full computation. */
const PROGRESS_TICKS = 64;
/**
 * Find the LCA height between two axis values.
 * Height = bit_length(v1 XOR v2).
 */
export function findLcaHeight(v1, v2) {
    if (v1 === v2)
        return 0;
    const xor = v1 ^ v2;
    return xor.toString(2).length;
}
/**
 * Number of leaves in the aligned subtree for a given LCA height.
 * This is the dominant cost term: computing the tree is O(2^h).
 */
export function subtreeLeafCount(height) {
    return height === 0 ? 1 : 2 ** height;
}
/**
 * Total Cantor pairings required to reduce a height-h subtree to its root.
 * A full binary tree with 2^h leaves needs 2^h - 1 internal pairings.
 */
export function subtreeCantorOps(height) {
    return height === 0 ? 0 : 2 ** height - 1;
}
/**
 * The aligned base of the subtree containing v at the given height.
 */
export function alignedBase(v, height) {
    if (height <= 0)
        return v;
    const h = BigInt(height);
    return (v >> h) << h;
}
/**
 * Compute the Cantor number for a subtree rooted at (base, height).
 * O(2^h) computation.
 */
export function computeSubtreeCantor(base, height, maxComputeHeight = DEFAULT_MAX_COMPUTE_HEIGHT, onProgress) {
    if (height < 0)
        throw new Error('height must be >= 0');
    if (height > maxComputeHeight) {
        throw new Error(`height ${height} exceeds maxComputeHeight ${maxComputeHeight}`);
    }
    if (height === 0) {
        onProgress?.(1);
        return base;
    }
    const leafCount = 2 ** height;
    // The tree is folded leaf by leaf with a stack of partial roots, one per
    // level at most, instead of being built a level at a time. The root is the
    // same bit for bit: a pairing at level k joins the same two subtrees in the
    // same order whichever way the tree is walked. What changes is memory. A
    // level at a time holds every leaf as its own object (a million at height
    // 20, each with a header several times its 85 bits) and two whole levels at
    // once; the stack holds at most height + 1 numbers, which add up to about
    // one level's worth of digits. Measured at height 20: 328 MB down to 184 MB.
    //
    // Progress is charged by LEVEL, as before, and the difference from charging
    // by node is the whole reason a hop looked frozen: a pairing DOUBLES the
    // size of its operands, so every level costs about the same and is worth
    // the same slice of the bar; building the leaves is one more level. In the
    // fold the levels advance together, level k pairing once every 2^(k+1)
    // leaves, so the bar is the mean of the levels' completions. The last leaf
    // closes every level in turn and the top few pairings are the slow ones, so
    // each of those reports on its own.
    const totalLevels = height + 1;
    const tickEvery = Math.max(1, Math.floor(leafCount / PROGRESS_TICKS));
    const pairings = new Array(height).fill(0);
    const report = (leavesBuilt) => {
        if (!onProgress)
            return;
        let sum = leavesBuilt / leafCount;
        for (let k = 0; k < height; k++)
            sum += pairings[k] / 2 ** (height - 1 - k);
        onProgress(sum / totalLevels);
    };
    const values = [];
    const levels = [];
    for (let i = 0; i < leafCount; i++) {
        let value = base + BigInt(i);
        let level = 0;
        while (levels.length > 0 && levels[levels.length - 1] === level) {
            const left = values.pop();
            levels.pop();
            value = cantorPair(left, value);
            pairings[level]++;
            level++;
            // The top of the tree: few pairings, each a long one, each worth a report.
            if (i === leafCount - 1 && level >= height - 3)
                report(leafCount);
        }
        values.push(value);
        levels.push(level);
        if ((i + 1) % tickEvery === 0)
            report(i + 1);
    }
    onProgress?.(1);
    return values[0];
}
/**
 * Compute the axis Cantor root for two axis values.
 */
export function computeAxisCantor(v1, v2, maxComputeHeight = DEFAULT_MAX_COMPUTE_HEIGHT, onProgress) {
    const h = findLcaHeight(v1, v2);
    return computeSubtreeCantor(alignedBase(v1, h), h, maxComputeHeight, onProgress);
}
/**
 * Compute the spatial-only movement proof (region_n).
 */
export function computeMovementProof(x1, y1, z1, x2, y2, z2, maxComputeHeight = DEFAULT_MAX_COMPUTE_HEIGHT) {
    const cx = computeAxisCantor(x1, x2, maxComputeHeight);
    const cy = computeAxisCantor(y1, y2, maxComputeHeight);
    const cz = computeAxisCantor(z1, z2, maxComputeHeight);
    const combined = cantorPair(cantorPair(cx, cy), cz);
    const proofHash = sha256IntHex(combined);
    return { cantorX: cx, cantorY: cy, cantorZ: cz, combined, proofHash };
}
/**
 * Compute the full 4D hop proof (spatial + temporal) per spec §5.5–§5.7.
 *
 * @param plane destination plane bit (0 or 1)
 * @param previousEventIdHex 64-char lowercase hex
 */
export function computeHopProof(x1, y1, z1, x2, y2, z2, plane, previousEventIdHex, maxComputeHeight = DEFAULT_MAX_COMPUTE_HEIGHT, onProgress) {
    // Spatial component. Weight each axis's progress by its share of the work so
    // the reported fraction tracks real elapsed cost, not axis count.
    const hx = findLcaHeight(x1, x2);
    const hy = findLcaHeight(y1, y2);
    const hz = findLcaHeight(z1, z2);
    const tkPre = terrainK(x2, y2, z2, plane);
    // Everything after the four trees used to be free, according to the bar,
    // and it is not. Measured on a height-18 hop: the three axis trees take 3.1
    // seconds and the work after them takes 3.3. The bar reached 100% with more
    // than half the wall clock still to come, which is what a frozen hop with a
    // full progress bar and a stopped timer actually was.
    //
    // So the combination is charged too. A tree of height h costs h + 1 levels
    // (see computeSubtreeCantor), and the steps after it operate on the roots,
    // which are the largest values in the whole computation. Charged in the same
    // level units, measured against a height-18 hop where one level averaged
    // 68 ms: pairing two axis roots is about 4, folding in the third about 8,
    // folding in the temporal root about 16, and turning the result into bytes
    // and hashing it twice about 8 between them. These are approximations of a
    // superlinear cost by a linear one, and they are honest to within the width
    // of the bar rather than to within a percent.
    // In EXECUTION order, because stage() and step() hand out slices as they are
    // called and a slice taken out of order would run the bar backwards.
    const levels = (h) => h + 1;
    const work = [levels(hx), levels(hy), levels(hz), 4, 8, levels(tkPre), 16, 8];
    const totalWork = work.reduce((a, b) => a + b, 0);
    let baseFraction = 0;
    const stage = (i) => {
        if (!onProgress)
            return undefined;
        const share = work[i] / totalWork;
        const start = baseFraction;
        baseFraction += share;
        return (f) => onProgress(start + f * share);
    };
    /** Charge a non-tree step and report, so the tail keeps the bar moving. */
    const step = (i) => {
        if (!onProgress)
            return;
        baseFraction += work[i] / totalWork;
        onProgress(Math.min(1, baseFraction));
    };
    const cx = computeAxisCantor(x1, x2, maxComputeHeight, stage(0));
    const cy = computeAxisCantor(y1, y2, maxComputeHeight, stage(1));
    const cz = computeAxisCantor(z1, z2, maxComputeHeight, stage(2));
    const cxy = cantorPair(cx, cy);
    step(3);
    const regionN = cantorPair(cxy, cz);
    step(4);
    // Temporal component (§5.5.2)
    const tk = tkPre;
    // Seed from previous event id
    if (previousEventIdHex.length !== 64) {
        throw new Error('previousEventIdHex must be exactly 64 hex chars');
    }
    const prevIdBytes = hexToBytes(previousEventIdHex);
    let prevIdInt = 0n;
    for (const b of prevIdBytes) {
        prevIdInt = (prevIdInt << 8n) | BigInt(b);
    }
    const axisMask = (1n << BigInt(AXIS_BITS)) - 1n;
    const t = prevIdInt & axisMask; // mod 2^85
    // Temporal subtree root
    const cantorT = computeSubtreeCantor(alignedBase(t, tk), tk, TEMPORAL_MAX_COMPUTE_HEIGHT, stage(5));
    // 4D combination (§5.5.3)
    const hopN = cantorPair(regionN, cantorT);
    step(6);
    // Proof hash (§5.7): double SHA-256
    const movementProofKey = sha256(intToBytesBE(hopN));
    const proofHash = bytesToHex(sha256(movementProofKey));
    step(7);
    onProgress?.(1);
    return {
        cantorX: cx,
        cantorY: cy,
        cantorZ: cz,
        regionN,
        terrainK: tk,
        temporalSeed: t,
        cantorT,
        hopN,
        proofHash,
    };
}
/**
 * Estimate the cost of a hop without computing it. Used by the UI to warn
 * before a move that would take minutes, and to drive the live cost readout.
 */
export function estimateHopCost(x1, y1, z1, x2, y2, z2, plane, maxComputeHeight = DEFAULT_MAX_COMPUTE_HEIGHT) {
    const lcaX = findLcaHeight(x1, x2);
    const lcaY = findLcaHeight(y1, y2);
    const lcaZ = findLcaHeight(z1, z2);
    const tk = terrainK(x2, y2, z2, plane);
    const maxHeight = Math.max(lcaX, lcaY, lcaZ);
    const totalOps = subtreeCantorOps(lcaX) + subtreeCantorOps(lcaY) + subtreeCantorOps(lcaZ) + subtreeCantorOps(tk);
    return {
        lcaX,
        lcaY,
        lcaZ,
        terrainK: tk,
        maxHeight,
        totalOps,
        exceedsLimit: maxHeight > maxComputeHeight || tk > TEMPORAL_MAX_COMPUTE_HEIGHT,
    };
}
//# sourceMappingURL=movement.js.map