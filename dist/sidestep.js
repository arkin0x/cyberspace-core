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
import { cantorPair, intToBytesBE, sha256, sha256FromMidstate, sha256Midstate, hexToBytes, bytesToHex } from './cantor.js';
import { AXIS_BITS } from './coords.js';
import { GRANDFATHERED_V2_SIDESTEPS } from './grandfathered_v2_sidesteps.js';
import { TEMPORAL_MAX_COMPUTE_HEIGHT, alignedBase, computeSubtreeCantor, findLcaHeight, subtreeLeafCount, } from './movement.js';
import { terrainK } from './terrain.js';
/** Domain separation for the seeded leaves (spec 6.4). Bumped from V1 with the seed. */
export const SIDESTEP_DOMAIN = new TextEncoder().encode('CYBERSPACE_SIDESTEP_V2');
/** Nine zero bytes, so the seed prefix fills one 64-byte block exactly (spec 6.4, 6.5). */
export const SEED_PAD = new Uint8Array(9);
/** Domain separation for the re-roll price hash G (spec 6.10). 28 bytes. */
export const SIDESTEP_GRIND_DOMAIN = new TextEncoder().encode('CYBERSPACE_SIDESTEP_GRIND_V1');
/** Domain separation for the sampled opening indices, drawn from G (spec 6.10). V1 drew them from the root. */
export const SIDESTEP_SAMPLE_DOMAIN = new TextEncoder().encode('CYBERSPACE_SIDESTEP_SAMPLE_V2');
/** Sampled openings per non-trivial axis, after the destination's (spec 6.10). */
export const SIDESTEP_SAMPLES = 8;
/** The axis byte in the seed: X 0, Y 1, Z 2 (spec 6.4). */
export const AXIS_BYTE = { x: 0, y: 1, z: 2 };
/** Report progress roughly this many times over a full axis computation. */
const PROGRESS_TICKS = 64;
/**
 * Streaming index arithmetic uses Number leaf indices, exact below 2^53.
 * Heights past this bound are centuries of hashing anyway; refuse loudly
 * rather than corrupt silently.
 */
const MAX_STREAMING_HEIGHT = 52;
/**
 * Nodes from this many levels below the root are kept from the main pass, so
 * the openings can be assembled afterwards by rebuilding only the small
 * subtree under each opened leaf (see computeAxisMerkleRoot). 2^17 hashes,
 * 4 MB, whatever the height.
 */
const KEPT_LEVELS = 16;
/** The nonce is an unsigned 64-bit integer (spec 6.10). */
const NONCE_LIMIT = 1n << 64n;
const TWO_256 = 1n << 256n;
/** The nonce's eight bytes sit right after the domain, in G's first block (spec 6.10). */
const NONCE_AT = SIDESTEP_GRIND_DOMAIN.length;
const HEX64 = /^[0-9a-f]{64}$/;
function concatBytes(...parts) {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of parts) {
        out.set(p, at);
        at += p.length;
    }
    return out;
}
function bytesToBigInt(bytes) {
    let n = 0n;
    for (const b of bytes)
        n = (n << 8n) | BigInt(b);
    return n;
}
/**
 * The per-axis seed prefix (spec 6.4): domain, the 32 raw bytes of the
 * previous event id, the axis byte, and the pad, 64 bytes in all.
 */
export function seedPrefix(previousEventId, axisByte) {
    if (previousEventId.length !== 32)
        throw new Error('previous_event_id must be 32 raw bytes');
    if (axisByte < 0 || axisByte > 2)
        throw new Error('axis byte must be 0, 1 or 2');
    const prefix = concatBytes(SIDESTEP_DOMAIN, previousEventId, new Uint8Array([axisByte]), SEED_PAD);
    if (prefix.length !== 64)
        throw new Error('seed prefix must be exactly one SHA-256 block');
    return prefix;
}
/** A leaf hasher for one seed prefix, resuming from the prefix's midstate (spec 6.5). */
export function leafHasher(prefix) {
    const mid = sha256Midstate(prefix);
    return (value) => sha256FromMidstate(mid, intToBytesBE(value));
}
/** Merkle leaf hash: SHA256(seed_prefix || int_to_bytes_be_min(value)). */
export function merkleLeaf(prefix, value) {
    return sha256(concatBytes(prefix, intToBytesBE(value)));
}
/** Merkle internal node: SHA256(left || right). */
export function merkleParent(left, right) {
    return sha256(concatBytes(left, right));
}
/**
 * The sampled positions for an axis (spec 6.10): eight indices within the
 * aligned subtree drawn from G, the re-roll price hash, never from the root.
 * Collisions stand; the count is fixed.
 */
export function sampleIndices(G, axisByte, height) {
    if (height === 0)
        return [];
    const out = [];
    const mod = 1n << BigInt(height);
    for (let i = 0; i < SIDESTEP_SAMPLES; i++) {
        const be32 = new Uint8Array([(i >>> 24) & 0xff, (i >>> 16) & 0xff, (i >>> 8) & 0xff, i & 0xff]);
        const h = sha256(concatBytes(SIDESTEP_SAMPLE_DOMAIN, G, new Uint8Array([axisByte]), be32));
        out.push(Number(bytesToBigInt(h) % mod));
    }
    return out;
}
/**
 * A, the price in attempts (spec 6.10): the leaves of every axis that moves,
 * over SIDESTEP_SAMPLES, rounded up, and at least 1. An attempt is three
 * SHA-256 compressions, one leaf's share of the tree, so the A attempts a
 * prover makes on average cost one eighth of the crossing.
 */
export function sidestepAttempts(heights) {
    let leaves = 0n;
    for (const h of heights)
        if (h > 0)
            leaves += 1n << BigInt(h);
    const samples = BigInt(SIDESTEP_SAMPLES);
    const attempts = (leaves + samples - 1n) / samples;
    return attempts > 1n ? attempts : 1n;
}
function checkNonce(nonce) {
    if (nonce < 0n || nonce >= NONCE_LIMIT)
        throw new Error('the nonce is an unsigned 64-bit integer');
}
/** G's 164-byte preimage (spec 6.10), with the nonce's eight bytes left zero for the caller. */
function grindPreimage(previousEventId, roots) {
    if (previousEventId.length !== 32)
        throw new Error('previous_event_id must be 32 raw bytes');
    if (roots.length !== 3 || roots.some((r) => r.length !== 32))
        throw new Error('G takes the three 32-byte axis roots');
    return concatBytes(SIDESTEP_GRIND_DOMAIN, new Uint8Array(8), previousEventId, roots[0], roots[1], roots[2]);
}
/**
 * G = SHA256(SIDESTEP_GRIND_DOMAIN || be64(nonce) || previous_event_id ||
 * M_x || M_y || M_z) (spec 6.10), with each M the axis root, or for a trivial
 * axis its single seeded leaf. Three blocks with the nonce in the first, so no
 * midstate survives from one attempt to the next.
 */
export function sidestepGrindHash(previousEventId, roots, nonce) {
    checkNonce(nonce);
    const preimage = grindPreimage(previousEventId, roots);
    new DataView(preimage.buffer).setBigUint64(NONCE_AT, nonce);
    return sha256(preimage);
}
/** The price (spec 6.10): G, read as a 256-bit big-endian integer, times A is below 2^256. */
export function meetsPrice(G, attempts) {
    if (G.length !== 32)
        throw new Error('G is 32 bytes');
    if (attempts < 1n)
        throw new Error('the price is at least one attempt');
    return bytesToBigInt(G) * attempts < TWO_256;
}
/**
 * The first nonce from `start` upward and below `end` whose G meets the price
 * (spec 6.10), or null when that range holds none. Any such nonce verifies,
 * so a caller can split the search over workers by giving each a disjoint
 * range and keeping whichever finds one first.
 */
export function findSidestepNonce(previousEventId, roots, attempts, search = {}) {
    const { start = 0n, end = NONCE_LIMIT, onProgress } = search;
    if (start < 0n || end > NONCE_LIMIT || start > end)
        throw new Error('the nonce range must lie within 0 .. 2^64');
    if (attempts < 1n)
        throw new Error('the price is at least one attempt');
    const preimage = grindPreimage(previousEventId, roots);
    const view = new DataView(preimage.buffer);
    // G × A < 2^256 exactly when G <= floor((2^256 - 1) / A), so each attempt
    // compares bytes, usually only the first, instead of building a bigint.
    const threshold = hexToBytes(((TWO_256 - 1n) / attempts).toString(16).padStart(64, '0'));
    const expected = Number(attempts);
    const tickEvery = Math.max(1, Math.floor(expected / PROGRESS_TICKS));
    let tried = 0;
    for (let nonce = start; nonce < end; nonce++) {
        view.setBigUint64(NONCE_AT, nonce);
        const G = sha256(preimage);
        if (notAbove(G, threshold)) {
            onProgress?.(1);
            return { nonce, G };
        }
        tried++;
        if (onProgress && tried % tickEvery === 0)
            onProgress(-Math.expm1(-tried / expected));
    }
    return null;
}
/** a <= b, for two 32-byte big-endian integers. */
function notAbove(a, b) {
    for (let i = 0; i < 32; i++)
        if (a[i] !== b[i])
            return a[i] < b[i];
    return true;
}
/** The `mn` tag's value (spec 8.5): the nonce as exactly 16 lowercase hex characters, big-endian. */
export function encodeNonce(nonce) {
    checkNonce(nonce);
    return nonce.toString(16).padStart(16, '0');
}
/** The nonce in an `mn` tag's value, or null unless it is exactly 16 lowercase hex characters (spec 8.5). */
export function decodeNonce(hex) {
    return /^[0-9a-f]{16}$/.test(hex) ? BigInt('0x' + hex) : null;
}
/**
 * Whether an event is one of the version 2 sidesteps exempt under spec 6.16,
 * which carry no `mn` tag and keep their roots and openings unchecked.
 */
export function isGrandfatheredV2Sidestep(eventId) {
    return eventId !== undefined && GRANDFATHERED_V2_SIDESTEPS.has(eventId);
}
/**
 * A streaming fold over the leaves `first .. first + 2^height - 1` (spec
 * 6.5): each leaf is pushed and merged with the pending node of its own level
 * until levels differ, so at most `height` nodes are pending at once. `keep`
 * receives every node at or above level `keepFrom`, by level and by index
 * within the level.
 */
function fold(leaf, base, first, height, keepFrom, keep, onLeaf) {
    const count = 2 ** height;
    const stack = [];
    for (let i = 0; i < count; i++) {
        const at = first + i;
        let hash = leaf(base + BigInt(at));
        let level = 0;
        let start = at;
        if (keepFrom === 0)
            keep(0, at, hash);
        while (stack.length > 0 && stack[stack.length - 1].level === level) {
            const left = stack.pop();
            hash = merkleParent(left.hash, hash);
            level += 1;
            start = left.start;
            if (level >= keepFrom)
                keep(level, start / 2 ** level, hash);
        }
        stack.push({ hash, level, start });
        onLeaf?.(i);
    }
    if (stack.length !== 1)
        throw new Error(`expected single root, got ${stack.length}`);
    return stack[0].hash;
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
export function computeAxisMerkleRoot(prefix, axisByte, v1, v2, onProgress) {
    const height = findLcaHeight(v1, v2);
    const leaf = leafHasher(prefix);
    if (height === 0) {
        onProgress?.(1);
        return { root: leaf(v1), height: 0, openingsFor: () => [] };
    }
    if (height > MAX_STREAMING_HEIGHT) {
        throw new Error(`LCA height ${height} exceeds streaming index range (2^53 leaves)`);
    }
    const base = alignedBase(v1, height);
    const leafCount = 2 ** height;
    const keepFrom = Math.max(0, height - KEPT_LEVELS);
    // One packed buffer per kept level, 32 bytes per node, rather than an
    // object per node: three axes' worth now stay alive through the nonce search.
    const kept = [];
    for (let level = 0; level <= height; level++)
        kept.push(new Uint8Array(level >= keepFrom ? 32 * 2 ** (height - level) : 0));
    const tickEvery = Math.max(1, Math.floor(leafCount / PROGRESS_TICKS));
    const root = fold(leaf, base, 0, height, keepFrom, (level, index, hash) => kept[level].set(hash, 32 * index), (i) => {
        if (onProgress && (i + 1) % tickEvery === 0)
            onProgress((i + 1) / leafCount);
    });
    // The path for one leaf: siblings below keepFrom from a rebuild of its
    // level-keepFrom subtree, siblings from keepFrom up from what was kept.
    const pathFor = (index) => {
        const siblings = new Array(height);
        if (keepFrom > 0) {
            const size = 2 ** keepFrom;
            const first = Math.floor(index / size) * size;
            const local = [];
            for (let level = 0; level < keepFrom; level++)
                local.push(new Array(2 ** (keepFrom - level)));
            fold(leaf, base, first, keepFrom, 0, (level, idx, hash) => { if (level < keepFrom)
                local[level][idx - first / 2 ** level] = hash; });
            for (let level = 0; level < keepFrom; level++) {
                const at = Math.floor(index / 2 ** level) - first / 2 ** level;
                siblings[level] = local[level][at ^ 1];
            }
        }
        for (let level = keepFrom; level < height; level++) {
            const at = 32 * (Math.floor(index / 2 ** level) ^ 1);
            siblings[level] = kept[level].slice(at, at + 32);
        }
        for (let level = 0; level < height; level++)
            if (!siblings[level])
                throw new Error('incomplete opening');
        return siblings;
    };
    const destIndex = Number(v2 - base);
    onProgress?.(1);
    return {
        root,
        height,
        openingsFor: (G) => [pathFor(destIndex), ...sampleIndices(G, axisByte, height).map(pathFor)],
    };
}
/**
 * Whether `siblings` carry the leaf at `leafValue` up to `expectedRoot` in a
 * tree of `height` over the subtree at `base`. The leaf is recomputed from
 * the seed, never taken from the proof.
 */
export function verifyMerkleInclusion(prefix, leafValue, siblings, expectedRoot, height, base) {
    if (height === 0) {
        return siblings.length === 0 && bytesToHex(merkleLeaf(prefix, leafValue)) === bytesToHex(expectedRoot);
    }
    if (siblings.length !== height)
        return false;
    if (leafValue < base || leafValue - base >= (1n << BigInt(height)))
        return false;
    const leafIndex = Number(leafValue - base);
    let current = merkleLeaf(prefix, leafValue);
    for (let level = 0; level < height; level++) {
        // The bit at this level of the leaf index says which child the path is.
        if ((Math.floor(leafIndex / 2 ** level) & 1) === 0)
            current = merkleParent(current, siblings[level]);
        else
            current = merkleParent(siblings[level], current);
    }
    return bytesToHex(current) === bytesToHex(expectedRoot);
}
/**
 * Level 1 for one axis (spec 6.11, 8.7.2 step 5): the destination's path,
 * then each leaf sampled from G recomputed from the seed and carried to the
 * root. G is the caller's to derive and price-check (sidestepGrindHash,
 * meetsPrice); this checks the paths only.
 */
export function verifyAxisOpenings(prefix, axisByte, v1, v2, root, openings, G) {
    const height = findLcaHeight(v1, v2);
    if (height === 0)
        return openings.length === 0 && bytesToHex(merkleLeaf(prefix, v1)) === bytesToHex(root);
    if (openings.length !== SIDESTEP_SAMPLES + 1)
        return false;
    if (openings.some((p) => p.length !== height))
        return false;
    const base = alignedBase(v1, height);
    if (!verifyMerkleInclusion(prefix, v2, openings[0], root, height, base))
        return false;
    const samples = sampleIndices(G, axisByte, height);
    for (let i = 0; i < SIDESTEP_SAMPLES; i++) {
        if (!verifyMerkleInclusion(prefix, base + BigInt(samples[i]), openings[i + 1], root, height, base))
            return false;
    }
    return true;
}
/** The `mp` segment for one axis (spec 8.5): every opening's siblings, leaf first, as one hex string. */
export function encodeOpenings(openings) {
    let out = '';
    for (const path of openings)
        for (const s of path)
            out += bytesToHex(s);
    return out;
}
/**
 * The openings from an `mp` segment for an axis of LCA height `height`
 * (spec 8.5). Null when malformed, and null for a v1 segment (one path
 * rather than nine), which spec 6.15 says must be rejected.
 */
export function decodeOpenings(segment, height) {
    if (height === 0)
        return segment === '' ? [] : null;
    if (!/^[0-9a-f]*$/.test(segment))
        return null;
    const per = 64 * height;
    if (segment.length !== per * (SIDESTEP_SAMPLES + 1))
        return null;
    const out = [];
    for (let p = 0; p < SIDESTEP_SAMPLES + 1; p++) {
        const path = [];
        for (let level = 0; level < height; level++) {
            const at = p * per + level * 64;
            path.push(hexToBytes(segment.slice(at, at + 64)));
        }
        out.push(path);
    }
    return out;
}
/** SHA-256 evaluations to build one axis tree: 2^h leaves + 2^h - 1 internals. */
function axisHashCount(height) {
    return height === 0 ? 1 : 2 ** (height + 1) - 1;
}
/**
 * Closed-form cost of a sidestep. Unlike the hop estimate there is no
 * feasibility ceiling: a sidestep is always storable, only ever slow. The
 * openings add nine small rebuilds per axis, not counted here.
 */
export function estimateSidestepCost(x1, y1, z1, x2, y2, z2) {
    const lcaX = findLcaHeight(x1, x2);
    const lcaY = findLcaHeight(y1, y2);
    const lcaZ = findLcaHeight(z1, z2);
    return {
        lcaX,
        lcaY,
        lcaZ,
        maxHeight: Math.max(lcaX, lcaY, lcaZ),
        totalHashes: axisHashCount(lcaX) + axisHashCount(lcaY) + axisHashCount(lcaZ),
        attempts: Number(sidestepAttempts([lcaX, lcaY, lcaZ])),
    };
}
/**
 * The landing coordinate for a sidestep from v1 across the highest boundary
 * toward `target`: exactly 1 gibson past that boundary (spec 6.3). Upward
 * that is the adjacent subtree's first leaf; downward its last.
 */
export function sidestepLanding(v1, target) {
    const h = findLcaHeight(v1, target);
    if (h === 0)
        return v1;
    const hb = BigInt(h - 1);
    const childBase = (v1 >> hb) << hb;
    return target > v1 ? childBase + (1n << hb) : childBase - 1n;
}
/**
 * Spec 6.3 on one axis: with h the LCA height of the pair, the source touches
 * the wall on its side (base + half - 1 going up, base + half going down) and
 * the destination is exactly one gibson past it. An axis that does not move
 * is a valid trivial crossing.
 */
export function validCrossing(v1, v2) {
    const h = findLcaHeight(v1, v2);
    if (h === 0)
        return true;
    const base = alignedBase(v1, h);
    const half = 1n << BigInt(h - 1);
    return v2 > v1 ? v1 === base + half - 1n && v2 === base + half : v1 === base + half && v2 === base + half - 1n;
}
/** The temporal seed and its Cantor root (spec 6.7), shared with hops. */
function temporal(previousEventIdHex, K, onProgress) {
    const prevIdInt = bytesToBigInt(hexToBytes(previousEventIdHex));
    const axisMask = (1n << BigInt(AXIS_BITS)) - 1n;
    const t = prevIdInt & axisMask; // mod 2^85
    return { t, cantorT: computeSubtreeCantor(alignedBase(t, K), K, TEMPORAL_MAX_COMPUTE_HEIGHT, onProgress) };
}
/**
 * Compute a full sidestep proof: per-axis seeded Merkle roots, the re-roll
 * nonce, and the openings sampled from its G, with the roots combined into
 * region_m, plus the temporal Cantor binding identical to hop proofs (spec
 * 6.4 - 6.10). The nonce is the first meeting the price searching upward
 * from 0 on this thread, as in the golden vectors. The search is one eighth
 * of the tree's work, and the tree itself runs on this thread too.
 */
export function computeSidestepProof(x1, y1, z1, x2, y2, z2, plane, previousEventIdHex, onProgress) {
    if (previousEventIdHex.length !== 64)
        throw new Error('previousEventIdHex must be exactly 64 hex chars');
    const prevId = hexToBytes(previousEventIdHex);
    // Weight each stage's progress by its share of the hash work, mirroring
    // computeHopProof, so the reported fraction tracks elapsed cost. An attempt
    // at the price is three compressions against a tree hash's one and a half.
    const hx = findLcaHeight(x1, x2);
    const hy = findLcaHeight(y1, y2);
    const hz = findLcaHeight(z1, z2);
    const attempts = sidestepAttempts([hx, hy, hz]);
    const tk = terrainK(x2, y2, z2, plane);
    const work = [axisHashCount(hx), axisHashCount(hy), axisHashCount(hz), 2 * Number(attempts), subtreeLeafCount(tk)];
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
    const ax = computeAxisMerkleRoot(seedPrefix(prevId, AXIS_BYTE.x), AXIS_BYTE.x, x1, x2, stage(0));
    const ay = computeAxisMerkleRoot(seedPrefix(prevId, AXIS_BYTE.y), AXIS_BYTE.y, y1, y2, stage(1));
    const az = computeAxisMerkleRoot(seedPrefix(prevId, AXIS_BYTE.z), AXIS_BYTE.z, z1, z2, stage(2));
    // The samples come from G, and G from all three roots and the nonce, so the
    // openings are taken last (spec 6.10).
    const found = findSidestepNonce(prevId, [ax.root, ay.root, az.root], attempts, { onProgress: stage(3) });
    if (!found)
        throw new Error('no 64-bit nonce meets the price');
    const { nonce, G } = found;
    const openings = { x: ax.openingsFor(G), y: ay.openingsFor(G), z: az.openingsFor(G) };
    const regionM = cantorPair(cantorPair(bytesToBigInt(ax.root), bytesToBigInt(ay.root)), bytesToBigInt(az.root));
    const { t, cantorT } = temporal(previousEventIdHex, tk, stage(4));
    const sidestepN = cantorPair(regionM, cantorT);
    // Proof hash (spec 6.8): double SHA-256.
    const proofHash = bytesToHex(sha256(sha256(intToBytesBE(sidestepN))));
    onProgress?.(1);
    return {
        merkleX: ax.root,
        merkleY: ay.root,
        merkleZ: az.root,
        regionM,
        terrainK: tk,
        temporalSeed: t,
        cantorT,
        sidestepN,
        proofHash,
        lcaHeights: [ax.height, ay.height, az.height],
        nonce,
        G,
        openings,
    };
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
export function verifySidestepLevel1(claim) {
    const failed = [];
    if (!HEX64.test(claim.previousEventIdHex))
        return ['previous_event_id'];
    const prevId = hexToBytes(claim.previousEventIdHex);
    // Undefined as well as null, for a caller that passes a missing tag straight through.
    const absent = claim.nonce === null || claim.nonce === undefined;
    const exempt = absent && isGrandfatheredV2Sidestep(claim.eventId);
    const nonce = absent ? null : decodeNonce(claim.nonce);
    if (nonce === null && !exempt)
        failed.push('mn');
    const axes = ['x', 'y', 'z'];
    const heights = [];
    const roots = [];
    axes.forEach((axis, i) => {
        const v1 = claim.from[axis], v2 = claim.to[axis];
        const h = findLcaHeight(v1, v2);
        heights.push(h);
        if (claim.lcaHeights[i] !== h)
            failed.push(`h${axis}`);
        if (!validCrossing(v1, v2))
            failed.push(`geometry:${axis}`);
        const rootHex = claim.merkleRoots[i];
        if (!HEX64.test(rootHex)) {
            failed.push(`mr:${axis}`);
            roots.push(null);
            return;
        }
        roots.push(hexToBytes(rootHex));
    });
    if (!exempt) {
        // Step 4: G from the claimed roots and nonce, then its price.
        let G = null;
        if (nonce !== null && roots.every((r) => r !== null)) {
            G = sidestepGrindHash(prevId, roots, nonce);
            if (!meetsPrice(G, sidestepAttempts(heights)))
                failed.push('price');
        }
        // Step 5: the destination path and the paths at the positions G draws.
        axes.forEach((axis, i) => {
            const openings = decodeOpenings(claim.openings[i], heights[i]);
            if (!openings) {
                failed.push(`mp:${axis}`);
                return;
            }
            const root = roots[i];
            if (G === null || root === null)
                return;
            if (!verifyAxisOpenings(seedPrefix(prevId, AXIS_BYTE[axis]), AXIS_BYTE[axis], claim.from[axis], claim.to[axis], root, openings, G)) {
                failed.push(`openings:${axis}`);
            }
        });
    }
    if (failed.length)
        return failed;
    const [mx, my, mz] = roots.map((r) => bytesToBigInt(r));
    const regionM = cantorPair(cantorPair(mx, my), mz);
    const K = terrainK(claim.to.x, claim.to.y, claim.to.z, claim.plane);
    const { cantorT } = temporal(claim.previousEventIdHex, K);
    const proofHash = bytesToHex(sha256(sha256(intToBytesBE(cantorPair(regionM, cantorT)))));
    if (proofHash !== claim.proofHash)
        failed.push('proof');
    return failed;
}
//# sourceMappingURL=sidestep.js.map