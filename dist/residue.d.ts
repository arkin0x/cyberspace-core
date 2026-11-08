/**
 * residue.ts - residue openings, version 2 of the hop proof (spec 5.9 to 5.13).
 *
 * Version 1 of the hop proof is SHA256(SHA256(hop_n)) (spec 5.6), a
 * fingerprint, so checking it means rebuilding every tree: verification costs
 * what production costs. Version 2 keeps the Cantor work exactly as it was and
 * changes only the commitment at the end. A Cantor root modulo an odd p is the
 * same tree carried on a clock of p positions, with halving replaced by a
 * multiplication by (p + 1) / 2, so anyone can compute hop_n mod p in word
 * arithmetic without building hop_n (5.9). The prover computes hop_n modulo m
 * primes, each drawn on its own from the previous event id and its index,
 * seals that list in a Merkle tree (the `proof` tag), pays a re-roll price in
 * residue work for a nonce (the `mn` tag), and opens the 16 entries the nonce
 * draws (the `mp` tag) (5.10). A verifier recomputes those 16 entries itself
 * and climbs their paths to the seal (5.11): milliseconds at height 20.
 *
 * Two seams keep the arithmetic replaceable. A WordKernel does the 61-bit
 * modular work (the prime search, a root modulo one prime, the combine modulo
 * every prime, and optionally whole steps with their hashes); JS_WORD_KERNEL
 * is the pure JavaScript one, Montgomery with 25-bit limbs in plain numbers,
 * and WASM_WORD_KERNEL is src/residue/kern.ts compiled (64-bit Montgomery in
 * WebAssembly, committed as kernWasm.ts). Every function that takes a kernel
 * defaults to selectWordKernel(): WASM when WebAssembly is there and the
 * module can be instantiated, JavaScript otherwise. A BigBackend does the big
 * numbers: the Cantor trees, the exact pairings for region_n, the product
 * tree of the primes, the pairings modulo Q and the remainder trees.
 * BIGINT_BACKEND is native BigInt and the default; a consumer passes its own
 * as `backend` to computeHopProofV2, proveHopResidues, computeHopResidues or
 * auditHopLevel2 (a GMP adapter, say, which core never imports: see the
 * README). Every implementation of either MUST give the same values, which
 * the golden vectors check. The three exported implementations are frozen.
 *
 * Checked against the spec's hop-residue-vectors.json (written from
 * hop-residue-reference.py), copied unchanged into test/fixtures.
 */
import { type Plane, type Xyz } from './coords.js';
import { type ProgressFn } from './movement.js';
import { encodeNonce, type NonceSearch } from './sidestep.js';
/** Domain of the hop primes (5.9). 31 bytes. */
export declare const HOP_RESIDUE_PRIME_DOMAIN: Uint8Array<ArrayBufferLike>;
/** Domain of the seal's leaves (5.10). 30 bytes. */
export declare const HOP_RESIDUE_LEAF_DOMAIN: Uint8Array<ArrayBufferLike>;
/** Domain of the re-roll attempt, both its seed and its G (5.10). 31 bytes. */
export declare const HOP_RESIDUE_GRIND_DOMAIN: Uint8Array<ArrayBufferLike>;
/** Domain of the draw of sample indices from G (5.10). 32 bytes. */
export declare const HOP_RESIDUE_SAMPLE_DOMAIN: Uint8Array<ArrayBufferLike>;
/** Residues a verifier recomputes. */
export declare const HOP_SAMPLES = 16;
/** Residues per Merkle leaf. */
export declare const RESIDUE_BLOCK = 8;
/** Every hop prime is at least 2^61. */
export declare const PRIME_BITS = 61;
/** The primes' product spans a quarter of the widest root. */
export declare const WIDTH_DIVISOR = 4;
/** One re-roll attempt is one aligned height-12 tree modulo p_0. */
export declare const HOP_GRIND_HEIGHT = 12;
/** The small-factor filter of the prime search (5.9). */
export declare const SMALL_ODD_PRIMES: readonly number[];
/** The re-roll budget B(h) in attempts for heights 0 to 22 (5.9, 5.10): one sixteenth of an honest hop at that height. */
export declare const HOP_REROLL_BUDGET: readonly bigint[];
/** The leaf that pads the seal's tree to a power of two (5.10). */
export declare const PAD_LEAF: Uint8Array<ArrayBuffer>;
/** be64(n) (5.9): n as 8 big-endian bytes, for 0 <= n < 2^64. */
export declare function be64(n: bigint | number): Uint8Array;
/** be32(n) (5.9): n as 4 big-endian bytes, for 0 <= n < 2^32. */
export declare function be32(n: number): Uint8Array;
/**
 * A list of values below 2^64, two 32-bit words each, high word first:
 * entry j is (list[2j] << 32) | list[2j + 1]. Primes and residues travel this
 * way between the kernel, the big-number backend and the seal, so a WASM
 * kernel can copy one buffer and no step depends on the platform's byte order.
 */
export type WordList = Uint32Array;
/** An empty word list for `count` values. */
export declare function wordList(count: number): WordList;
/** Entry j of a word list. */
export declare function wordAt(list: WordList, j: number): bigint;
/** Sets entry j of a word list to v, for 0 <= v < 2^64. */
export declare function setWord(list: WordList, j: number, v: bigint): void;
/** A word list's values, in order. */
export declare function wordsOf(list: WordList): bigint[];
/** SHA-256 over be64 of every value in a word list, as the vectors hash the primes and residues. */
export declare function wordListSha256(list: WordList): Uint8Array;
/**
 * The 61-bit modular arithmetic of residue openings. Every method returns
 * exactly what spec 5.9 defines; an implementation chooses only how fast.
 */
export interface WordKernel {
    readonly name: string;
    /**
     * For each j, the hop prime search of 5.9 from the odd start at entry j of
     * `starts` (in [2^61, 2^62)): the smallest n >= start, stepping by 2, with no
     * factor in SMALL_ODD_PRIMES that is a base-2 strong probable prime. Written
     * to entry j of `out`.
     */
    searchPrimes(starts: WordList, out: WordList): void;
    /**
     * compute_subtree_cantor(base, height) mod p for an odd p in [2^61, 2^62),
     * by any equivalent method (5.9), without the root. `base` is any natural
     * number.
     */
    rootResidue(p: bigint, base: bigint, height: number): bigint;
    /** pi_p(a, b) (5.9) for a and b below p. */
    pairMod(p: bigint, a: bigint, b: bigint): bigint;
    /**
     * For each j, the entries j of `parts` folded from the left with pi modulo
     * prime j: pi_p(pi_p(pi_p(a, b), c), d) for four parts, pi_p(a, b) for two.
     * Every entry of every part is below its prime. Written to entry j of `out`.
     */
    combine(primes: WordList, parts: readonly WordList[], out: WordList): void;
    /** p_0 to p_(m-1) for an id (5.9), m = out.length / 2 (at most 2^53), into `out`: deriveHopPrimes. */
    hopPrimes?(previousEventId: Uint8Array, out: WordList): void;
    /** One attempt (5.10) for a nonce below 2^64 under a seal: hopAttempt. */
    attempt?(previousEventId: Uint8Array, seal: Uint8Array, nonce: bigint, p0: bigint): HopAttempt;
    /**
     * The first nonce in [start, end) whose attempt meets the price `attempts`
     * (G A < 2^256), with that attempt, or null: one range of findHopNonce.
     */
    findNonce?(previousEventId: Uint8Array, seal: Uint8Array, attempts: bigint, p0: bigint, start: bigint, end: bigint): HopNonce | null;
}
/** The product tree over a hop's primes: level 0 the primes, each level up the products of pairs, the top Q. */
export interface ProductTree<N> {
    readonly levels: readonly (readonly N[])[];
}
/**
 * The big-number arithmetic of a hop, every step of the prover that works on
 * numbers wider than a word: the Cantor trees, the exact pairings for
 * region_n, the product tree of the primes, the region pairings modulo Q (the
 * multi-axis path of the prover) and the remainder trees. The values are the
 * backend's own type N, which core only passes back to the same backend;
 * native BigInt is N = bigint.
 *
 * Any implementation MUST return exactly the values BIGINT_BACKEND returns
 * (the residues, and so the tags, are then bit for bit the same); it chooses
 * only how fast and in what memory. Methods never modify their arguments.
 */
export interface BigBackend<N = bigint> {
    readonly name: string;
    fromBigInt(v: bigint): N;
    toBigInt(v: N): bigint;
    /** compute_subtree_cantor(base, height) (4.6), refusing heights above maxComputeHeight. */
    subtreeCantor(base: bigint, height: number, maxComputeHeight: number, onProgress?: ProgressFn): N;
    /** pi(a, b) exactly. */
    pair(a: N, b: N): N;
    /** The product tree over the primes, built once per hop. */
    productTree(primes: WordList): ProductTree<N>;
    /** pi(a, b) mod Q, from a and b reduced modulo Q first, Q the product of every prime (odd, so halving is exact). */
    pairModQ(tree: ProductTree<N>, a: N, b: N): N;
    /** x mod p_j for every prime, by one descent of the tree, into entry j of `out`. */
    remainders(tree: ProductTree<N>, x: N, out: WordList): void;
    /**
     * Optional, for a backend whose values live outside the JavaScript heap (a
     * GMP adapter's mpz_t in WebAssembly memory, which no garbage collector
     * sees): frees one value. Core calls it exactly once for every value it
     * made through the backend, as soon as it no longer needs it, and never for
     * a value it was given (the roots handed to proveHopResidues and
     * computeHopResidues stay the caller's). BigInt needs neither hook.
     */
    release?(value: N): void;
    /** Optional, as `release`: frees a product tree core made through `productTree`. */
    releaseTree?(tree: ProductTree<N>): void;
}
/** pi_p(a, b) = ((a + b)(a + b + 1)(p + 1)/2 + b) mod p, for odd p: pi(a, b) mod p from a mod p and b mod p. */
export declare function pairModP(a: bigint, b: bigint, p: bigint): bigint;
/** compute_subtree_cantor(base, height) mod p, by the same tree carried modulo p (5.9). The definition, in BigInt. */
export declare function residueTree(base: bigint, height: number, p: bigint): bigint;
/**
 * The same value by Babbage's method of differences at level k (5.9). The
 * level-k nodes of an aligned tree are the values of one polynomial of degree
 * 2^k at evenly spaced points, so once its differences are tabulated each
 * further node costs 2^k additions modulo p. In BigInt, for checking kernels.
 */
export declare function residueEngine(base: bigint, height: number, p: bigint, k?: number): bigint;
/**
 * The difference engine's level for a residue of height h: the reference's
 * choice below h16, and 7 from there up (2^7 additions per node). Every level
 * gives the same residue; this one is only the fastest measured.
 */
export declare function engineLevel(height: number): number;
/** The pure JavaScript word kernel: Montgomery arithmetic in 25-bit limbs, the difference engine for roots. */
export declare const JS_WORD_KERNEL: WordKernel;
/** The committed module's bytes. Decoded here so it works the same in Node, browsers and workers. */
export declare function wasmWordKernelBytes(): Uint8Array;
/**
 * Instantiates the WASM word kernel asynchronously (WebAssembly.instantiate on
 * the committed bytes; nothing is fetched), which works on every thread of
 * every runtime that has WebAssembly. Resolves to WASM_WORD_KERNEL, ready; a
 * second call returns the first's promise. Rejects where WebAssembly is
 * missing or disabled (iOS Lockdown Mode, some locked-down WebViews), and
 * then JS_WORD_KERNEL is the kernel to use.
 */
export declare function loadWasmWordKernel(): Promise<WordKernel>;
/**
 * Whether WASM_WORD_KERNEL can run now: instantiated already, or
 * instantiable synchronously on this thread (tried once).
 */
export declare function wasmWordKernelReady(): boolean;
export type WordKernelChoice = 'auto' | 'wasm' | 'js';
/**
 * The word kernel for a choice: `js` always JS_WORD_KERNEL; `wasm` always
 * WASM_WORD_KERNEL, throwing when it cannot run here; `auto` (every
 * function's default) WASM when it can run now and JavaScript otherwise. A
 * page that wants WASM everywhere awaits loadWasmWordKernel() once at start,
 * so `auto` finds the module ready even where a synchronous compile is
 * refused. Both kernels give identical values, so the choice changes only the
 * speed.
 */
export declare function selectWordKernel(choice?: WordKernelChoice): WordKernel;
/**
 * The WASM word kernel: src/residue/kern.ts, 64-bit Montgomery arithmetic in
 * WebAssembly, with the prime derivation, the attempt and the nonce search
 * done whole inside the module. Instantiated on first use (synchronously), or
 * ahead of time by loadWasmWordKernel(). Gives exactly JS_WORD_KERNEL's
 * values, several times faster.
 */
export declare const WASM_WORD_KERNEL: WordKernel;
/** Native BigInt: the Cantor trees of movement.ts, and the product and remainder trees in plain BigInt. */
export declare const BIGINT_BACKEND: BigBackend<bigint>;
/**
 * Where the search for p_j starts (5.9 steps 1 to 3): the first 8 bytes of
 * SHA256(domain || previous_event_id || be64(j)), shifted right 4 bits, plus
 * 2^61, made odd. The 71-byte preimage is two compressions; the first block
 * ends with the first byte of be64(j), so its midstate serves every j below
 * 2^56.
 */
export declare function hopPrimeStart(previousEventId: Uint8Array, j: bigint | number): bigint;
/** p_j (5.9): the prime search from hopPrimeStart. Never deduplicated across indices. */
export declare function hopPrime(previousEventId: Uint8Array, j: bigint | number, kernel?: WordKernel): bigint;
/** p_0 to p_(m-1), in one batch through the kernel. */
export declare function deriveHopPrimes(previousEventId: Uint8Array, m: number, kernel?: WordKernel): WordList;
/** One aligned tree of a hop: its base and its height. */
export interface HopTree {
    base: bigint;
    height: number;
}
export interface HopGeometry {
    /** The three axis trees, x, y, z (4.4, 4.5). */
    axes: [HopTree, HopTree, HopTree];
    /** The temporal tree: t_base and K (5.2, 5.3). */
    temporal: HopTree;
    /** K, the terrain height at the destination, plane bit included. */
    K: number;
    /** t = previous_event_id mod 2^85 (5.3), before alignment. */
    temporalSeed: bigint;
    /** The largest of the three axis heights and K. */
    hMax: number;
    /** m, the residue count (5.9). */
    m: bigint;
    /** m / RESIDUE_BLOCK leaves before padding. */
    blocks: bigint;
    /** Levels of the seal's tree above its leaves (5.10). */
    depth: number;
    /** A, the re-roll price in attempts (5.10). */
    A: bigint;
}
/** m (5.9): enough 61-bit primes for Q to span a quarter of an 85 2^h_max bit root, in whole blocks of 8. */
export declare function hopResidueCount(hMax: number): bigint;
/** depth (5.10): the smallest d with 2^d >= m / RESIDUE_BLOCK. */
export declare function hopMerkleDepth(m: bigint): number;
/** Characters of the `mp` tag at a depth (8.4): HOP_SAMPLES (128 + 64 depth). */
export declare function hopOpeningsLength(depth: number): number;
/** B(h) (5.10): the table for h <= 22, and floor(223681 9^(h-22) / 4^(h-22)) above, in exact integers. */
export declare function hopRerollBudget(h: number): bigint;
/** A (5.10): the budgets of the three axis heights and K, summed, and at least 1. */
export declare function hopRerollAttempts(heights: readonly number[]): bigint;
/**
 * Everything a verifier derives from the event (5.11 step 1, 8.7.1 steps 1
 * to 6), taking nothing from the prover: each axis's height and base from the
 * source and destination, K from the destination including its plane bit,
 * t_base from previous_event_id and K, and from those h_max, m, depth and A.
 */
export declare function hopGeometry(previousEventId: Uint8Array, from: Xyz, to: Xyz): HopGeometry;
/** Each root modulo p and hop_n modulo p (5.9), from the geometry alone: no root, no region_n, no hop_n. */
export interface HopRootResidues {
    x: bigint;
    y: bigint;
    z: bigint;
    t: bigint;
    /** pi_p(pi_p(pi_p(x, y), z), t), which is hop_n mod p. */
    hopN: bigint;
}
export declare function hopRootResidues(geometry: HopGeometry, p: bigint, kernel?: WordKernel): HopRootResidues;
/** hop_n mod p (5.9, 5.11 step 5), in word arithmetic. */
export declare function hopResidue(geometry: HopGeometry, p: bigint, kernel?: WordKernel): bigint;
/** leaf_b = SHA256(LEAF_DOMAIN || previous_event_id || be64(b) || be64(r_8b) || ... || be64(r_8b+7)). */
export declare function hopLeafHash(previousEventId: Uint8Array, block: bigint | number, residues: readonly bigint[]): Uint8Array;
/** The seal's tree: every level packed 32 bytes per node, leaves first (padded with PAD_LEAF), the seal last. */
export interface HopSealTree {
    seal: Uint8Array;
    levels: Uint8Array[];
}
/** The seal over a list of residues (5.10), keeping every level so any block can be opened. */
export declare function hopSealTree(previousEventId: Uint8Array, residues: WordList): HopSealTree;
/** One opening (5.10): a block's 8 residues and the siblings from its leaf up to the seal. */
export interface HopOpening {
    residues: bigint[];
    siblings: Uint8Array[];
}
/** The opening of block `block` from the seal's tree. */
export declare function openHopBlock(tree: HopSealTree, residues: WordList, block: number): HopOpening;
/**
 * Whether `siblings` carry `leaf`, at block position `position`, up to `seal`:
 * an even position is a left child and an odd one a right child, and the
 * position halves at each level up (5.10).
 */
export declare function verifyHopPath(leaf: Uint8Array, position: bigint, siblings: readonly Uint8Array[], seal: Uint8Array): boolean;
/** One re-roll attempt, with its parts. */
export interface HopAttempt {
    /** SHA256(GRIND_DOMAIN || previous_event_id || seal || be64(nonce)). */
    seed: Uint8Array;
    /** ((int(seed) mod 2^85) >> 12) << 12. */
    gBase: bigint;
    /** compute_subtree_cantor(g_base, 12) mod p_0. */
    rG: bigint;
    /** SHA256(GRIND_DOMAIN || seed || be64(r_g)). */
    G: Uint8Array;
}
/** One attempt (5.10) for `nonce` under a seal, its cost one aligned height-12 tree modulo p_0. */
export declare function hopAttempt(previousEventId: Uint8Array, seal: Uint8Array, nonce: bigint, p0: bigint, kernel?: WordKernel): HopAttempt;
export interface HopNonce {
    nonce: bigint;
    attempt: HopAttempt;
}
/**
 * The first nonce from `start` upward and below `end` whose G meets the price
 * A (G A < 2^256, 5.10), or null when that range holds none. Any such nonce
 * verifies, so a caller can split the search over workers by giving each a
 * disjoint range. The golden vectors take the first from 0.
 */
export declare function findHopNonce(previousEventId: Uint8Array, seal: Uint8Array, attempts: bigint, p0: bigint, kernel?: WordKernel, search?: NonceSearch): HopNonce | null;
/** The draw (5.10): idx_i = int(SHA256(SAMPLE_DOMAIN || G || be32(i))) mod m, for i in 0..15, collisions kept. */
export declare function hopSampleIndices(G: Uint8Array, m: bigint): bigint[];
/** The `proof` tag's value for a seal: 64 lowercase hex characters. */
export declare function encodeSeal(seal: Uint8Array): string;
/** The seal in a `proof` tag's value, or null unless it is exactly 64 lowercase hex characters. */
export declare function decodeSeal(hex: string): Uint8Array | null;
/** The `mn` tag's value: the nonce as exactly 16 lowercase hex characters, big-endian (8.4). */
export declare const encodeHopNonce: typeof encodeNonce;
/** The nonce in an `mn` tag's value, or null unless it is exactly 16 lowercase hex characters (8.4). */
export declare function decodeHopNonce(hex: string): bigint | null;
/**
 * The `mp` tag's value (8.4): the openings in draw order with no separators,
 * each its block's 8 residues as 16 hex characters then its siblings from the
 * leaf level up as 64 hex characters.
 */
export declare function encodeHopOpenings(openings: readonly HopOpening[]): string;
/**
 * The openings in an `mp` tag's value for a hop of Merkle depth `depth`, or
 * null when it is malformed (8.4): anything but exactly HOP_SAMPLES (128 + 64
 * depth) characters of 0-9 and a-f. No prefix, sign, separator, space or
 * uppercase letter is read past.
 */
export declare function decodeHopOpenings(mp: string, depth: number): HopOpening[] | null;
/**
 * The ids in the text of a list in the format of grandfathered-v1-hops.txt.
 * Throws on any line that is not empty, a comment or an entry, and on an id
 * listed twice, as the generator does.
 */
export declare function parseGrandfatheredList(text: string): Set<string>;
/** Whether an event is one of the version 1 hops exempt under spec 5.13, against `list` (the generated one by default). */
export declare function isGrandfatheredV1Hop(eventId: string | undefined, list?: ReadonlySet<string>): boolean;
/** The exact roots of a hop, in the backend's type. */
export interface HopRoots<N = bigint> {
    x: N;
    y: N;
    z: N;
    /** cantor_t, the temporal root. */
    t: N;
}
export interface HopResidueOptions<N = bigint> {
    kernel?: WordKernel;
    backend?: BigBackend<N>;
    /** Where the nonce search starts and ends; by default from 0, as in the golden vectors. */
    nonceSearch?: Omit<NonceSearch, 'onProgress'>;
    onProgress?: ProgressFn;
}
/** What the prover produces: the list it keeps, and the three tags it publishes. */
export interface HopResidueProof {
    /** p_0 to p_(m-1). */
    primes: WordList;
    /** r_j = hop_n mod p_j. */
    residues: WordList;
    seal: Uint8Array;
    nonce: bigint;
    /** The attempt whose nonce meets the price. */
    attempt: HopAttempt;
    indices: bigint[];
    openings: HopOpening[];
    tags: {
        proof: string;
        mn: string;
        mp: string;
    };
}
/**
 * Every residue r_j = hop_n mod p_j without hop_n (5.9), in the order the
 * reference's fast prover takes: the product tree once; the three axis roots
 * reduced modulo Q and paired modulo Q into region_n mod Q; one descent of the
 * remainder tree for it and one for the temporal root (a K = 0 root is t_base,
 * a word or two, reduced directly); then the temporal residues paired in,
 * modulo each prime. A still axis is a trivial tree whose root is its base,
 * so a single-axis hop takes the same path. Every big-number step goes
 * through `backend`; the roots stay the caller's, and the product tree and
 * the values modulo Q are released here (BigBackend.release).
 */
export declare function computeHopResidues<N>(primes: WordList, geometry: HopGeometry, roots: HopRoots<N>, kernel: WordKernel, backend: BigBackend<N>, onProgress?: ProgressFn): WordList;
/**
 * The residue extension of a hop (5.9, 5.10), given the roots the hop builds
 * anyway: derive the primes, compute every residue, seal, grind the nonce,
 * open the 16 drawn blocks. Bit for bit the reference's output.
 */
export declare function proveHopResidues<N = bigint>(previousEventId: Uint8Array, geometry: HopGeometry, roots: HopRoots<N>, options?: HopResidueOptions<N>): HopResidueProof;
export interface HopProofV2Options<N = bigint> extends HopResidueOptions<N> {
    /** The tallest axis tree to build; the temporal tree is capped at TEMPORAL_MAX_COMPUTE_HEIGHT as for version 1. */
    maxComputeHeight?: number;
}
/** A version 2 hop: the roots and region_n a client still uses for keys, and the three tags. Never hop_n. */
export interface HopProofV2 {
    cantorX: bigint;
    cantorY: bigint;
    cantorZ: bigint;
    /** pi(pi(cantor_x, cantor_y), cantor_z) (4.7), for the region keys of 7.2. */
    regionN: bigint;
    terrainK: number;
    temporalSeed: bigint;
    cantorT: bigint;
    geometry: HopGeometry;
    seal: Uint8Array;
    nonce: bigint;
    G: Uint8Array;
    indices: bigint[];
    /** The `proof`, `mn` and `mp` tag values (8.4). */
    tags: {
        proof: string;
        mn: string;
        mp: string;
    };
}
/**
 * Compute a full version 2 hop proof (5.9, 5.10): the three axis trees and the
 * temporal tree exactly as version 1 builds them, region_n from the axis roots
 * for the region keys, and the residue openings over hop_n, which is never
 * built (nor its hex). The nonce is the first meeting the price from 0 unless
 * options.nonceSearch says otherwise.
 */
export declare function computeHopProofV2<N = bigint>(x1: bigint, y1: bigint, z1: bigint, x2: bigint, y2: bigint, z2: bigint, plane: Plane, previousEventIdHex: string, options?: HopProofV2Options<N>): HopProofV2;
export interface HopClaim {
    /** The source, decoded from the `c` tag. */
    from: Xyz;
    /** The destination, decoded from the `C` tag; its plane bit enters K. */
    to: Xyz;
    /** The id in the `e` previous tag, 64 lowercase hex. */
    previousEventIdHex: string;
    /** The `proof` tag's value, or null (or undefined) when the event has none. */
    proof: string | null | undefined;
    /** The `mn` tag's value, or null (or undefined) when the event has none. */
    nonce: string | null | undefined;
    /** The `mp` tag's value, or null (or undefined) when the event has none. */
    openings: string | null | undefined;
    /**
     * The event's NIP-01 id, 64 lowercase hex, which decides whether a version 1
     * hop is exempt (5.13). Required, so that no caller can drop it by accident
     * and turn every listed hop into a rejected one.
     */
    eventId: string;
    /** The version 1 exemption list; GRANDFATHERED_V1_HOPS by default. */
    grandfathered?: ReadonlySet<string>;
}
export interface HopVerifyOptions {
    kernel?: WordKernel;
    /**
     * Which failure a rejected proof reports, when it fails at more than one
     * sample or at both checks of one sample. The verdict is the same either way.
     *
     * - `spec` (the default): the first failure in the order of 5.11 step 5,
     *   residue then path for each sample in ascending i, which is the
     *   `first_failure` of the spec's vectors. Every path is climbed first,
     *   because a climb costs microseconds and a residue milliseconds, and
     *   residues are computed only up to the first sample whose path fails, so
     *   a junk tree costs at most one residue.
     * - `cost`: a failing path rejects at once, before any residue is computed,
     *   so a junk tree costs one attempt and 16 climbs. The step reported can
     *   then be a path where `spec` would report that sample's residue.
     */
    order?: 'spec' | 'cost';
    /**
     * Check every sample and report every failure, residue and path, in spec
     * order, instead of stopping at the first. For diagnostics: it always costs
     * 16 residues.
     */
    allFailures?: boolean;
}
/**
 * Level 1 verification of a hop's proof (5.11, 8.7.1 steps 7 to 11): the
 * tags' form and width, one attempt and its price, the 16 indices from G, and
 * for each sample its path climbed to the seal and its residue recomputed in
 * word arithmetic. Never builds a root, region_n or hop_n. Returns what
 * failed, as `step` or `step:detail`: `event_id`, `previous_event_id`,
 * `form:proof`, `form:mn`, `form:mp` (every malformed tag is named),
 * `geometry`, `price`, `residue:i` and `path:i` for sample i. Past the form,
 * it stops at the first failure (see HopVerifyOptions for which one and for
 * reporting all). Empty means the proof is valid.
 *
 * A hop whose id is on the list is a version 1 hop exempt under 5.13: its
 * `proof` is accepted without steps 8 to 11, and only the form of the tags it
 * carries is checked (8.8). Any other hop must carry all three tags.
 * Everything else about a hop (links, sector tags, the count of its tags) is
 * the chain verifier's to check.
 */
export declare function verifyHopLevel1(claim: HopClaim, options?: HopVerifyOptions): string[];
export interface HopAuditOptions<N = bigint> {
    kernel?: WordKernel;
    backend?: BigBackend<N>;
    /** The tallest tree the audit builds. Default DEFAULT_MAX_COMPUTE_HEIGHT. */
    maxComputeHeight?: number;
}
/**
 * Level 2, the full audit (5.11), for tests and the census. A version 1 hop
 * (no `mn` and no `mp`) is audited as 5.13 audits a hop before listing it: its
 * proof_hash recomputed per 5.6 from its own coordinates and previous event
 * id and compared with `proof`. Any other hop is checked at Level 1, the list
 * ignored, and then every root rebuilt, every residue computed and the seal
 * rebuilt and compared with `proof` (`seal` when it differs). Costs what
 * making the hop costs.
 */
export declare function auditHopLevel2<N = bigint>(claim: HopClaim, options?: HopAuditOptions<N>): string[];
//# sourceMappingURL=residue.d.ts.map