/**
 * cantor.ts — Cantor pairing and hashing primitives.
 *
 * All integers here are bigint since Cyberspace coordinates exceed 2^53.
 * SHA-256 is a pure-JS synchronous implementation so that this module has zero
 * runtime dependencies and works identically in Node, browsers and workers.
 * (Web Crypto's digest() is async, which would poison every call site.)
 */
/**
 * Cantor pairing function: (a, b) -> N
 */
export declare function cantorPair(a: bigint, b: bigint): bigint;
/**
 * Convert a non-negative bigint to minimal big-endian bytes.
 *
 * The values this runs on are not small. A hop proof at LCA height 18 ends
 * with a 21 MB integer, so this loop runs 22 million times, and the obvious
 * `parseInt(hex.substring(i * 2, i * 2 + 2), 16)` allocates a two-character
 * string and runs a general-purpose number parser on every one of them: 750 ms
 * of the six seconds that hop takes. Reading the two code points and looking
 * their nibbles up in a table is the same answer 3.7 times faster, and it
 * allocates nothing.
 *
 * toString(16) stays because hex is a power of two, so V8 reinterprets the
 * digits rather than dividing, which makes it linear and cheap.
 */
export declare function intToBytesBE(n: bigint): Uint8Array;
export declare function bytesToHex(bytes: Uint8Array): string;
export declare function hexToBytes(hex: string): Uint8Array;
/**
 * Synchronous SHA-256. Returns 32 bytes.
 */
export declare function sha256(data: Uint8Array): Uint8Array;
/**
 * The compression state after exactly one 64-byte block, to hash many
 * messages that share that block as their prefix (spec 6.5, the midstate
 * optimization): resume from it with sha256FromMidstate for each tail.
 */
export declare function sha256Midstate(block: Uint8Array): Uint32Array;
/**
 * SHA-256 of (the 64-byte block behind `midstate` || tail), for a tail of at
 * most 55 bytes so that one more compression finishes the hash.
 */
export declare function sha256FromMidstate(midstate: Uint32Array, tail: Uint8Array): Uint8Array;
export declare function sha256Hex(data: Uint8Array): string;
/**
 * SHA-256 of a bigint's minimal big-endian representation, as hex.
 */
export declare function sha256IntHex(n: bigint): string;
//# sourceMappingURL=cantor.d.ts.map