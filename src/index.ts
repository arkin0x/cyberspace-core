/**
 * cyberspace-core — TypeScript port of the cyberspace CLI core.
 *
 * Consensus-critical primitives for the Cyberspace Protocol v2:
 * - Cantor pairing and SHA-256 hashing
 * - 256-bit interleaved coordinate system
 * - Movement proofs (spatial and 4D temporal), hop residue openings and Merkle sidesteps
 * - Terrain-derived temporal height K
 * - Sector partitioning
 * - Location-based encryption key derivation
 *
 * Zero runtime dependencies. Works in Node, browsers and web workers.
 */

export * from './cantor.js'
export * from './coords.js'
export * from './movement.js'
export * from './terrain.js'
export * from './sector.js'
export * from './sidestep.js'
export * from './grandfathered_v2_sidesteps.js'
export * from './residue.js'
export * from './grandfathered_v1_hops.js'
export * from './location_encryption.js'
export * from './avatar.js'
