# cyberspace-core

TypeScript implementation of the [Cyberspace Protocol v2](https://github.com/arkin0x/cyberspace) core primitives.

Zero runtime dependencies. Runs identically in Node, browsers and web workers, which is what lets ONOSENDAI-V2 compute movement proofs off the main thread.

## What is here

| Module | Responsibility |
| --- | --- |
| `cantor.ts` | Cantor pairing, synchronous pure-JS SHA-256, byte/hex helpers |
| `coords.ts` | 256-bit interleaved coordinates (85-bit X/Y/Z + plane bit) |
| `movement.ts` | LCA height, Cantor subtree roots, spatial and 4D hop proofs |
| `terrain.ts` | Deterministic terrain-derived temporal height K, in [0, 16] |
| `sector.ts` | Sector partitioning (default 2^30 axis-units per side) |
| `location_encryption.ts` | Region key derivation from Cantor roots |
| `sidestep.ts` | Merkle sidesteps, version 3: seeded trees, the re-roll price and its `mn` nonce, openings, Level 1 verification |
| `grandfathered_v2_sidesteps.ts` | Generated: the version 2 sidesteps exempt under spec 6.16, by event id |
| `residue.ts` | Hop proof version 2, residue openings (spec 5.9 to 5.13): hop primes, residues of a root, the seal, the re-roll price and its `mn` nonce, the `mp` openings, `computeHopProofV2`, Level 1 and Level 2 verification; the JavaScript word kernel and the BigInt backend behind the `WordKernel` and `BigBackend` interfaces |
| `grandfathered_v1_hops.ts` | Generated: the version 1 hops exempt under spec 5.13, by event id (empty until the census) |

## Usage

```ts
import { computeHopProof, estimateHopCost } from 'cyberspace-core'

// Check the cost before paying it.
const cost = estimateHopCost(0n, 0n, 0n, 4104n, 0n, 0n, 0)
// => { lcaX: 13, terrainK: 11, maxHeight: 13, totalOps: 10238, exceedsLimit: false }

const proof = computeHopProof(0n, 0n, 0n, 4104n, 0n, 0n, 0, '0'.repeat(64))
// => proof.proofHash === 'ed9d09ca697b2da29c9d042207ac8ef7aab40f6dde550e6467452aa0e2e8cac6'
```

Movement cost is `O(2^h)` where `h` is the LCA height, so `computeHopProof` and
`computeSubtreeCantor` accept an optional progress callback. Use it from a
worker to stream live stats instead of freezing the UI.

## Cantor convention

`pi(a, b) = (a + b)(a + b + 1) / 2 + b`

The `+ b` term matters. The previous `test_vectors.js` asserted `pi(0,1) = 1`
and `pi(1,0) = 2`, which implies `+ a`. That was a transcription error that went
unnoticed because the file imported from `../src/*` while the sources lived at
the repo root, so the suite never ran. Two golden vectors independently settle
the convention as `+ b`:

- `pi(100, 101) = 20402` (`+ a` would give `20401`)
- `computeAxisCantor(0, 3) = 228` (`+ a` would give `172`)

Every proof hash in the suite depends on this.

## Provenance

Ported from the CommonJS `cyberspace-cli-js` sources, which were themselves
ported from the Python `cyberspace-cli`. The golden vectors in
`test/vectors.test.ts` are the cross-implementation contract: they must produce
byte-identical results to the Python implementation.

## Development

```sh
npm install
npm test        # golden vectors
npm run typecheck
npm run build   # emits dist/ with declarations
```

Three files are generated from the spec repository, read at a git ref (never the
working tree) with the commit recorded. Fetch the clone first; both default to
`../cyberspace` at `origin/master`.

```sh
# The exempt version 2 sidestep ids (spec 6.16) and version 1 hop ids (spec 5.13), when a list grows.
npm run grandfathered -- [path to cyberspace clone] [ref]

# The sidestep golden vectors, from sidestep-reference.py.
python3 scripts/sidestep-vectors.py [path to cyberspace clone] [ref] > test/fixtures/sidestep_v3.json
```
