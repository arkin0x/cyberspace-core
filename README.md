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
| `residue.ts` | Hop proof version 2, residue openings (spec 5.9 to 5.13): hop primes, residues of a root, the seal, the re-roll price and its `mn` nonce, the `mp` openings, `computeHopProofV2`, Level 1 and Level 2 verification; the JavaScript and WASM word kernels and the BigInt backend behind the `WordKernel` and `BigBackend` interfaces, and `selectWordKernel` |
| `residue/kern.ts` | AssemblyScript source of the WASM word kernel; `residue/kernWasm.ts` is its compiled module as base64 (generated), `residue/kern.sha256` the hashes of both |
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

Residue openings (hop proof version 2) take a word kernel. By default every
function uses `selectWordKernel()`: the WASM kernel wherever WebAssembly can be
instantiated, the JavaScript kernel otherwise (for example with WebAssembly
disabled). Both give identical values. Pass `kernel: JS_WORD_KERNEL` or
`kernel: WASM_WORD_KERNEL` to choose, and on a page that wants WASM even where a
synchronous compile is refused, `await loadWasmWordKernel()` once at start. The
module is embedded in the package; nothing is fetched.

### Injecting a big-number backend

Every big-number step of a hop goes through a `BigBackend`: the Cantor trees,
the exact pairings for `region_n`, the product tree of the primes, the region
pairings modulo Q and the remainder trees. `BIGINT_BACKEND` (native BigInt) is
the default and the only backend core ships. To use another, pass it as
`backend` to `computeHopProofV2`, `proveHopResidues`, `computeHopResidues` or
`auditHopLevel2`:

```ts
import { computeHopProofV2, type BigBackend } from 'cyberspace-core'

const gmp: BigBackend<number> = await loadMyGmpAdapter() // your code, not core's
const proof = computeHopProofV2(x1, y1, z1, x2, y2, z2, plane, previousEventIdHex, { backend: gmp })
```

A backend MUST return exactly what `BIGINT_BACKEND` returns, and then the tags
are byte for byte the same. Its values are its own type, and core passes them
back only to the same backend. A backend whose values live outside the
JavaScript heap (GMP's `mpz_t` in WebAssembly memory) also implements `release`
and `releaseTree`. Core calls them once for every value and tree it made
through the backend, even when it throws, and never for roots the caller
passed in. `test/support/gmpBackend.ts` is a working adapter over `gmp-wasm`.
The residue suite runs every vector through it with both word kernels. Copy it
into your project; do not import it. The exported kernels and
`BIGINT_BACKEND` are frozen.

GMP is not bundled, for three reasons:

- **License.** `gmp-wasm` is LGPL-3.0 and core is MIT. Bundling it would put
  the LGPL's obligations on every consumer, including the ones that never use
  it.
- **Size.** It is 242 KB (157 KB gzipped), against core's 14 KB word kernel. It
  saves about a fifth of a hop at browser heights: 18% on a residue hop at h20
  in the research, and more where BigInt is slow (Android). So a consumer loads
  it lazily, and only for tall hops. ONOSENDAI does this from h17.
- **Memory ceiling.** GMP runs in a single 32-bit WebAssembly memory (2 to 4 GB).
  In the research it aborted on a version 1 hop at h22 and on the product tree
  at h24. A consumer that loads it chooses its own fallback.

`gmp-wasm` is a devDependency, pinned exactly, and used only by that test. The
published package does not contain it and does not install it.

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

Consumers install this package from git at a pinned commit. Bump `version` in
`package.json` (and the two matching lines in `package-lock.json`) in every
change a consumer can see. npm compares a git dependency by version before
anything else, and git dependencies carry no integrity hash. When a consumer's
`node_modules` is restored from a build cache (Vercel does this) and npm's hidden
lockfile is stale, npm fills the installed copy's metadata in from the
consumer's lockfile. A repin to a new commit with the same version then
reports `up to date` and keeps the old code.

Three files are generated from the spec repository, read at a git ref (never the
working tree) with the commit recorded. Fetch the clone first; both default to
`../cyberspace` at `origin/master`.

```sh
# The exempt version 2 sidestep ids (spec 6.16) and version 1 hop ids (spec 5.13), when a list grows.
npm run grandfathered -- [path to cyberspace clone] [ref]

# The sidestep golden vectors, from sidestep-reference.py.
python3 scripts/sidestep-vectors.py [path to cyberspace clone] [ref] > test/fixtures/sidestep_v3.json
```

The WASM word kernel is built from `src/residue/kern.ts` with AssemblyScript
(a devDependency pinned to one exact version) and committed, so installing from
git needs only `tsc`. After editing `kern.ts`:

```sh
npm run build:kernel             # rewrites src/residue/kernWasm.ts and src/residue/kern.sha256
npm run build:kernel -- --check  # rebuilds in memory; exits 1 unless the committed files match
```
