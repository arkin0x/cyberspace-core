/**
 * avatar.ts - the work an avatar owes (kind 11333).
 *
 * An avatar is drawn on every screen near its owner whether they like it or
 * not, so its size and its detail are paid for in proof of work on the event
 * itself, NIP-13 style: the event id must carry `required` leading zero bits,
 * with the target committed in a `nonce` tag. Any viewer verifies with one
 * hash and a walk over the vertices, and draws the dodecahedron instead for
 * an avatar that has not paid.
 *
 *   required = ceil(10 + 2 log2(reach) + 1.5 log2(detail / 32))
 *
 * reach is the farthest vertex from the build origin in gibsons at true
 * scale (a model unit is 2^unit gibsons), never below one; detail is the
 * vertex count plus the face count, never below 32. The terms are summed as
 * real numbers and the total is rounded up once. Reach is priced hardest
 * because a large avatar is the one that gets in everyone's way. Bytes are
 * not priced by the work (a miner that varies the end of the content pays
 * the same per try at any size, avatarMine.ts); the content limit bounds
 * them instead. The floor is no spam guard: a relay limits how often one
 * key replaces its avatar.
 *
 * Until 2026-11 the floor was 16 bits and detail 3 bits per doubling, set
 * while SNO still capped an object at 512 vertices and 1,024 faces. No
 * shape costs more now than it did then, so every avatar published before
 * the change stays paid.
 */
/** Bits every avatar owes, whatever its shape. */
export declare const AVATAR_FLOOR_BITS = 10;
/** Bits per doubling of reach. */
export declare const AVATAR_SIZE_BITS = 2;
/** Bits per doubling of vertices plus faces beyond DETAIL_FREE (three per fourfold). */
export declare const AVATAR_DETAIL_BITS = 1.5;
/** Vertices plus faces that cost nothing. */
export declare const AVATAR_DETAIL_FREE = 32;
/**
 * The most bytes an avatar's content may hold, counted as UTF-8 (128 KiB),
 * a trailing `nonce` field included. A reader draws the default avatar for
 * a larger one, whatever work it carries.
 */
export declare const AVATAR_CONTENT_MAX = 131072;
/**
 * Above this many bytes of content a publishing client warns that some
 * remote signers (NIP-46) may refuse the event: older NIP-44 libraries
 * encrypt at most 65,535 bytes, and the request carries the whole event
 * with its content escaped again, so such a signer fails near 65,200
 * bytes of content. Spec 8.10, non-normative.
 */
export declare const AVATAR_CONTENT_WARN = 64000;
/**
 * Replaceable: one avatar per pubkey, the newest wins, no `d` tag.
 *
 * This was 33331, addressable with a `d` fixed at "avatar", which is
 * emulating replaceable semantics with the wrong tool: a constant `d` asks
 * every reader to trust a convention where the relay could enforce the rule.
 * Spec 8.10. The break was clean because nothing was published: a query for
 * 33331 across four relays returned nothing while the same query returned
 * bags and movement events. 33331 now belongs to a standalone SNO object
 * (DECK-0004), where a `d` the author chooses is a real key.
 */
export declare const AVATAR_KIND = 11333;
/** What the price reads from a shard payload: the parts of it that matter. */
export interface AvatarPayload {
    /** A model unit is 2^unit gibsons. */
    unit?: number;
    /** Whole units per vertex. */
    vertices: number[][];
    /** Ticks per vertex, as the payload packs them: a triple, or -N for N zero triples. */
    ticks?: Array<number[] | number>;
    faces?: unknown[];
}
/**
 * The ticks column unpacked to one triple per vertex. Stops at `count`
 * triples, so a run of a billion zero triples costs nothing.
 */
export declare function unpackTicks(packed: Array<number[] | number> | undefined, count: number): number[][];
/** The farthest any vertex reaches from the build origin, in gibsons at true scale. */
export declare function avatarReach(payload: AvatarPayload): number;
/**
 * Whether the work can be read from a payload at all (spec 8.10: content a
 * client cannot read is not an avatar). `vertices` is a list of lists whose
 * first three entries, where present, are numbers; `ticks`, where present,
 * holds runs (whole numbers, zero or below) and such lists; `faces`, where
 * present, is a list. Without this a coordinate that is not a number would
 * price the avatar at NaN, which passes every comparison.
 */
export declare function avatarReadable(payload: unknown): payload is AvatarPayload;
/** Vertices plus faces, before the free allowance. */
export declare function avatarDetail(payload: AvatarPayload): number;
/**
 * The bits owed for a reach in gibsons and a detail (vertices plus faces):
 * the floor, two bits per doubling of reach beyond one gibson, one and a
 * half per doubling of detail beyond 32, summed and rounded up once.
 */
export declare function avatarBits(reach: number, detail: number): number;
/** The leading zero bits the avatar's event id must carry. */
export declare function avatarWork(payload: AvatarPayload): number;
/** The content's length as the limit counts it: UTF-8 bytes (a lone surrogate counts three). */
export declare function avatarContentBytes(content: string): number;
/** Leading zero bits of a hex string, as NIP-13 counts them. */
export declare function leadingZeroBits(hex: string): number;
export interface AvatarVerdict {
    ok: boolean;
    /** What the shape owes. */
    required: number;
    /** What the nonce tag commits to; null without a well-formed tag. */
    committed: number | null;
    /** What the id actually carries. */
    zeros: number;
    reason: 'ok' | 'not-an-avatar' | 'too-large' | 'no-nonce' | 'under-committed' | 'unpaid';
}
/**
 * Whether an avatar event has paid for its shape (NIP-13): the content is
 * within AVATAR_CONTENT_MAX, the nonce tag's committed target covers what
 * the shape owes, and the id carries at least the committed zeros.
 * Committing matters: a lucky id must not be claimed against a lower bar
 * than it was mined for. The length is checked before the content is
 * parsed. Only the committed target is read from the nonce tag, never its
 * first value: a miner may vary the nonce anywhere (avatarMine.ts puts it
 * at the end of the content and writes "0" in the tag).
 */
export declare function verifyAvatarWork(event: {
    kind: number;
    id: string;
    tags: string[][];
    content: string;
}): AvatarVerdict;
//# sourceMappingURL=avatar.d.ts.map