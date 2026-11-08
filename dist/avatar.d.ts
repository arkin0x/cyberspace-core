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
 *   required = ceil(FLOOR + SIZE_BITS * log2(reach) + DETAIL_BITS * log2(detail / 32))
 *
 * reach is the farthest vertex from the build origin in gibsons at true
 * scale (a model unit is 2^unit gibsons), never below one; detail is the
 * vertex count plus the face count, never below 32. The floor is planned on
 * a hundred-year horizon of growing hash power; reach is priced hardest
 * because a large avatar is the one that gets in everyone's way. Bytes are
 * charged as well without a term, since every nonce hashes the whole event.
 */
/** Bits every avatar owes, whatever its shape. */
export declare const AVATAR_FLOOR_BITS = 16;
/** Bits per doubling of reach. */
export declare const AVATAR_SIZE_BITS = 2;
/** Bits per doubling of vertices plus faces beyond DETAIL_FREE. */
export declare const AVATAR_DETAIL_BITS = 3;
/** Vertices plus faces that cost nothing. */
export declare const AVATAR_DETAIL_FREE = 32;
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
/** The ticks column unpacked to one triple per vertex. */
export declare function unpackTicks(packed: Array<number[] | number> | undefined, count: number): number[][];
/** The farthest any vertex reaches from the build origin, in gibsons at true scale. */
export declare function avatarReach(payload: AvatarPayload): number;
/** The leading zero bits the avatar's event id must carry. */
export declare function avatarWork(payload: AvatarPayload): number;
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
    reason: 'ok' | 'not-an-avatar' | 'no-nonce' | 'under-committed' | 'unpaid';
}
/**
 * Whether an avatar event has paid for its shape (NIP-13): the nonce tag's
 * committed target covers what the shape owes, and the id carries at least
 * the committed zeros. Committing matters: a lucky id must not be claimed
 * against a lower bar than it was mined for.
 */
export declare function verifyAvatarWork(event: {
    kind: number;
    id: string;
    tags: string[][];
    content: string;
}): AvatarVerdict;
//# sourceMappingURL=avatar.d.ts.map