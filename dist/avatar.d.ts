/**
 * avatar.ts - what a reader checks on an avatar (kind 11333, spec 8.10).
 *
 * An avatar carries no proof of work (owner ruling 2026-11-16). A reader
 * draws it when its content is within AVATAR_CONTENT_MAX bytes of UTF-8 and
 * holds a payload the reader can read, and draws its default avatar for that
 * identity otherwise. A `nonce` tag, which avatars published before 2026-11
 * carry, is ignored: no verdict reads a tag. Relays limit how often one key
 * replaces its avatar; viewers mute.
 *
 * Until 2026-11 an avatar paid NIP-13 work priced by its reach and detail
 * (16 bits, 2 per doubling of reach, 3 per doubling of vertices plus faces
 * beyond 32). A miner that varies the end of the content hashes one SHA-256
 * block per try at any size, which made that price meaningless, so it was
 * dropped. avatarWork and the price constants are gone; verifyAvatarWork
 * stays one release as a deprecated alias of verifyAvatar that never
 * checks work.
 */
/**
 * The most bytes an avatar's content may hold, counted as UTF-8 (128 KiB).
 * A reader draws the default avatar for a larger one.
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
/** The parts of a shard payload a reader checks here and reach reads. */
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
/** The content's length as the limit counts it: UTF-8 bytes (a lone surrogate counts three). */
export declare function avatarContentBytes(content: string): number;
/** Leading zero bits of a hex string, as NIP-13 counts them. */
export declare function leadingZeroBits(hex: string): number;
/** Why a reader draws an avatar event, or draws the default instead. */
export interface AvatarCheck {
    ok: boolean;
    reason: 'ok' | 'not-an-avatar' | 'too-large';
}
/**
 * Whether a reader draws this avatar event (spec 8.10): the kind is 11333,
 * the content is within AVATAR_CONTENT_MAX (checked before parsing) and it
 * holds a payload the reader can read (avatarReadable). Tags are not read.
 * Empty content is the default avatar, the caller's to handle first; here it
 * is not-an-avatar, as any content that is not a payload is.
 */
export declare function verifyAvatar(event: {
    kind: number;
    content: string;
}): AvatarCheck;
/** The old verdict's shape, kept for verifyAvatarWork. */
export interface AvatarVerdict {
    ok: boolean;
    /** Always 0: an avatar owes no work. */
    required: number;
    /** What a nonce tag commits to, if one is there; never read for the verdict. */
    committed: number | null;
    /** Leading zero bits of the id; never read for the verdict. */
    zeros: number;
    reason: AvatarCheck['reason'];
}
/**
 * @deprecated An avatar carries no proof of work (spec 8.10, 2026-11-16).
 * Use verifyAvatar. This alias reaches verifyAvatar's verdict and never
 * checks work; it reports the nonce tag and the id's zeros for display only.
 */
export declare function verifyAvatarWork(event: {
    kind: number;
    id: string;
    tags: string[][];
    content: string;
}): AvatarVerdict;
//# sourceMappingURL=avatar.d.ts.map