/**
 * avatarMine.ts - mining an avatar's work with the nonce at the end of the content.
 *
 * Spec 8.10 counts the work on the event id and reads only the committed
 * target, so a miner may vary the nonce anywhere in the event. The id is the
 * SHA-256 of the serialized event, SHA-256 reads its input front to back in
 * 64-byte blocks, and the content is the last field serialized. So this
 * miner writes the nonce as a trailing `nonce` field of the payload, hashes
 * everything before it once (the midstate), and per try hashes only the last
 * block: one compression, whatever the avatar's size. A 98 KB avatar mined
 * with the nonce in the tags hashes about 1,500 blocks per try instead.
 *
 * When the last partial block before the nonce leaves too little room for
 * up to 16 digits, the end of the serialization and the padding, the nonce
 * is led with zeros up to the next block boundary (still a string of
 * decimal digits), so every try is exactly one compression. The nonce tag
 * carries "0" as its first value and the committed target as its second.
 *
 * This is the same miner as the spec's avatar-reference.py (mine_tail): for
 * the same template, target and first nonce it finds the same nonce, and the
 * spec's avatar-vectors.json pins that. Pure JavaScript, no allocation in
 * the hot loop, int32 words throughout, so it runs the same in node, in a
 * browser and in a phone's Web Worker (about two million tries a second on
 * one desktop core).
 */
/** The fields of an event that its id covers, besides the id itself. */
export interface AvatarMineTemplate {
    pubkey: string;
    created_at: number;
    kind: number;
    tags: string[][];
    content: string;
}
/** A find: the whole nonce field (zeros it was led with included) and the id it gives. */
export interface AvatarMineFound {
    nonce: string;
    id: string;
}
/** Digits a try's nonce may have; the last block keeps room for them. */
export declare const AVATAR_NONCE_DIGITS_MAX = 16;
/**
 * The most bytes mining adds to a content that holds no nonce yet:
 * `,"nonce":"` and `"` (11), the zeros that lead the digits (fewer than
 * 64 - (64 - AVATAR_NONCE_DIGITS_MAX - POST_BYTES - 9), so at most 29) and
 * AVATAR_NONCE_DIGITS_MAX digits: 56. A content within AVATAR_CONTENT_MAX
 * less this always fits the limit once mined; avatarTailSplit refuses one
 * that would not.
 */
export declare const AVATAR_NONCE_ROOM: number;
/**
 * The content with `nonce` as the last field of its payload. A nonce this
 * miner wrote before (the content ends with it) is cut off as text, so the
 * rest stays byte for byte; any other `nonce` field is dropped by writing
 * the payload again. Throws when the content is not a JSON object.
 */
export declare function avatarTailContent(content: string, nonce: string): string;
/**
 * The event to sign once `nonce` is found: the content with the nonce at
 * its end and the nonce tag committing to `target`. Its id is the find's.
 */
export declare function avatarTailEvent<T extends AvatarMineTemplate>(template: T, nonce: string, target: number): T;
/**
 * The serialized event cut around the nonce: every try hashes
 * pre + lead + digits + post. `lead` is the zeros that move the digits to
 * a block boundary when the last partial block of `pre` lacks room.
 */
export interface AvatarTailSplit {
    pre: Uint8Array;
    post: Uint8Array;
    lead: string;
}
export declare function avatarTailSplit(template: AvatarMineTemplate, target: number): AvatarTailSplit;
/** The most leading zero bits this miner can aim for (it reads two words of the hash). */
export declare const AVATAR_MINE_MAX_TARGET = 64;
/**
 * The midstate miner over one split. Nonces are tried in order from
 * `start`: start, start + 1, ... as decimal digits, each led by the split's
 * `lead`. Give each worker its own `start` far from the others' (worker i
 * of n at i * 10^12, say); 16 digits are room for 10^16 nonces.
 */
export declare class AvatarTailMiner {
    /** Nonces tried so far. */
    tries: number;
    private readonly mid;
    private readonly W;
    private readonly s;
    private readonly buf;
    private readonly remLen;
    private readonly hashed;
    private readonly post;
    private readonly lead;
    private readonly digits;
    constructor(split: AvatarTailSplit, start?: number);
    /** Try up to `count` nonces; the first whose id carries `target` leading zero bits, or null. */
    run(count: number, target: number): AvatarMineFound | null;
}
/**
 * Mine `template` to `target` bits on this thread, from nonce `start`, at
 * most `limit` tries; the event to sign (avatarTailEvent) and the find, or
 * null when the limit runs out. For tests and small targets: a client mines
 * in workers, each with its own AvatarTailMiner and start.
 */
export declare function mineAvatarTail<T extends AvatarMineTemplate>(template: T, target: number, start?: number, limit?: number): {
    event: T;
    found: AvatarMineFound;
    tries: number;
} | null;
//# sourceMappingURL=avatarMine.d.ts.map