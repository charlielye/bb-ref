/**
 * Reassembles length-prefixed frames (`u32 len | len bytes`) from stream
 * chunks. Chunks are queued as they arrive and each frame is copied out once
 * it is complete, so a large frame costs one copy rather than one per chunk,
 * and memory grows only with the bytes the peer has actually sent.
 */
export declare class FrameReader {
    private chunks;
    private buffered;
    push(chunk: Buffer): void;
    /** The next frame's length prefix, once its 4 bytes have arrived. */
    peekLength(): number | undefined;
    /** The next whole frame, length prefix included, once it has fully arrived. */
    next(): Buffer | undefined;
    private copyOut;
    private consume;
}
