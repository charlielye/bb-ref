/** Request ids stay below 2^30 so V8 keeps them as small integers (no heap allocation per call). */
export declare const REQUEST_ID_SPACE: number;
/** A call awaiting its response. */
export interface PendingCall {
    requestId: number;
    resolve: (data: Uint8Array) => void;
    reject: (error: unknown) => void;
}
/**
 * In-flight calls in issue order, paired to responses by request id. Servers
 * that answer in order (e.g. a serial `run()` loop) always match the head, so
 * the common path is a shift and an integer compare; out-of-order responses
 * fall back to a search. Ids start at a random point so a stale frame from a
 * previous occupant of the channel is unlikely to pair with a live call.
 */
export declare class PendingQueue {
    private calls;
    private nextRequestId;
    get length(): number;
    /** Enqueues a call under a fresh request id and returns the id. */
    push(resolve: PendingCall["resolve"], reject: PendingCall["reject"]): number;
    /** Removes the most recently pushed call (to unwind a failed send). */
    pop(): PendingCall | undefined;
    /** Removes and returns the call for `requestId`, or undefined if none is pending. */
    take(requestId: number): PendingCall | undefined;
    /** Removes and returns every pending call. */
    drain(): PendingCall[];
}
