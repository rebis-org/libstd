// Safe wrapper over the session boundary. The raw FFI stays in stdk.cj, and
// this file adds handle ownership, storage lifecycle, and status-to-exception
// mapping so hosts never touch raw pointers or error codes.
package stdk

// Exception surface for the session boundary. Every non-OK status maps here.
public class StdKException <: Exception {
    public let status: UInt32

    public init(message: String, status: UInt32) {
        super(message)
        this.status = status
    }

    protected override func getClassName(): String {
        return "StdKException"
    }
}

public struct StepResult {
    public let consumed: UInt64
    public let produced: UInt64
    public let finished: Bool

    public init(consumed: UInt64, produced: UInt64, finished: Bool) {
        this.consumed = consumed
        this.produced = produced
        this.finished = finished
    }
}

// Session over the C boundary. The ABI requires caller-owned storage, so the
// wrapper owns the allocation and releases it on close. Close is idempotent.
public class Session <: Resource {
    private let storage: CPointer<UInt8>
    private let storageLen: UInt64
    private var handle: CPointer<Unit>
    private var closed = false

    private init(storage: CPointer<UInt8>, storageLen: UInt64, handle: CPointer<Unit>) {
        this.storage = storage
        this.storageLen = storageLen
        this.handle = handle
    }

    // Opens an unbounded session for a published pair from stdk_session_catalog.
    public static func open(component: String, verb: String): Session {
        return openBounded(component, verb, UInt64.Max, UInt64.Max, UInt64.Max, UInt64.Max)
    }

    /**
     * Opens a session with per-session ceilings on encoded, decoded, work, and
     * entry bytes for untrusted input.
     *
     * @throws StdKException when the pair is unknown or creation fails.
     */
    // The ceiling list is fixed by the C ABI boundary, so the style rule that
    // caps parameter lists does not apply here.
    // cjlint-ignore -start !G.FUN.01
    public static func openBounded(component: String, verb: String, maxEncoded: UInt64, maxDecoded: UInt64,
        maxWork: UInt64, maxEntries: UInt64): Session {
        let componentC = unsafe { LibC.mallocCString(component) }
        let verbC = unsafe { LibC.mallocCString(verb) }
        try {
            let storageLen = sessionStorage(componentC, verbC)
            if (storageLen == 0) {
                throw StdKException("Unknown session pair: ${component}/${verb}.", STDK_STATUS_INVALID_CALL)
            }
            let storage = unsafe { LibC.malloc<UInt8>(count: Int64(storageLen)) }
            if (storage.isNull()) {
                throw StdKException("Failed to allocate ${storageLen} bytes of session storage.",
                    STDK_STATUS_INTERNAL_FAILURE)
            }
            let created = sessionBounded(componentC, verbC, storage, storageLen, maxEncoded, maxDecoded, maxWork,
                maxEntries)
            if (created != STDK_STATUS_OK) {
                unsafe { LibC.free(storage) }
                throw StdKException("stdk_session_create failed with status ${created}.", created)
            }
            // The handle is the storage pointer per the ABI, so the pointer pun is required.
            return Session(storage, storageLen, unsafe { CPointer<Unit>(storage) }) // cjlint-ignore !FFI.C.7
        } finally {
            unsafe {
                LibC.free(componentC)
                LibC.free(verbC)
            }
        }
        // cjlint-ignore -end
    }

    /**
     * One pump over the given spans.
     *
     * @throws StdKException with the status and the driver detail when the step fails.
     */
    public func step(input: Array<UInt8>, output: Array<UInt8>, endOfInput!: Bool = false): StepResult {
        if (closed) {
            throw StdKException("Session is closed.", STDK_STATUS_INVALID_CALL)
        }
        let counts = unsafe { LibC.malloc<UInt64>(count: 2) }
        // The native step writes state through the pointer, so it stays a var.
        var state: Int32 = 0 // cjlint-ignore !G.VAR.01
        let rc = unsafe {
            let inputPtr = if (input.size == 0) {
                CPointer<UInt8>()
            } else {
                acquireArrayRawData(input).pointer
            }
            let outputPtr = if (output.size == 0) {
                CPointer<UInt8>()
            } else {
                acquireArrayRawData(output).pointer
            }
            stdk_session_step(handle, inputPtr, UInt64(input.size), outputPtr, UInt64(output.size),
                if (endOfInput) {
                    1
                } else {
                    0
                }, counts, inout state)
        }
        let consumed = unsafe { counts.read() }
        let produced = unsafe { (counts + 1).read() }
        let result = StepResult(consumed, produced, state == 1)
        unsafe { LibC.free(counts) }
        if (rc != STDK_STATUS_OK) {
            // The native failure readback writes both slots through the pointers.
            var detailStatus: UInt32 = 0 // cjlint-ignore !G.VAR.01 !G.VAR.02
            var detail: UInt64 = 0 // cjlint-ignore !G.VAR.01 !G.VAR.02
            let readback = unsafe { stdk_session_failure(handle, inout detailStatus, inout detail) }
            if (readback == STDK_STATUS_OK) {
                throw StdKException("Session step failed with status ${detailStatus}, detail ${detail}.", detailStatus)
            }
            throw StdKException("Session step failed with status ${rc}.", rc)
        }
        return result
    }

    public func close(): Unit {
        if (!closed) {
            unsafe {
                stdk_session_destroy(handle)
                LibC.free(storage)
            }
            closed = true
        }
    }

    public func isClosed(): Bool {
        return closed
    }
}
