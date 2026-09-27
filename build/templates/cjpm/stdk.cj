// FFI bindings for the libstd C ABI (stdk.h, STDK_ABI_EPOCH 7).
// Foreign declarations are package-private in Cangjie; the public wrappers
// below are the importable surface and encapsulate the unsafe calls.
package stdk

// Status codes (stdk.h STDK_STATUS_*).
public let STDK_ABI_EPOCH: UInt32 = 7
public let STDK_STATUS_OK: UInt32 = 0
public let STDK_STATUS_INVALID_CALL: UInt32 = 1
public let STDK_STATUS_UNSUPPORTED: UInt32 = 2
public let STDK_STATUS_INSUFFICIENT_CAPACITY: UInt32 = 3
public let STDK_STATUS_INVALID_DATA: UInt32 = 4
public let STDK_STATUS_INTEGRITY_FAILURE: UInt32 = 5
public let STDK_STATUS_IO_FAILURE: UInt32 = 6
public let STDK_STATUS_RESOURCE_LIMIT: UInt32 = 7
public let STDK_STATUS_INTERNAL_FAILURE: UInt32 = 8

// Fixed structure sizes (stdk.h STDK_SIZEOF_*).
public let STDK_SIZEOF_ID: UInt32 = 16
public let STDK_SIZEOF_NODE: UInt32 = 96
public let STDK_SIZEOF_CALL: UInt32 = 112

@C
public struct Id {
    var low: UInt64 = 0
    var high: UInt64 = 0
}

@C
public struct Node {
    var structure_size: UInt32 = 0
    var flags: UInt32 = 0
    var id: Id = Id()
    var value_low: UInt64 = 0
    var value_high: UInt64 = 0
    var bytes: CPointer<UInt8> = CPointer<UInt8>()
    var byte_capacity: UInt64 = 0
    var byte_length: UInt64 = 0
    var child: CPointer<Node> = CPointer<Node>()
    var next: CPointer<Node> = CPointer<Node>()
    var reserved: VArray<UInt64, $2> = [0, 0]
}

@C
public struct CallEnvelope {
    var structure_size: UInt32 = 0
    var flags: UInt32 = 0
    var operation: Id = Id()
    var request: CPointer<Node> = CPointer<Node>()
    var response: CPointer<Node> = CPointer<Node>()
    var diagnostic: CPointer<Node> = CPointer<Node>()
    var workspace: CPointer<UInt8> = CPointer<UInt8>()
    var workspace_capacity: UInt64 = 0
    // The header types this as stdk_callback (a function pointer). It stays
    // opaque here because hosts that wire callback resources build it from a
    // CFunc with an unsafe cast.
    var callback: CPointer<Unit> = CPointer<Unit>()
    var callback_context: CPointer<Unit> = CPointer<Unit>()
    var reserved: VArray<UInt64, $4> = [0, 0, 0, 0]
}

foreign func stdk_call(call: CPointer<CallEnvelope>): UInt32

foreign func stdk_session_storage(component: CString, verb: CString): UInt64

foreign func stdk_session_create(component: CString, verb: CString, storage: CPointer<UInt8>, storage_len: UInt64): UInt32

foreign func stdk_session_bounded(component: CString, verb: CString, storage: CPointer<UInt8>, storage_len: UInt64, max_encoded: UInt64, max_decoded: UInt64, max_work: UInt64, max_entries: UInt64): UInt32

foreign func stdk_session_step(session: CPointer<Unit>, input: CPointer<UInt8>, input_len: UInt64, output: CPointer<UInt8>, output_len: UInt64, end_of_input: Int32, counts_out: CPointer<UInt64>, state_out: CPointer<Int32>): UInt32

foreign func stdk_session_failure(session: CPointer<Unit>, status_out: CPointer<UInt32>, detail_out: CPointer<UInt64>): UInt32

foreign func stdk_session_catalog(): CString

foreign func stdk_session_destroy(session: CPointer<Unit>): UInt32

public func invoke(call: CPointer<CallEnvelope>): UInt32 {
    unsafe { stdk_call(call) }
}

// Session boundary: caller-owned storage, opaque handles, no allocator.
public func sessionStorage(component: CString, verb: CString): UInt64 {
    unsafe { stdk_session_storage(component, verb) }
}

public func sessionCreate(component: CString, verb: CString, storage: CPointer<UInt8>, storageLen: UInt64): UInt32 {
    unsafe { stdk_session_create(component, verb, storage, storageLen) }
}

public func sessionBounded(component: CString, verb: CString, storage: CPointer<UInt8>, storageLen: UInt64, maxEncoded: UInt64, maxDecoded: UInt64, maxWork: UInt64, maxEntries: UInt64): UInt32 {
    unsafe { stdk_session_bounded(component, verb, storage, storageLen, maxEncoded, maxDecoded, maxWork, maxEntries) }
}

public func sessionStep(session: CPointer<Unit>, input: CPointer<UInt8>, inputLen: UInt64, output: CPointer<UInt8>, outputLen: UInt64, endOfInput: Int32, countsOut: CPointer<UInt64>, stateOut: CPointer<Int32>): UInt32 {
    unsafe { stdk_session_step(session, input, inputLen, output, outputLen, endOfInput, countsOut, stateOut) }
}

public func sessionFailure(session: CPointer<Unit>, statusOut: CPointer<UInt32>, detailOut: CPointer<UInt64>): UInt32 {
    unsafe { stdk_session_failure(session, statusOut, detailOut) }
}

public func sessionDestroy(session: CPointer<Unit>): UInt32 {
    unsafe { stdk_session_destroy(session) }
}

// Versioned "v1:component/verb,..." list; the prefix is the retirement mechanism.
public func sessionCatalog(): String {
    unsafe { stdk_session_catalog().toString() }
}
