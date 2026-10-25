package dev.stdk;

/**
 * Raw JNI bindings for the libstd C session boundary. Every entry point validates arguments before
 * touching native memory.
 */
public final class StdK {
    public static final int ABI_EPOCH = 8;
    public static final int OK = 0;
    public static final int INVALID_CALL = 1;
    public static final int UNSUPPORTED = 2;
    public static final int INSUFFICIENT_CAPACITY = 3;
    public static final int INVALID_DATA = 4;
    public static final int INTEGRITY_FAILURE = 5;
    public static final int IO_FAILURE = 6;
    public static final int RESOURCE_LIMIT = 7;
    public static final int INTERNAL_FAILURE = 8;

    // JNI is the point of this class, so the restricted loadLibrary warning is expected.
    @SuppressWarnings("restricted")
    static void loadNative() {
        System.loadLibrary("std");
    }

    static {
        loadNative();
    }

    private StdK() {}

    public static native long sessionStorage(String component, String verb);

    public static native long sessionCreate(
            String component,
            String verb,
            long maxEncoded,
            long maxDecoded,
            long maxWork,
            long maxEntries);

    /**
     * Runs one step. {@code counts} holds consumed, produced, and state (0 open, 1 done, -1
     * failed); lengths stay within their arrays.
     */
    public static int sessionStep(
            long session,
            byte[] input,
            int inputLen,
            byte[] output,
            int outputLen,
            boolean endOfInput,
            long[] counts) {
        requireHandle(session, "session");
        if (inputLen < 0
                || (input == null && inputLen != 0)
                || (input != null && inputLen > input.length)) {
            throw new IllegalArgumentException("inputLen out of range");
        }
        if (outputLen < 0
                || (output == null && outputLen != 0)
                || (output != null && outputLen > output.length)) {
            throw new IllegalArgumentException("outputLen out of range");
        }
        if (counts == null || counts.length < 3) {
            throw new IllegalArgumentException("counts must hold 3 elements");
        }
        return nativeSessionStep(session, input, inputLen, output, outputLen, endOfInput, counts);
    }

    private static native int nativeSessionStep(
            long session,
            byte[] input,
            int inputLen,
            byte[] output,
            int outputLen,
            boolean endOfInput,
            long[] counts);

    public static int sessionFailure(long session, long[] statusAndDetail) {
        requireHandle(session, "session");
        if (statusAndDetail == null || statusAndDetail.length < 2) {
            throw new IllegalArgumentException("statusAndDetail must hold 2 elements");
        }
        return nativeSessionFailure(session, statusAndDetail);
    }

    private static native int nativeSessionFailure(long session, long[] statusAndDetail);

    /**
     * Destroys a live session. Pair each non-zero handle with exactly one destroy, then release
     * storage with {@link #sessionFree}.
     */
    public static int sessionDestroy(long session) {
        requireHandle(session, "session");
        return nativeSessionDestroy(session);
    }

    private static native int nativeSessionDestroy(long session);

    /**
     * Releases storage previously returned by {@link #sessionCreate}. Passing any pointer not
     * returned by sessionCreate, or double-freeing, corrupts the heap.
     */
    public static void sessionFree(long storage) {
        if (storage == 0) {
            return;
        }
        nativeSessionFree(storage);
    }

    private static native void nativeSessionFree(long storage);

    public static native String sessionCatalog();

    private static void requireHandle(long handle, String what) {
        if (handle == 0) {
            throw new IllegalArgumentException(what + " must be non-zero");
        }
    }
}
