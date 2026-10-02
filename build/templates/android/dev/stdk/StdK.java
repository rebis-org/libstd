package dev.stdk;

/**
 * Raw JNI bindings for the libstd C session boundary. The native library is {@code libstd.so}
 * inside the AAR, loaded once on class init.
 */
public final class StdK {
    public static final int ABI_EPOCH = 7;
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

    // counts carries consumed, produced, and state (0 open, 1 done) in that order.
    public static native int sessionStep(
            long session,
            byte[] input,
            int inputLen,
            byte[] output,
            int outputLen,
            boolean endOfInput,
            long[] counts);

    public static native int sessionFailure(long session, long[] statusAndDetail);

    public static native int sessionDestroy(long session);

    public static native void sessionFree(long storage);

    public static native String sessionCatalog();
}
