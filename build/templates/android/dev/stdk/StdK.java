package dev.stdk;

import java.util.Objects;

/**
 * JNI bindings for the libstd C session boundary. Java and Kotlin hosts use {@link Session} instead
 * of hand-writing JNI against stdk.h. The native library is {@code libstd.so} inside the AAR,
 * loaded once on class init.
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

    private static native long sessionCreate(
            String component,
            String verb,
            long maxEncoded,
            long maxDecoded,
            long maxWork,
            long maxEntries);

    // counts carries consumed, produced, and state (0 open, 1 done) in that order.
    private static native int sessionStep(
            long session,
            byte[] input,
            int inputLen,
            byte[] output,
            int outputLen,
            boolean endOfInput,
            long[] counts);

    private static native int sessionFailure(long session, long[] statusAndDetail);

    private static native int sessionDestroy(long session);

    private static native void sessionFree(long storage);

    public static native String sessionCatalog();

    /** Opens an unbounded session for a published pair from {@link #sessionCatalog()}. */
    public static Session open(String component, String verb) {
        return openBounded(component, verb, -1L, -1L, -1L, -1L);
    }

    /** Opens a session with per-session ceilings for untrusted input. */
    public static Session openBounded(
            String component,
            String verb,
            long maxEncoded,
            long maxDecoded,
            long maxWork,
            long maxEntries) {
        long storage = sessionStorage(component, verb);
        if (storage == 0) {
            throw new StdKException(
                    "Unknown session pair: " + component + "/" + verb, INVALID_CALL);
        }
        long handle = sessionCreate(component, verb, maxEncoded, maxDecoded, maxWork, maxEntries);
        if (handle == 0) {
            throw new StdKException(
                    "stdk_session_create failed for " + component + "/" + verb, INVALID_CALL);
        }
        return new Session(handle);
    }

    /** One pump over the given spans. A failed step throws with the driver detail. */
    public static final class Session implements AutoCloseable {
        private long handle;

        private Session(long handle) {
            this.handle = handle;
        }

        public StepResult step(byte[] input, byte[] output, boolean endOfInput) {
            if (handle == 0) {
                throw new StdKException("Session is closed.", INVALID_CALL);
            }
            // A null output can never produce bytes, so it is a caller bug, not a drain request.
            Objects.requireNonNull(output, "output");
            long[] counts = new long[3];
            int rc =
                    sessionStep(
                            handle,
                            input,
                            input != null ? input.length : 0,
                            output,
                            output != null ? output.length : 0,
                            endOfInput,
                            counts);
            if (rc != OK) {
                long[] statusAndDetail = new long[2];
                if (sessionFailure(handle, statusAndDetail) == OK) {
                    throw new StdKException(
                            "Session step failed with status "
                                    + statusAndDetail[0]
                                    + ", detail "
                                    + statusAndDetail[1],
                            (int) statusAndDetail[0]);
                }
                throw new StdKException("Session step failed with status " + rc, rc);
            }
            return new StepResult(counts[0], counts[1], counts[2] == 1);
        }

        /** Idempotent destroy. Stepping a closed session throws. */
        @Override
        public void close() {
            if (handle != 0) {
                sessionDestroy(handle);
                sessionFree(handle);
                handle = 0;
            }
        }
    }

    public static final class StepResult {
        public final long consumed;
        public final long produced;
        public final boolean finished;

        private StepResult(long consumed, long produced, boolean finished) {
            this.consumed = consumed;
            this.produced = produced;
            this.finished = finished;
        }
    }

    public static class StdKException extends RuntimeException {
        private static final long serialVersionUID = 1;
        public final int status;

        public StdKException(String message, int status) {
            super(message);
            this.status = status;
        }
    }
}
