// JNI bridge for the dev.stdk.StdK bindings. Kept out of the host library so
// the C ABI export surface stays exactly the enumerated set. The session
// handle is the caller-owned storage pointer, so this bridge owns the malloc
// behind it and releases it through sessionFree after destroy.
#include <jni.h>
#include <stdint.h>
#include <stdlib.h>

extern uint64_t stdk_session_storage(const char* component, const char* verb);
extern uint32_t stdk_session_bounded(const char* component,
                                     const char* verb,
                                     void* storage,
                                     uint64_t storage_len,
                                     uint64_t max_encoded,
                                     uint64_t max_decoded,
                                     uint64_t max_work,
                                     uint64_t max_entries);
extern uint32_t stdk_session_step(void* session,
                                  const uint8_t* input,
                                  uint64_t input_len,
                                  uint8_t* output,
                                  uint64_t output_len,
                                  int end_of_input,
                                  uint64_t* counts,
                                  int* state);
extern uint32_t stdk_session_failure(void* session, uint32_t* status, uint64_t* detail);
extern const char* stdk_session_catalog(void);
extern uint32_t stdk_session_destroy(void* session);

// The string materialization pairs collapse into one helper so the release
// path cannot drift from the acquire path.
static const char* utf8(JNIEnv* env, jstring value) {
    // GetStringUTFChars returns NULL on JVM out-of-memory.
    return value == NULL ? NULL : (*env)->GetStringUTFChars(env, value, NULL);
}

static void utf8_done(JNIEnv* env, jstring value, const char* chars) {
    if (chars != NULL) {
        (*env)->ReleaseStringUTFChars(env, value, chars);
    }
}

JNIEXPORT jlong JNICALL Java_dev_stdk_StdK_sessionStorage(JNIEnv* env, jclass cls, jstring component, jstring verb) {
    (void) cls;
    const char* component_chars = utf8(env, component);
    const char* verb_chars = utf8(env, verb);
    if (component_chars == NULL || verb_chars == NULL) {
        utf8_done(env, component, component_chars);
        utf8_done(env, verb, verb_chars);
        return 0;
    }
    jlong storage = (jlong) stdk_session_storage(component_chars, verb_chars);
    utf8_done(env, component, component_chars);
    utf8_done(env, verb, verb_chars);
    return storage;
}

JNIEXPORT jlong JNICALL Java_dev_stdk_StdK_sessionCreate(JNIEnv* env,
                                                         jclass cls,
                                                         jstring component,
                                                         jstring verb,
                                                         jlong max_encoded,
                                                         jlong max_decoded,
                                                         jlong max_work,
                                                         jlong max_entries) {
    (void) cls;
    const char* component_chars = utf8(env, component);
    const char* verb_chars = utf8(env, verb);
    if (component_chars == NULL || verb_chars == NULL) {
        utf8_done(env, component, component_chars);
        utf8_done(env, verb, verb_chars);
        return 0;
    }
    uint64_t storage_len = stdk_session_storage(component_chars, verb_chars);
    if (storage_len == 0) {
        utf8_done(env, component, component_chars);
        utf8_done(env, verb, verb_chars);
        return 0;
    }
    void* storage = malloc(storage_len);
    if (storage == NULL) {
        utf8_done(env, component, component_chars);
        utf8_done(env, verb, verb_chars);
        return 0;
    }
    uint32_t rc = stdk_session_bounded(component_chars,
                                       verb_chars,
                                       storage,
                                       storage_len,
                                       (uint64_t) max_encoded,
                                       (uint64_t) max_decoded,
                                       (uint64_t) max_work,
                                       (uint64_t) max_entries);
    utf8_done(env, component, component_chars);
    utf8_done(env, verb, verb_chars);
    if (rc != 0) {
        free(storage);
        return 0;
    }
    return (jlong) storage;
}

JNIEXPORT jint JNICALL Java_dev_stdk_StdK_sessionStep(JNIEnv* env,
                                                      jclass cls,
                                                      jlong session,
                                                      jbyteArray input,
                                                      jint input_len,
                                                      jbyteArray output,
                                                      jint output_len,
                                                      jboolean end_of_input,
                                                      jlongArray counts) {
    (void) cls;
    uint8_t* input_ptr = input != NULL ? (uint8_t*) (*env)->GetByteArrayElements(env, input, NULL) : NULL;
    uint8_t* output_ptr = output != NULL ? (uint8_t*) (*env)->GetByteArrayElements(env, output, NULL) : NULL;
    jlong* counts_ptr = (*env)->GetLongArrayElements(env, counts, NULL);
    int state = 0;
    // JNI jlong and pointer interop is inherently integer-to-pointer.
    void* session_ptr = (void*) session; /* NOLINT(performance-no-int-to-ptr) */
    uint32_t rc = stdk_session_step(session_ptr,
                                    input_ptr,
                                    (uint64_t) input_len,
                                    output_ptr,
                                    (uint64_t) output_len,
                                    end_of_input == JNI_TRUE ? 1 : 0,
                                    (uint64_t*) counts_ptr,
                                    &state);
    counts_ptr[2] = state;
    (*env)->SetLongArrayRegion(env, counts, 0, 3, counts_ptr);
    (*env)->ReleaseLongArrayElements(env, counts, counts_ptr, JNI_ABORT);
    if (output_ptr != NULL) {
        (*env)->ReleaseByteArrayElements(env, output, (jbyte*) output_ptr, 0);
    }
    if (input_ptr != NULL) {
        (*env)->ReleaseByteArrayElements(env, input, (jbyte*) input_ptr, JNI_ABORT);
    }
    return (jint) rc;
}

JNIEXPORT jint JNICALL Java_dev_stdk_StdK_sessionFailure(JNIEnv* env,
                                                         jclass cls,
                                                         jlong session,
                                                         jlongArray status_and_detail) {
    (void) cls;
    uint32_t status = 0;
    uint64_t detail = 0;
    // JNI jlong and pointer interop is inherently integer-to-pointer.
    void* session_ptr = (void*) session; /* NOLINT(performance-no-int-to-ptr) */
    uint32_t rc = stdk_session_failure(session_ptr, &status, &detail);
    jlong values[2];
    values[0] = (jlong) status;
    values[1] = (jlong) detail;
    (*env)->SetLongArrayRegion(env, status_and_detail, 0, 2, values);
    return (jint) rc;
}

JNIEXPORT jint JNICALL Java_dev_stdk_StdK_sessionDestroy(JNIEnv* env, jclass cls, jlong session) {
    (void) env;
    (void) cls;
    // JNI jlong and pointer interop is inherently integer-to-pointer.
    void* session_ptr = (void*) session; /* NOLINT(performance-no-int-to-ptr) */
    return (jint) stdk_session_destroy(session_ptr);
}

JNIEXPORT void JNICALL Java_dev_stdk_StdK_sessionFree(JNIEnv* env, jclass cls, jlong storage) {
    (void) env;
    (void) cls;
    // JNI jlong and pointer interop is inherently integer-to-pointer.
    void* storage_ptr = (void*) storage; /* NOLINT(performance-no-int-to-ptr) */
    free(storage_ptr);
}

JNIEXPORT jstring JNICALL Java_dev_stdk_StdK_sessionCatalog(JNIEnv* env, jclass cls) {
    (void) cls;
    return (*env)->NewStringUTF(env, stdk_session_catalog());
}
