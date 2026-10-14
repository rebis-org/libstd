// JNI bridge for the dev.stdk.StdK bindings. Kept out of the host library so
// the C ABI export surface stays exactly the enumerated set. The session
// handle is the caller-owned storage pointer, so this bridge owns the malloc
// behind it and releases it through sessionFree after destroy.
#include <jni.h>
#include <stdint.h>
#include <stdlib.h>

// The envelope status vocabulary subset this bridge needs. Kept as literals so
// the bridge stays decoupled from the generated header.
#define STDK_STATUS_OK 0u
#define STDK_STATUS_INVALID_CALL 1u

extern uint64_t stdk_session_storage(const char *component, const char *verb);
extern uint32_t stdk_session_bounded(const char *component, const char *verb,
				     void *storage, uint64_t storage_len,
				     uint64_t max_encoded, uint64_t max_decoded,
				     uint64_t max_work, uint64_t max_entries);
extern uint32_t stdk_session_step(void *session, const uint8_t *input,
				  uint64_t input_len, uint8_t *output,
				  uint64_t output_len, int end_of_input,
				  uint64_t *counts, int *state);
extern uint32_t stdk_session_failure(void *session, uint32_t *status,
				     uint64_t *detail);
extern const char *stdk_session_catalog(void);
extern uint32_t stdk_session_destroy(void *session);

// The string materialization pairs collapse into one helper so the release
// path cannot drift from the acquire path.
static const char *acquireUtf8(JNIEnv *env, jstring value)
{
	// GetStringUTFChars returns NULL on JVM out-of-memory.
	return value == NULL ? NULL :
			       (*env)->GetStringUTFChars(env, value, NULL);
}

static void releaseUtf8(JNIEnv *env, jstring value, const char *chars)
{
	if (chars != NULL) {
		(*env)->ReleaseStringUTFChars(env, value, chars);
	}
}

// Rejects negative lengths and lengths past the real array extent before any
// pointer is handed to the native engine: a negative jint widens to a huge
// u64 in the engine and would read or write out of bounds.
static jint checkedLen(JNIEnv *env, jbyteArray array, jint len,
		       const char *what)
{
	if (len < 0 || (array == NULL && len != 0)) {
		(*env)->ThrowNew(
			env,
			(*env)->FindClass(env,
					  "java/lang/IllegalArgumentException"),
			what);
		return -1;
	}
	if (array != NULL && len > (*env)->GetArrayLength(env, array)) {
		(*env)->ThrowNew(
			env,
			(*env)->FindClass(env,
					  "java/lang/IllegalArgumentException"),
			what);
		return -1;
	}
	return len;
}

JNIEXPORT jlong JNICALL Java_dev_stdk_StdK_sessionStorage(JNIEnv *env,
							  jclass cls,
							  jstring component,
							  jstring verb)
{
	(void)cls;
	const char *component_chars = acquireUtf8(env, component);
	const char *verb_chars = acquireUtf8(env, verb);
	if (component_chars == NULL || verb_chars == NULL) {
		releaseUtf8(env, component, component_chars);
		releaseUtf8(env, verb, verb_chars);
		return 0;
	}
	jlong storage =
		(jlong)stdk_session_storage(component_chars, verb_chars);
	releaseUtf8(env, component, component_chars);
	releaseUtf8(env, verb, verb_chars);
	return storage;
}

JNIEXPORT jlong JNICALL Java_dev_stdk_StdK_sessionCreate(
	JNIEnv *env, jclass cls, jstring component, jstring verb,
	jlong max_encoded, jlong max_decoded, jlong max_work, jlong max_entries)
{
	(void)cls;
	const char *component_chars = acquireUtf8(env, component);
	const char *verb_chars = acquireUtf8(env, verb);
	if (component_chars == NULL || verb_chars == NULL) {
		releaseUtf8(env, component, component_chars);
		releaseUtf8(env, verb, verb_chars);
		return 0;
	}
	uint64_t storage_len =
		stdk_session_storage(component_chars, verb_chars);
	if (storage_len == 0) {
		releaseUtf8(env, component, component_chars);
		releaseUtf8(env, verb, verb_chars);
		return 0;
	}
	void *storage = malloc(storage_len);
	if (storage == NULL) {
		releaseUtf8(env, component, component_chars);
		releaseUtf8(env, verb, verb_chars);
		return 0;
	}
	uint32_t rc = stdk_session_bounded(component_chars, verb_chars, storage,
					   storage_len, (uint64_t)max_encoded,
					   (uint64_t)max_decoded,
					   (uint64_t)max_work,
					   (uint64_t)max_entries);
	releaseUtf8(env, component, component_chars);
	releaseUtf8(env, verb, verb_chars);
	if (rc != 0) {
		free(storage);
		return 0;
	}
	return (jlong)storage;
}

JNIEXPORT jint JNICALL Java_dev_stdk_StdK_nativeSessionStep(
	JNIEnv *env, jclass cls, jlong session, jbyteArray input,
	jint input_len, jbyteArray output, jint output_len,
	jboolean end_of_input, jlongArray counts)
{
	(void)cls;
	if (checkedLen(env, input, input_len, "inputLen out of range") < 0) {
		return STDK_STATUS_INVALID_CALL;
	}
	if (checkedLen(env, output, output_len, "outputLen out of range") < 0) {
		return STDK_STATUS_INVALID_CALL;
	}
	// Counts must exist and carry consumed, produced, and state.
	if (counts == NULL || (*env)->GetArrayLength(env, counts) < 3) {
		(*env)->ThrowNew(
			env,
			(*env)->FindClass(env,
					  "java/lang/IllegalArgumentException"),
			"counts must hold 3 elements");
		return STDK_STATUS_INVALID_CALL;
	}
	uint8_t *input_ptr = input != NULL ?
				     (uint8_t *)(*env)->GetByteArrayElements(
					     env, input, NULL) :
				     NULL;
	uint8_t *output_ptr = output != NULL ?
				      (uint8_t *)(*env)->GetByteArrayElements(
					      env, output, NULL) :
				      NULL;
	jlong *counts_ptr = (*env)->GetLongArrayElements(env, counts, NULL);
	if (counts_ptr == NULL) {
		// JVM out-of-memory while materializing the counts array.
		if (output_ptr != NULL) {
			(*env)->ReleaseByteArrayElements(
				env, output, (jbyte *)output_ptr, JNI_ABORT);
		}
		if (input_ptr != NULL) {
			(*env)->ReleaseByteArrayElements(
				env, input, (jbyte *)input_ptr, JNI_ABORT);
		}
		return STDK_STATUS_INVALID_CALL;
	}
	int state = 0;
	// JNI jlong and pointer interop is inherently integer-to-pointer.
	void *session_ptr =
		(void *)session; /* NOLINT(performance-no-int-to-ptr) */
	uint32_t rc = stdk_session_step(session_ptr, input_ptr,
					(uint64_t)input_len, output_ptr,
					(uint64_t)output_len,
					end_of_input == JNI_TRUE ? 1 : 0,
					(uint64_t *)counts_ptr, &state);
	counts_ptr[2] = state;
	(*env)->SetLongArrayRegion(env, counts, 0, 3, counts_ptr);
	(*env)->ReleaseLongArrayElements(env, counts, counts_ptr, JNI_ABORT);
	if (output_ptr != NULL) {
		(*env)->ReleaseByteArrayElements(env, output,
						 (jbyte *)output_ptr, 0);
	}
	if (input_ptr != NULL) {
		(*env)->ReleaseByteArrayElements(env, input, (jbyte *)input_ptr,
						 JNI_ABORT);
	}
	return (jint)rc;
}

JNIEXPORT jint JNICALL Java_dev_stdk_StdK_nativeSessionFailure(
	JNIEnv *env, jclass cls, jlong session, jlongArray status_and_detail)
{
	(void)cls;
	if (status_and_detail == NULL ||
	    (*env)->GetArrayLength(env, status_and_detail) < 2) {
		(*env)->ThrowNew(
			env,
			(*env)->FindClass(env,
					  "java/lang/IllegalArgumentException"),
			"statusAndDetail must hold 2 elements");
		return STDK_STATUS_INVALID_CALL;
	}
	uint32_t status = 0;
	uint64_t detail = 0;
	// JNI jlong and pointer interop is inherently integer-to-pointer.
	void *session_ptr =
		(void *)session; /* NOLINT(performance-no-int-to-ptr) */
	uint32_t rc = stdk_session_failure(session_ptr, &status, &detail);
	jlong values[2];
	values[0] = (jlong)status;
	values[1] = (jlong)detail;
	(*env)->SetLongArrayRegion(env, status_and_detail, 0, 2, values);
	return (jint)rc;
}

JNIEXPORT jint JNICALL Java_dev_stdk_StdK_nativeSessionDestroy(JNIEnv *env,
							       jclass cls,
							       jlong session)
{
	(void)env;
	(void)cls;
	// JNI jlong and pointer interop is inherently integer-to-pointer.
	void *session_ptr =
		(void *)session; /* NOLINT(performance-no-int-to-ptr) */
	return (jint)stdk_session_destroy(session_ptr);
}

// Frees storage obtained from sessionCreate. Java must never pass a foreign or
// already-freed pointer; the class tracks live handles and nulls them on free.
JNIEXPORT void JNICALL Java_dev_stdk_StdK_nativeSessionFree(JNIEnv *env,
							    jclass cls,
							    jlong storage)
{
	(void)env;
	(void)cls;
	// JNI jlong and pointer interop is inherently integer-to-pointer.
	void *storage_ptr =
		(void *)storage; /* NOLINT(performance-no-int-to-ptr) */
	free(storage_ptr);
}

JNIEXPORT jstring JNICALL Java_dev_stdk_StdK_sessionCatalog(JNIEnv *env,
							    jclass cls)
{
	(void)cls;
	return (*env)->NewStringUTF(env, stdk_session_catalog());
}
