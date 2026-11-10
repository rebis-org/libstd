#include <jni.h>
#include <stdint.h>
#include <stdlib.h>

enum {
	kStatusInvalidCall = 1,
};

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

static const char *acquire_utf8(JNIEnv *env, jstring value)
{
	return value == NULL ? NULL :
			       (*env)->GetStringUTFChars(env, value, NULL);
}

static void release_utf8(JNIEnv *env, jstring value, const char *chars)
{
	if (chars != NULL) {
		(*env)->ReleaseStringUTFChars(env, value, chars);
	}
}

static void throw_illegal_arg(JNIEnv *env, const char *message)
{
	(*env)->ThrowNew(
		env,
		(*env)->FindClass(env, "java/lang/IllegalArgumentException"),
		message);
}

static jint checked_len(JNIEnv *env, jbyteArray array, jint len,
			const char *what)
{
	if (len < 0 || (array == NULL && len != 0)) {
		throw_illegal_arg(env, what);
		return -1;
	}
	if (array != NULL && len > (*env)->GetArrayLength(env, array)) {
		throw_illegal_arg(env, what);
		return -1;
	}
	return len;
}

/*
 * The JVM resolves every symbol below by its JNI-mandated name
 * (Java_<package>_<class>_<method> from dev.stdk.StdK), needs external
 * linkage, and calls each entry with the exact parameter list declared by
 * the Java native method, so the naming, internal-linkage, and
 * swappable-parameters rules cannot apply to the JNI surface.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
/* NOLINTNEXTLINE(misc-use-internal-linkage,readability-identifier-naming) */
JNIEXPORT jlong JNICALL Java_dev_stdk_StdK_sessionStorage(JNIEnv *env,
							  jclass cls,
							  jstring component,
							  jstring verb)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
	(void)cls;
	const char *component_chars = acquire_utf8(env, component);
	const char *verb_chars = acquire_utf8(env, verb);
	if (component_chars == NULL || verb_chars == NULL) {
		release_utf8(env, component, component_chars);
		release_utf8(env, verb, verb_chars);
		return 0;
	}
	jlong storage =
		(jlong)stdk_session_storage(component_chars, verb_chars);
	release_utf8(env, component, component_chars);
	release_utf8(env, verb, verb_chars);
	return storage;
}

/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
/* NOLINTNEXTLINE(misc-use-internal-linkage,readability-identifier-naming) */
JNIEXPORT jlong JNICALL Java_dev_stdk_StdK_sessionCreate(
	JNIEnv *env, jclass cls, jstring component, jstring verb,
	jlong max_encoded, jlong max_decoded, jlong max_work, jlong max_entries)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
	(void)cls;
	const char *component_chars = acquire_utf8(env, component);
	const char *verb_chars = acquire_utf8(env, verb);
	if (component_chars == NULL || verb_chars == NULL) {
		release_utf8(env, component, component_chars);
		release_utf8(env, verb, verb_chars);
		return 0;
	}
	uint64_t storage_len =
		stdk_session_storage(component_chars, verb_chars);
	if (storage_len == 0) {
		release_utf8(env, component, component_chars);
		release_utf8(env, verb, verb_chars);
		return 0;
	}
	void *storage = malloc(storage_len);
	if (storage == NULL) {
		release_utf8(env, component, component_chars);
		release_utf8(env, verb, verb_chars);
		return 0;
	}
	uint32_t ret = stdk_session_bounded(
		component_chars, verb_chars, storage, storage_len,
		(uint64_t)max_encoded, (uint64_t)max_decoded,
		(uint64_t)max_work, (uint64_t)max_entries);
	release_utf8(env, component, component_chars);
	release_utf8(env, verb, verb_chars);
	if (ret != 0) {
		free(storage);
		return 0;
	}
	return (jlong)storage;
}

/* NOLINTNEXTLINE(misc-use-internal-linkage,readability-identifier-naming) */
JNIEXPORT jint JNICALL Java_dev_stdk_StdK_nativeSessionStep(
	JNIEnv *env, jclass cls, jlong session, jbyteArray input,
	jint input_len, jbyteArray output, jint output_len,
	jboolean end_of_input, jlongArray counts)
{
	(void)cls;
	if (checked_len(env, input, input_len, "inputLen out of range") < 0) {
		return kStatusInvalidCall;
	}
	if (checked_len(env, output, output_len, "outputLen out of range") <
	    0) {
		return kStatusInvalidCall;
	}
	if (counts == NULL || (*env)->GetArrayLength(env, counts) < 3) {
		throw_illegal_arg(env, "counts must hold 3 elements");
		return kStatusInvalidCall;
	}
	uint8_t *input_ptr = input != NULL ?
				     (uint8_t *)(*env)->GetByteArrayElements(
					     env, input, NULL) :
				     NULL;
	uint8_t *output_ptr = output != NULL ?
				      (uint8_t *)(*env)->GetByteArrayElements(
					      env, output, NULL) :
				      NULL;
	if (input != NULL && input_ptr == NULL) {
		if (output_ptr != NULL) {
			(*env)->ReleaseByteArrayElements(
				env, output, (jbyte *)output_ptr, JNI_ABORT);
		}
		return kStatusInvalidCall;
	}
	if (output != NULL && output_ptr == NULL) {
		if (input_ptr != NULL) {
			(*env)->ReleaseByteArrayElements(
				env, input, (jbyte *)input_ptr, JNI_ABORT);
		}
		return kStatusInvalidCall;
	}
	jlong *counts_ptr = (*env)->GetLongArrayElements(env, counts, NULL);
	if (counts_ptr == NULL) {
		if (output_ptr != NULL) {
			(*env)->ReleaseByteArrayElements(
				env, output, (jbyte *)output_ptr, JNI_ABORT);
		}
		if (input_ptr != NULL) {
			(*env)->ReleaseByteArrayElements(
				env, input, (jbyte *)input_ptr, JNI_ABORT);
		}
		return kStatusInvalidCall;
	}
	int state = 0;
	void *session_ptr =
		(void *)session; /* NOLINT(performance-no-int-to-ptr) */
	uint32_t ret = stdk_session_step(session_ptr, input_ptr,
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
	return (jint)ret;
}

/* NOLINTNEXTLINE(misc-use-internal-linkage,readability-identifier-naming) */
JNIEXPORT jint JNICALL Java_dev_stdk_StdK_nativeSessionFailure(
	JNIEnv *env, jclass cls, jlong session, jlongArray status_and_detail)
{
	(void)cls;
	if (status_and_detail == NULL ||
	    (*env)->GetArrayLength(env, status_and_detail) < 2) {
		throw_illegal_arg(env, "statusAndDetail must hold 2 elements");
		return kStatusInvalidCall;
	}
	uint32_t status = 0;
	uint64_t detail = 0;
	void *session_ptr =
		(void *)session; /* NOLINT(performance-no-int-to-ptr) */
	uint32_t ret = stdk_session_failure(session_ptr, &status, &detail);
	jlong values[2];
	values[0] = (jlong)status;
	values[1] = (jlong)detail;
	(*env)->SetLongArrayRegion(env, status_and_detail, 0, 2, values);
	return (jint)ret;
}

/* NOLINTNEXTLINE(misc-use-internal-linkage,readability-identifier-naming) */
JNIEXPORT jint JNICALL Java_dev_stdk_StdK_nativeSessionDestroy(JNIEnv *env,
							       jclass cls,
							       jlong session)
{
	(void)env;
	(void)cls;
	void *session_ptr =
		(void *)session; /* NOLINT(performance-no-int-to-ptr) */
	return (jint)stdk_session_destroy(session_ptr);
}

/* NOLINTNEXTLINE(misc-use-internal-linkage,readability-identifier-naming) */
JNIEXPORT void JNICALL Java_dev_stdk_StdK_nativeSessionFree(JNIEnv *env,
							    jclass cls,
							    jlong storage)
{
	(void)env;
	(void)cls;
	/* JNI jlong and pointer interop is inherently integer-to-pointer. */
	void *storage_ptr =
		(void *)storage; /* NOLINT(performance-no-int-to-ptr) */
	free(storage_ptr);
}

/* NOLINTNEXTLINE(misc-use-internal-linkage,readability-identifier-naming) */
JNIEXPORT jstring JNICALL Java_dev_stdk_StdK_sessionCatalog(JNIEnv *env,
							    jclass cls)
{
	(void)cls;
	return (*env)->NewStringUTF(env, stdk_session_catalog());
}
