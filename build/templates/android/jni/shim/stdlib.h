/* Zig ships no android libc headers; malloc and free resolve against
   the libc stubs at link. */
#ifndef STDK_JNI_STDLIB_SHIM
#define STDK_JNI_STDLIB_SHIM
#ifndef NULL
#define NULL 0
#endif
typedef __SIZE_TYPE__ size_t;
void *malloc(size_t);
void free(void *);
#endif
