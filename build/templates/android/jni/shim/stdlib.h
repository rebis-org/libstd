/* Minimal declarations for the android target: zig bundles no libc headers,
   and the bridge only needs malloc and free. Symbol resolution at link time
   goes against the android libc stubs like the rest of the library. */
#ifndef STDK_JNI_STDLIB_SHIM
#define STDK_JNI_STDLIB_SHIM
#ifndef NULL
    #define NULL ((void*) 0)
#endif
void* malloc(unsigned long);
void free(void*);
#endif
