#include "abi.h"

// NOLINTNEXTLINE(bugprone-macro-parentheses)
#define STDK_C_SAME(expression, type) _Generic((expression), type: 1, default: 0)
#define STDK_C_RUN(kind, ...) STDK_C_##kind(__VA_ARGS__)
#define STDK_C_TYPE(expression, type) _Static_assert(STDK_C_SAME(expression, type), #expression " : " #type)
#define STDK_C_SIZE(type, expected) _Static_assert(sizeof(type) == (expected), #type " size")
#define STDK_C_OFFSET(type, member, expected)                                                                          \
    _Static_assert(offsetof(type, member) == (expected), #type "." #member " offset")
#define STDK_C_VALUE(expression, expected) _Static_assert((expression) == (expected), #expression " value")

STDK_ABI_CONTRACT(STDK_C_RUN)

int main(void) {
    return STDK_STATUS_OK;
}
