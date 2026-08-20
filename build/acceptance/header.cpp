#include "abi.h"

#include <concepts>
#include <cstddef>
#include <type_traits>

template <typename T>
concept stdk_abi_value = std::is_standard_layout_v<T> && std::is_trivially_copyable_v<T>;

#define STDK_CXX_RUN(kind, ...) STDK_CXX_##kind(__VA_ARGS__)
#define STDK_CXX_TYPE(expression, type) static_assert(std::same_as<decltype(expression), type>, #expression " : " #type)
#define STDK_CXX_SIZE(type, expected) static_assert(sizeof(type) == (expected), #type " size")
#define STDK_CXX_OFFSET(type, member, expected)                                                                        \
    static_assert(offsetof(type, member) == (expected), #type "." #member " offset")
#define STDK_CXX_VALUE(expression, expected) static_assert((expression) == (expected), #expression " value")

STDK_ABI_CONTRACT(STDK_CXX_RUN)

static_assert(stdk_abi_value<stdk_id> && stdk_abi_value<stdk_node> && stdk_abi_value<stdk_call_envelope>);

[[maybe_unused]]
constinit const stdk_id stdk_null_id {};
constexpr stdk_id stdk_compile_time_null_id {};
static_assert(stdk_compile_time_null_id.low == 0 && stdk_compile_time_null_id.high == 0);

int main() {
    return static_cast<int>(STDK_STATUS_OK);
}
