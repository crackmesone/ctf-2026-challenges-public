#include <cstdint>

using i8	= int8_t;
using i16	= int16_t;
using i32	= int32_t;
using i64	= int64_t;

using u8	= uint8_t;
using u16	= uint16_t;
using u32	= uint32_t;
using u64	= uint64_t;

using f32	= float;
using f64	= double;
using f128	= long double;

static_assert(sizeof(f32) == sizeof(i32));
static_assert(sizeof(f64) == sizeof(i64));
