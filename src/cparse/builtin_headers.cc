// The freestanding headers a compiler ships, written over the macros the
// profile predefines (__SIZE_TYPE__, __INT_MAX__, ...) as GCC's are, so one
// text serves every target. Where the target has a C library (a system
// include directory with its own stdint.h or limits.h), those are
// included next, as GCC's do.

#include "preprocessor.h"

#include <map>

namespace revkit::cparse::detail {
namespace {

const char *const kStddef = R"(/* revkit built-in <stddef.h> */
#if !defined(__need_size_t) && !defined(__need_ptrdiff_t) && !defined(__need_wchar_t) && \
    !defined(__need_NULL) && !defined(__need_wint_t) && !defined(__need_max_align_t) && \
    !defined(__need_offsetof) && !defined(__need_rsize_t)
#define __rk_stddef_all 1
#endif
#if defined(__rk_stddef_all) || defined(__need_size_t)
#ifndef __rk_size_t
#define __rk_size_t
#define _SIZE_T
#define __SIZE_T
#define _SIZE_T_
#define __size_t__
#define _BSD_SIZE_T_
#define _SIZE_T_DECLARED
#define __size_t
typedef __SIZE_TYPE__ size_t;
#endif
#endif
#if defined(__rk_stddef_all) || defined(__need_ptrdiff_t)
#ifndef __rk_ptrdiff_t
#define __rk_ptrdiff_t
#define _PTRDIFF_T
#define _PTRDIFF_T_
#define __PTRDIFF_T
typedef __PTRDIFF_TYPE__ ptrdiff_t;
#endif
#endif
#if (defined(__rk_stddef_all) || defined(__need_wchar_t)) && !defined(__cplusplus)
#ifndef __rk_wchar_t
#define __rk_wchar_t
#define _WCHAR_T
#define _WCHAR_T_
#define __WCHAR_T
#define _BSD_WCHAR_T_
#define __wchar_t__
typedef __WCHAR_TYPE__ wchar_t;
#endif
#endif
#if defined(__need_wint_t)
#ifndef __rk_wint_t
#define __rk_wint_t
#define _WINT_T
typedef __WINT_TYPE__ wint_t;
#endif
#endif
#if defined(__rk_stddef_all) || defined(__need_NULL)
#undef NULL
#ifdef __cplusplus
#define NULL 0
#else
#define NULL ((void *)0)
#endif
#endif
#if defined(__rk_stddef_all) || defined(__need_offsetof)
#undef offsetof
#define offsetof(TYPE, MEMBER) __builtin_offsetof(TYPE, MEMBER)
#endif
#if (defined(__rk_stddef_all) || defined(__need_max_align_t)) && !defined(__rk_max_align_t)
#define __rk_max_align_t
#define __CLANG_MAX_ALIGN_T_DEFINED
#ifdef _MSC_VER
typedef double max_align_t;
#else
typedef struct {
  long long __max_align_ll __attribute__((__aligned__(__alignof__(long long))));
  long double __max_align_ld __attribute__((__aligned__(__alignof__(long double))));
#ifdef __i386__
  __float128 __max_align_f128 __attribute__((__aligned__(__alignof(__float128))));
#endif
} max_align_t;
#endif
#endif
#if defined(__rk_stddef_all) && !defined(_STDDEF_H)
#define _STDDEF_H
#define _STDDEF_H_
#define _ANSI_STDDEF_H
#endif
#undef __need_size_t
#undef __need_rsize_t
#undef __need_ptrdiff_t
#undef __need_wchar_t
#undef __need_wint_t
#undef __need_NULL
#undef __need_offsetof
#undef __need_max_align_t
#undef __rk_stddef_all
)";

const char *const kStdint = R"(/* revkit built-in <stdint.h> */
#if __STDC_HOSTED__ && __has_include_next(<stdint.h>) && !defined(__rk_freestanding_stdint)
#include_next <stdint.h>
#elif !defined(__rk_stdint_h)
#define __rk_stdint_h
#define _STDINT_H
typedef __INT8_TYPE__ int8_t;
typedef __INT16_TYPE__ int16_t;
typedef __INT32_TYPE__ int32_t;
typedef __INT64_TYPE__ int64_t;
typedef __UINT8_TYPE__ uint8_t;
typedef __UINT16_TYPE__ uint16_t;
typedef __UINT32_TYPE__ uint32_t;
typedef __UINT64_TYPE__ uint64_t;
typedef __INT_LEAST8_TYPE__ int_least8_t;
typedef __INT_LEAST16_TYPE__ int_least16_t;
typedef __INT_LEAST32_TYPE__ int_least32_t;
typedef __INT_LEAST64_TYPE__ int_least64_t;
typedef __UINT_LEAST8_TYPE__ uint_least8_t;
typedef __UINT_LEAST16_TYPE__ uint_least16_t;
typedef __UINT_LEAST32_TYPE__ uint_least32_t;
typedef __UINT_LEAST64_TYPE__ uint_least64_t;
typedef __INT_FAST8_TYPE__ int_fast8_t;
typedef __INT_FAST16_TYPE__ int_fast16_t;
typedef __INT_FAST32_TYPE__ int_fast32_t;
typedef __INT_FAST64_TYPE__ int_fast64_t;
typedef __UINT_FAST8_TYPE__ uint_fast8_t;
typedef __UINT_FAST16_TYPE__ uint_fast16_t;
typedef __UINT_FAST32_TYPE__ uint_fast32_t;
typedef __UINT_FAST64_TYPE__ uint_fast64_t;
typedef __INTPTR_TYPE__ intptr_t;
typedef __UINTPTR_TYPE__ uintptr_t;
typedef __INTMAX_TYPE__ intmax_t;
typedef __UINTMAX_TYPE__ uintmax_t;
#define INT8_MAX __INT8_MAX__
#define INT16_MAX __INT16_MAX__
#define INT32_MAX __INT32_MAX__
#define INT64_MAX __INT64_MAX__
#define INT8_MIN (-INT8_MAX - 1)
#define INT16_MIN (-INT16_MAX - 1)
#define INT32_MIN (-INT32_MAX - 1)
#define INT64_MIN (-INT64_MAX - 1)
#define UINT8_MAX __UINT8_MAX__
#define UINT16_MAX __UINT16_MAX__
#define UINT32_MAX __UINT32_MAX__
#define UINT64_MAX __UINT64_MAX__
#define INTPTR_MAX __INTPTR_MAX__
#define INTPTR_MIN (-INTPTR_MAX - 1)
#define UINTPTR_MAX __UINTPTR_MAX__
#define INTMAX_MAX __INTMAX_MAX__
#define INTMAX_MIN (-INTMAX_MAX - 1)
#define UINTMAX_MAX __UINTMAX_MAX__
#define PTRDIFF_MAX __PTRDIFF_MAX__
#define PTRDIFF_MIN (-PTRDIFF_MAX - 1)
#define SIZE_MAX __SIZE_MAX__
#define WCHAR_MAX __WCHAR_MAX__
#define WCHAR_MIN __WCHAR_MIN__
#define INT8_C(c) __INT8_C(c)
#define INT16_C(c) __INT16_C(c)
#define INT32_C(c) __INT32_C(c)
#define INT64_C(c) __INT64_C(c)
#define UINT8_C(c) __UINT8_C(c)
#define UINT16_C(c) __UINT16_C(c)
#define UINT32_C(c) __UINT32_C(c)
#define UINT64_C(c) __UINT64_C(c)
#define INTMAX_C(c) __INTMAX_C(c)
#define UINTMAX_C(c) __UINTMAX_C(c)
#endif
)";

const char *const kStdbool = R"(/* revkit built-in <stdbool.h> */
#ifndef __rk_stdbool_h
#define __rk_stdbool_h
#define _STDBOOL_H
#ifndef __cplusplus
#define bool _Bool
#define true 1
#define false 0
#endif
#define __bool_true_false_are_defined 1
#endif
)";

const char *const kStdarg = R"(/* revkit built-in <stdarg.h> */
#ifndef __GNUC_VA_LIST
#define __GNUC_VA_LIST
typedef __builtin_va_list __gnuc_va_list;
#endif
#ifndef __need___va_list
#ifndef __rk_stdarg_h
#define __rk_stdarg_h
#define _STDARG_H
#define _ANSI_STDARG_H_
#define va_start(v, ...) __builtin_va_start(v, 0)
#define va_end(v) __builtin_va_end(v)
#define va_arg(v, l) __builtin_va_arg(v, l)
#define va_copy(d, s) __builtin_va_copy(d, s)
#define __va_copy(d, s) __builtin_va_copy(d, s)
#if !defined(_VA_LIST_) && !defined(_VA_LIST) && !defined(_VA_LIST_DEFINED) && !defined(_VA_LIST_T_H)
#define _VA_LIST_
#define _VA_LIST
#define _VA_LIST_DEFINED
#define _VA_LIST_T_H
#define __va_list__
typedef __gnuc_va_list va_list;
#endif
#endif
#endif
#undef __need___va_list
)";

const char *const kLimits = R"(/* revkit built-in <limits.h> */
#ifndef __rk_limits_h
#define __rk_limits_h
#ifndef _GCC_LIMITS_H_
#define _GCC_LIMITS_H_
#endif
#if __STDC_HOSTED__ && __has_include_next(<limits.h>)
#include_next <limits.h>
#endif
#undef CHAR_BIT
#define CHAR_BIT __CHAR_BIT__
#undef MB_LEN_MAX
#define MB_LEN_MAX 16
#undef SCHAR_MAX
#define SCHAR_MAX __SCHAR_MAX__
#undef SCHAR_MIN
#define SCHAR_MIN (-SCHAR_MAX - 1)
#undef UCHAR_MAX
#define UCHAR_MAX (SCHAR_MAX * 2 + 1)
#undef CHAR_MIN
#undef CHAR_MAX
#ifdef __CHAR_UNSIGNED__
#define CHAR_MIN 0
#define CHAR_MAX UCHAR_MAX
#else
#define CHAR_MIN SCHAR_MIN
#define CHAR_MAX SCHAR_MAX
#endif
#undef SHRT_MAX
#define SHRT_MAX __SHRT_MAX__
#undef SHRT_MIN
#define SHRT_MIN (-SHRT_MAX - 1)
#undef USHRT_MAX
#define USHRT_MAX (SHRT_MAX * 2 + 1)
#undef INT_MAX
#define INT_MAX __INT_MAX__
#undef INT_MIN
#define INT_MIN (-INT_MAX - 1)
#undef UINT_MAX
#define UINT_MAX (INT_MAX * 2U + 1U)
#undef LONG_MAX
#define LONG_MAX __LONG_MAX__
#undef LONG_MIN
#define LONG_MIN (-LONG_MAX - 1L)
#undef ULONG_MAX
#define ULONG_MAX (LONG_MAX * 2UL + 1UL)
#undef LLONG_MAX
#define LLONG_MAX __LONG_LONG_MAX__
#undef LLONG_MIN
#define LLONG_MIN (-LLONG_MAX - 1LL)
#undef ULLONG_MAX
#define ULLONG_MAX (LLONG_MAX * 2ULL + 1ULL)
#endif
)";

const char *const kFloat = R"(/* revkit built-in <float.h> */
#ifndef __rk_float_h
#define __rk_float_h
#define FLT_RADIX 2
#define FLT_MANT_DIG 24
#define DBL_MANT_DIG 53
#define LDBL_MANT_DIG __LDBL_MANT_DIG__
#define FLT_DIG 6
#define DBL_DIG 15
#define FLT_MIN_EXP (-125)
#define DBL_MIN_EXP (-1021)
#define FLT_MAX_EXP 128
#define DBL_MAX_EXP 1024
#define FLT_MIN_10_EXP (-37)
#define DBL_MIN_10_EXP (-307)
#define FLT_MAX_10_EXP 38
#define DBL_MAX_10_EXP 308
#define FLT_MAX 3.40282346638528859811704183484516925e+38F
#define DBL_MAX 1.79769313486231570814527423731704357e+308
#define FLT_EPSILON 1.19209289550781250000000000000000000e-7F
#define DBL_EPSILON 2.22044604925031308084726333618164062e-16
#define FLT_MIN 1.17549435082228750796873653722224568e-38F
#define DBL_MIN 2.22507385850720138309023271733240406e-308
#define FLT_EVAL_METHOD 0
#define DECIMAL_DIG 21
#endif
)";

const char *const kStdalign = R"(/* revkit built-in <stdalign.h> */
#ifndef __cplusplus
#define alignas _Alignas
#define alignof _Alignof
#endif
#define __alignas_is_defined 1
#define __alignof_is_defined 1
)";

const char *const kStdnoreturn = R"(/* revkit built-in <stdnoreturn.h> */
#ifndef __cplusplus
#define noreturn _Noreturn
#endif
)";

const char *const kIso646 = R"(/* revkit built-in <iso646.h> */
#ifndef __cplusplus
#define and &&
#define and_eq &=
#define bitand &
#define bitor |
#define compl ~
#define not !
#define not_eq !=
#define or ||
#define or_eq |=
#define xor ^
#define xor_eq ^=
#endif
)";

const char *const kStdatomic = R"(/* revkit built-in <stdatomic.h> */
#ifndef __rk_stdatomic_h
#define __rk_stdatomic_h
#include <stddef.h>
#include <stdint.h>
typedef enum memory_order {
  memory_order_relaxed = __ATOMIC_RELAXED,
  memory_order_consume = __ATOMIC_CONSUME,
  memory_order_acquire = __ATOMIC_ACQUIRE,
  memory_order_release = __ATOMIC_RELEASE,
  memory_order_acq_rel = __ATOMIC_ACQ_REL,
  memory_order_seq_cst = __ATOMIC_SEQ_CST
} memory_order;
typedef _Atomic _Bool atomic_bool;
typedef _Atomic char atomic_char;
typedef _Atomic signed char atomic_schar;
typedef _Atomic unsigned char atomic_uchar;
typedef _Atomic short atomic_short;
typedef _Atomic unsigned short atomic_ushort;
typedef _Atomic int atomic_int;
typedef _Atomic unsigned int atomic_uint;
typedef _Atomic long atomic_long;
typedef _Atomic unsigned long atomic_ulong;
typedef _Atomic long long atomic_llong;
typedef _Atomic unsigned long long atomic_ullong;
typedef _Atomic __CHAR16_TYPE__ atomic_char16_t;
typedef _Atomic __CHAR32_TYPE__ atomic_char32_t;
typedef _Atomic __WCHAR_TYPE__ atomic_wchar_t;
typedef _Atomic __INTPTR_TYPE__ atomic_intptr_t;
typedef _Atomic __UINTPTR_TYPE__ atomic_uintptr_t;
typedef _Atomic __SIZE_TYPE__ atomic_size_t;
typedef _Atomic __PTRDIFF_TYPE__ atomic_ptrdiff_t;
typedef _Atomic __INTMAX_TYPE__ atomic_intmax_t;
typedef _Atomic __UINTMAX_TYPE__ atomic_uintmax_t;
typedef _Atomic struct { _Bool __val; } atomic_flag;
#define ATOMIC_VAR_INIT(V) (V)
#define ATOMIC_FLAG_INIT { 0 }
#endif
)";

// GCC's x86 header for _mm_malloc, which mingw-w64's malloc.h includes.
const char *const kMmMalloc = R"(/* revkit built-in <mm_malloc.h> */
#ifndef _MM_MALLOC_H_INCLUDED
#define _MM_MALLOC_H_INCLUDED
#include <stddef.h>
void *_mm_malloc(size_t __size, size_t __alignment);
void _mm_free(void *__ptr);
#endif
)";

const std::map<std::string, const char *> &headers() {
  static const std::map<std::string, const char *> m = {
      {"stddef.h", kStddef}, {"stdint.h", kStdint},   {"stdbool.h", kStdbool},         {"stdarg.h", kStdarg},
      {"limits.h", kLimits}, {"float.h", kFloat},     {"stdalign.h", kStdalign},       {"iso646.h", kIso646},
      {"stdnoreturn.h", kStdnoreturn}, {"mm_malloc.h", kMmMalloc},
      {"stdatomic.h", kStdatomic},
  };
  return m;
}

}  // namespace

const char *builtin_header(const std::string &name) {
  auto it = headers().find(name);
  return it == headers().end() ? nullptr : it->second;
}

std::vector<std::string> builtin_header_names() {
  std::vector<std::string> out;
  for (const auto &[k, _] : headers()) out.push_back(k);
  return out;
}

}  // namespace revkit::cparse::detail
