/* revkit: the vector types of GCC's own emmintrin.h, which mingw-w64's
   winnt.h includes (the compiler's header, not the C library's; the
   Windows archives need only the types). */
#ifndef REVKIT_EMMINTRIN_H
#define REVKIT_EMMINTRIN_H
typedef float __m128 __attribute__((__vector_size__(16), __aligned__(16)));
typedef double __m128d __attribute__((__vector_size__(16), __aligned__(16)));
typedef long long __m128i __attribute__((__vector_size__(16), __aligned__(16)));
#endif
