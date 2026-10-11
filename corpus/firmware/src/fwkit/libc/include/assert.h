#ifndef FWKIT_ASSERT_H
#define FWKIT_ASSERT_H
void fw_assert_failed(const char *expr, const char *file, int line) __attribute__((noreturn));
#ifdef NDEBUG
#define assert(x) ((void)0)
#else
#define assert(x) ((x) ? (void)0 : fw_assert_failed(#x, __FILE__, __LINE__))
#endif
#endif
