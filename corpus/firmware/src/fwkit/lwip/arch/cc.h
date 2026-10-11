/* lwIP's compiler and platform glue for fwkit. */
#ifndef LWIP_ARCH_CC_H
#define LWIP_ARCH_CC_H

#include <stdio.h>
#include <stdlib.h>

#define LWIP_PROVIDE_ERRNO 1
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BYTE_ORDER BIG_ENDIAN
#else
#define BYTE_ORDER LITTLE_ENDIAN
#endif
#define LWIP_NO_INTTYPES_H 1
#define LWIP_NO_UNISTD_H 1
typedef __PTRDIFF_TYPE__ ssize_t;
#define X8_F  "02x"
#define U16_F "u"
#define S16_F "d"
#define X16_F "x"
#define U32_F "lu"
#define S32_F "ld"
#define X32_F "lx"
#define SZT_F "u"

void fw_panic(const char *why) __attribute__((noreturn));
#define LWIP_PLATFORM_DIAG(x) do { printf x; } while (0)
#define LWIP_PLATFORM_ASSERT(x) fw_panic(x)
#endif
