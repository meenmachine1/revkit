#include "features.h"

static unsigned popcount32(uint32_t x)
{
    x = x - ((x >> 1) & 0x55555555u);
    x = (x & 0x33333333u) + ((x >> 2) & 0x33333333u);
    return (((x + (x >> 4)) & 0x0f0f0f0fu) * 0x01010101u) >> 24;
}

static uint32_t rotl32(uint32_t x, unsigned r) { return (x << (r & 31)) | (x >> ((32 - r) & 31)); }

static uint32_t reverse_bits(uint32_t x)
{
    uint32_t r = 0;
    for (int i = 0; i < 32; i++) {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    return r;
}

static uint32_t crc_table[256];

static void crc_init(void)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? 0xedb88320u ^ (c >> 1) : c >> 1;
        crc_table[i] = c;
    }
}

static uint32_t crc32_buf(const unsigned char *p, size_t n)
{
    uint32_t c = 0xffffffffu;
    if (!crc_table[1])
        crc_init();
    while (n--)
        c = crc_table[(c ^ *p++) & 0xff] ^ (c >> 8);
    return c ^ 0xffffffffu;
}

static uint64_t bswap64(uint64_t x)
{
    x = ((x & 0x00ff00ff00ff00ffull) << 8) | ((x >> 8) & 0x00ff00ff00ff00ffull);
    x = ((x & 0x0000ffff0000ffffull) << 16) | ((x >> 16) & 0x0000ffff0000ffffull);
    return (x << 32) | (x >> 32);
}

static int64_t div_mix(int64_t a, int64_t b, uint64_t c, uint64_t d)
{
    if (b == 0 || d == 0)
        return 0;
    return a / b + a % b + (int64_t)(c / d) + (int64_t)(c % d) + a / 7 + (int64_t)(c % 10);
}

static uint64_t mulhi64(uint64_t a, uint64_t b)
{
    unsigned __int128 p = (unsigned __int128)a * b;
    return (uint64_t)(p >> 64);
}

static int clz_loop(uint64_t x)
{
    int n = 0;
    if (!x)
        return 64;
    while (!(x & (1ull << 63))) {
        x <<= 1;
        n++;
    }
    return n;
}

static int8_t sat_add8(int8_t a, int8_t b)
{
    int s = a + b;
    return (int8_t)(s > 127 ? 127 : s < -128 ? -128 : s);
}

uint32_t run_bits(int n)
{
    unsigned char buf[64];
    for (int i = 0; i < 64; i++)
        buf[i] = (unsigned char)(i * n + 3);
    uint32_t h = crc32_buf(buf, sizeof(buf));
    h += popcount32(h) + rotl32(h, (unsigned)n) + reverse_bits((uint32_t)n);
    uint64_t big = bswap64(0x0123456789abcdefull * (uint64_t)n);
    h ^= (uint32_t)big ^ (uint32_t)(big >> 32);
    h += (uint32_t)div_mix(-1000003LL * n, n + 3, 0xfedcba9876543210ull, (uint64_t)n + 1);
    h += (uint32_t)mulhi64(0x9e3779b97f4a7c15ull, (uint64_t)n * 0x1234567ull);
    h += (uint32_t)clz_loop((uint64_t)n << 20) + (uint32_t)sat_add8((int8_t)(n * 50), 100);
    h += (uint32_t)((int16_t)(n * 3000) >> 3) + ((uint32_t)(uint16_t)(n * 3000) >> 3);
    return h;
}
