/* The program revkit's script tests and starter scripts run over
   (sdk/python/tests/test_scripting.py, test_starter_scripts.py): strings
   naming their functions, crypto constants, an XOR-encrypted string and its
   decryptor, format-string sinks, a raw syscall and unreferenced data. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

const uint32_t sha256_iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                               0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
const unsigned char aes_sbox[32] = {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
                                    0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
                                    0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0};
__attribute__((used)) static const char unused_message[] = "this string is never referenced";
/* "hello secret" XOR 0x5a */
unsigned char secret[12] = {0x32, 0x3f, 0x36, 0x36, 0x35, 0x7a, 0x29, 0x3f, 0x39, 0x28, 0x3f, 0x2e};

__attribute__((noinline)) void decrypt(unsigned char *p, int n) {
  for (int i = 0; i < n; i++) p[i] ^= 0x5a;
}
__attribute__((noinline)) int parse_config(const char *s) {
  if (!s) {
    fprintf(stderr, "parse_config: missing value\n");
    return -1;
  }
  return (int)strlen(s);
}
__attribute__((noinline)) int open_database(const char *s) {
  if (!s[0]) {
    fprintf(stderr, "open_database: empty path\n");
    return -1;
  }
  return s[0];
}
__attribute__((noinline)) void log_user(const char *msg) { printf(msg); }
__attribute__((noinline)) void log_safe(const char *msg) { printf("[%s]\n", msg); }
__attribute__((noinline)) long raw_getpid(void) {
  long r;
  __asm__ volatile("mov $39, %%eax\n\tsyscall" : "=a"(r) : : "rcx", "r11", "memory");
  return r;
}
__attribute__((noinline)) uint32_t mix(uint32_t x) { return x ^ sha256_iv[x & 7] ^ aes_sbox[x & 31]; }

int main(int argc, char **argv) {
  decrypt(secret, (int)sizeof secret);
  log_user(argv[0]);
  log_safe((const char *)secret);
  return parse_config(argc > 1 ? argv[1] : 0) + open_database(argv[0]) + (int)raw_getpid() + (int)mix((uint32_t)argc);
}
