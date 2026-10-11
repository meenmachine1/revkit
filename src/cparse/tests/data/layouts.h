/* Layout cases for the C parser, checked against clang's record layouts on
 * every target (clang_oracle.py, with -DREVKIT_WITH_CLANG=ON) and against
 * values pinned in cparse_test.cc. Only the built-in headers are used. */
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct s_basic { char c; short s; int i; long l; long long ll; float f; double d; void *p; };
struct s_ld { char c; long double ld; };
struct s_bool { _Bool b; char c; bool b2; };
struct s_arr { char name[13]; int vals[3][4]; short tail; };
struct s_flex { int n; char data[]; };
struct s_flex_aligned { char c; double d[]; };
struct s_nested { struct s_basic b; char after; };
struct s_last_char { long long l; char c; };
struct s_wide_arr { short s; long long a[2]; };

struct s_bits1 { unsigned a : 1, b : 2, c : 3; unsigned d : 26; unsigned e : 1; };
struct s_bits2 { char c; int x : 4; int y : 28; char d; };
struct s_bits3 { unsigned char a : 3; unsigned short b : 9; unsigned int c : 17; };
struct s_bits4 { int a : 5; int : 0; int b : 3; };
struct s_bits5 { char a; int : 0; char b; };
struct s_bits6 { long long a : 33; long long b : 31; char c; };
struct s_bits7 { unsigned a : 30; unsigned b : 4; };
struct s_bits8 { short a : 9; char b : 7; short c; };
struct s_bits9 { char a : 4; short b : 12; int c : 20; long long d : 40; };
struct s_bits10 { int a : 3; unsigned : 5; int b : 7; };
enum e_small { ES_A, ES_B };
struct s_bits11 { _Bool a : 1; _Bool b : 1; enum e_small e : 2; };
struct s_bits12 { char a : 7; char b : 2; };
struct s_bits13 { char a : 4; int b : 4; char c : 4; };
struct s_bits14 { unsigned short a : 4; unsigned int b : 4; unsigned short c : 12; };
struct s_bits15 { char c; long long a : 60; };

union u_mixed { char c[5]; int i; double d; };
union u_bits { int a : 3; unsigned b : 20; char c; };

struct s_anon { int a; union { int b; float c; }; struct { char d; short e; }; int f; };
struct s_anon_named { int a; struct { char x; double y; } inner; char z; };

struct s_packed { char c; int i; short s; } __attribute__((packed));
struct __attribute__((packed)) s_packed2 { char c; long long ll; };
struct s_packed_member { char c; int i __attribute__((packed)); char d; };
struct s_aligned { char c; int i __attribute__((aligned(16))); };
struct s_aligned2 { char c; } __attribute__((aligned(8)));
struct s_aligned3 { char c; struct s_aligned2 a; char d; };
struct s_packed_bits { char a; int b : 12; int c : 20; } __attribute__((packed));
struct s_packed_aligned { char c; int i; } __attribute__((packed, aligned(2)));

#pragma pack(push, 1)
struct s_pack1 { char c; int i; double d; short s; };
#pragma pack(pop)
#pragma pack(push, 2)
struct s_pack2 { char c; int i; double d; };
#pragma pack(pop)
#pragma pack(4)
struct s_pack4 { char c; double d; long long ll; };
#pragma pack()
#pragma pack(push, 1)
struct s_pack1_bits { char a; int b : 4; int c : 20; char d; };
#pragma pack(pop)

struct s_fptr {
  int (*cb)(int, const char *);
  void (*arr[3])(void);
  struct s_fptr *(*next)(struct s_fptr *);
};
struct s_va { va_list ap; int n; };

enum e_neg { EN_A = -1, EN_B = 1 };
enum e_big { EB_A = 0x7fffffff };
struct s_enum { enum e_neg n; enum e_big b; char c; };

typedef struct { int x; char y; } t_anon;
struct s_typedefs { t_anon a; size_t sz; ptrdiff_t pd; uint8_t u8; int64_t i64; intptr_t ip; wchar_t wc; };
struct s_complex { char c; _Complex float cf; _Complex double cd; };
struct s_ptrs { const char *const *argv; volatile int *vi; char *restrict r; };
struct s_max_align { char c; max_align_t m; };

typedef float v4f __attribute__((vector_size(16)));
typedef int v2i __attribute__((vector_size(8)));
struct s_vec { char c; v4f v; v2i w; };
struct s_zero_len { int n; char z[0]; };
struct s_aligned_noarg { char c; } __attribute__((aligned));
union u_ld { char c; long double ld; };
struct s_anon_bits { int a; struct { unsigned x : 3, y : 5; }; char b; };
struct s_arr_of_struct { struct s_last_char items[3]; char tail; };
struct s_enum_bits { enum e_neg n : 2; enum e_small s : 3; int rest : 27; };

#ifdef __SIZEOF_INT128__
struct s_int128 { char c; __int128 x; unsigned __int128 y; };
#endif

/* Sizes the parser must agree with (a failed assertion is an error). */
_Static_assert(sizeof(struct s_basic) == 48 || sizeof(void *) != 8 || sizeof(long) != 8, "s_basic on LP64");
_Static_assert(offsetof(struct s_arr, tail) == 64, "s_arr.tail");
_Static_assert(sizeof(struct s_flex) == sizeof(int), "flexible array adds nothing");
