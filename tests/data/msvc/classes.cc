// A freestanding MSVC-ABI C++ program for revkit's PE and RTTI tests
// (src/msvc/tests, src/backend/tests/msvc_test.cc), built at test time with
// clang in cl mode and lld-link for x86_64-pc-windows-msvc and
// i686-pc-windows-msvc, without a Windows SDK or CRT:
//
//   clang --driver-mode=cl --target=<arch>-pc-windows-msvc /GR /EHsc /GS
//         /O1 /Zi /guard:cf,nochecks /c classes.cc
//   lld-link /nodefaultlib /entry:start /debug /guard:cf /map ...
//
// What the CRT would provide is in runtime.cc. This has RTTI with single,
// multiple and virtual inheritance and a template, virtual calls,
// try/catch, __try/__except (x64), a /GS cookie check and a TLS callback.

typedef decltype(sizeof 0) size_t;
typedef unsigned long long u64;
#if defined(_WIN64)
typedef unsigned long long uintptr;
#else
typedef unsigned int uintptr;
#endif

// ---- classes ----
namespace geo {
struct Shape {
  virtual ~Shape() {}
  virtual int area() const = 0;
  virtual int scale(int k) { return area() * k + id; }
  int id = 1;
};
struct Named {
  virtual const char *name() const { return "named"; }
  virtual int rank() const { return 7; }
};
struct Rect : Shape, Named {
  int w = 2, h = 3;
  int area() const override { return w * h; }
  const char *name() const override { return "rect"; }
};
struct Square : Rect {
  int area() const override { return w * w; }
  int scale(int k) override { return w * k + h; }
};
// Virtual inheritance.
struct Base {
  virtual int get() const { return 1; }
  int b = 0;
};
struct Left : virtual Base {
  int get() const override { return 2; }
  int l = 0;
};
template <class T>
struct Box : Shape {
  T value{};
  int area() const override { return static_cast<int>(value); }
};
}  // namespace geo

struct Error {
  int code;
};

volatile int g_input = 5;

__declspec(noinline) int may_throw(int x) {
  if (x > 100) throw Error{x};
  return x + 1;
}

__declspec(noinline) int guarded(int x) {
  try {
    return may_throw(x);
  } catch (const Error &e) {
    return e.code;
  } catch (...) {
    return -1;
  }
}

#if defined(_WIN64)
extern "C" int rk_read(int *p);  // runtime.cc: opaque, so the __try stays
__declspec(noinline) int filtered(int *p) {
  __try {
    return rk_read(p);
  } __except (1) {
    return -2;
  }
}
#endif

// A /GS cookie check: a local array whose address escapes.
__declspec(noinline) int cookie_user(int n) {
  char buf[64];
  for (int i = 0; i < 64; ++i) buf[i] = static_cast<char>(n + i);
  volatile char *vp = buf;
  return vp[n & 63];
}

// Virtual calls through the vftable.
__declspec(noinline) int call_virtual(geo::Shape *s, int k) { return s->scale(k) + s->area(); }

__declspec(noinline) const char *call_named(geo::Named *n) { return n->name(); }

__declspec(noinline) int call_base(geo::Base *b) { return b->get(); }

static geo::Rect g_rect;
static geo::Square g_square;
static geo::Left g_left;
static geo::Box<int> g_box;
static geo::Base g_base;
// Picked through a volatile index, so no call is devirtualized and every
// class keeps its vftable.
geo::Shape *const g_shapes[] = {&g_rect, &g_square, &g_box};
geo::Base *const g_bases[] = {&g_base, &g_left};

extern "C" {
typedef void(__stdcall *TlsCallback)(void *, unsigned long, void *);
extern TlsCallback rk_tls_callback_ptr;
}

extern "C" int start() {
  geo::Shape *s = g_shapes[(guarded(g_input) & 1) + g_input % 2];
  int r = call_virtual(s, g_input) + (dynamic_cast<geo::Named *>(s) != nullptr);
  r += call_base(g_bases[g_input & 1]) + cookie_user(g_input);
  r += call_named(&g_rect)[0];
#if defined(_WIN64)
  r += filtered(const_cast<int *>(&g_input));
#endif
  r += reinterpret_cast<uintptr>(rk_tls_callback_ptr) != 0;
  return r;
}
