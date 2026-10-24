#include "game.h"

int gFrameCount;              // .bss
SceneBase *gScene;            // .bss
int gSeed = 0x1234;           // .data
const int kRetryItems[4] = {3, 1, 4, 1};  // .rodata

// The SDK's module parameters: make_fixture.py fills them in (nitrocode).
extern "C" __attribute__((used, section(".rodata.params"))) volatile unsigned int _start_ModuleParams[9] = {0};

void operator delete(void *) noexcept {}
void operator delete(void *, unsigned int) noexcept {}

SceneBase::SceneBase() : frame(0), flags(1) {}
SceneBase::~SceneBase() { flags = 0; }
void SceneBase::Update() { ++frame; }
void SceneBase::Draw(int layer) { flags |= 1 << layer; }

int Clamp(int v, int lo, int hi) { return v < lo ? lo : v > hi ? hi : v; }

__attribute__((target("thumb"), noinline)) int ThumbChecksum(const unsigned char *p, int n) {
  int s = 0;
  for (int i = 0; i < n; ++i) s = (s << 1) ^ p[i];
  return s;
}

float Lerp(float a, float b, float t) { return _fadd(a, _fmul(_fsub(b, a), t)); }

// Stand-ins for the runtime's soft-float and division helpers, under the
// names CodeWarrior's code calls (the arithmetic is not IEEE: only the
// calls matter here, and real float operators would call clang's runtime).
// Not inlined: a game calls the runtime's, which are in a library.
union FloatBits {
  float f;
  unsigned int u;
};
extern "C" __attribute__((noinline)) float _fadd(float a, float b) {
  FloatBits x{a}, y{b};
  x.u += y.u;
  return x.f;
}
extern "C" __attribute__((noinline)) float _fsub(float a, float b) {
  FloatBits x{a}, y{b};
  x.u -= y.u;
  return x.f;
}
extern "C" __attribute__((noinline)) float _fmul(float a, float b) {
  FloatBits x{a}, y{b};
  x.u ^= y.u;
  return x.f;
}
extern "C" __attribute__((noinline)) float _fdiv(float a, float b) {
  FloatBits x{a}, y{b};
  x.u = (x.u >> 1) + (y.u >> 2);
  return x.f;
}
extern "C" __attribute__((noinline)) int _s32_div_f(int a, int b) {
  if (b == 0) return 0;
  int q = 0;
  for (unsigned int n = a < 0 ? -a : a, d = b < 0 ? -b : b; n >= d; n -= d) ++q;
  return (a < 0) != (b < 0) ? -q : q;
}

extern "C" void NitroMain() {
  static unsigned char buf[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  gFrameCount = Clamp(gSeed, 0, 100) + ThumbChecksum(buf, 8) + ItcmMix(gFrameCount, 3);
  if (gScene) gScene->Update();
}
