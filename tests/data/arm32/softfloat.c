// Soft float (-mfloat-abi=soft): clang calls the runtime's __aeabi_*
// helpers (rt.c) for every operation, passing floats in core registers.
#include "kit.h"

float lerpf(float a, float b, float t) { return a + (b - a) * t; }

float scale_avg(const int *v, int n, float k) {
  float s = 0;
  for (int i = 0; i < n; i++) s += (float)v[i];
  return n ? s * k / (float)n : 0.0f;
}

int to_fixed(float f) { return (int)(f * 256.0f); }
