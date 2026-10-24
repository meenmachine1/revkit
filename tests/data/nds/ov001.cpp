#include "game.h"

// Shares ov000's address range: only one of them is loaded at a time.
extern "C" int TitleTick(int t) { return Clamp(t * 2, 0, 255) + kRetryItems[0]; }
extern "C" int TitleBlend(int a, int b) { return ItcmMix(a, b) - gFrameCount; }
