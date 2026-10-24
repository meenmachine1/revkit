#include "game.h"

// DTCM data and ITCM code: autoload blocks the ARM9 copies out at start-up.
__attribute__((section(".dtcm"))) int gDtcmTable[4] = {9, 8, 7, 6};

extern "C" __attribute__((section(".itcm"))) int ItcmMix(int a, int b) { return (a * 31) ^ (b + gDtcmTable[b & 3]); }
