__declspec(dllexport) __attribute__((noinline)) int crash_here(int *p, int v) { *p = v; return v + 1; }
__declspec(dllexport) __attribute__((noinline)) int caller(int *p) { return crash_here(p, 7) * 2; }
int main(void) { return caller((int *)0); }
