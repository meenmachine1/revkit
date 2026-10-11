// What the CRT would provide for classes.cc (tests/data/msvc/build.sh),
// in its own object so the compiler can't see through it: type_info's
// vftable, the C++ exception runtime (stubs: nothing throws at run time,
// the binary is only analysed), the security cookie and its check, the
// load config with the Control Flow Guard table, and TLS with one callback.

typedef decltype(sizeof 0) size_t;
typedef unsigned long long u64;
#if defined(_WIN64)
typedef unsigned long long uintptr;
#else
typedef unsigned int uintptr;
#endif

// ---- what the CRT provides ----
class type_info {
 public:
  virtual ~type_info();
 private:
  void *data_;
  char name_[1];
};
type_info::~type_info() {}
void *rk_type_info_vftable[2] asm("??_7type_info@@6B@") = {nullptr, nullptr};

extern "C" {
int _fltused = 0;
void *__RTDynamicCast(void *p, long, void *, void *, int) { return p; }
int atexit(void (*)()) { return 0; }
void __std_terminate() { for (;;) {} }
int __CxxFrameHandler3(void *, void *, void *, void *) { return 0; }
void __stdcall _CxxThrowException(void *, void *) { for (;;) {} }
int __C_specific_handler(void *, void *, void *, void *) { return 0; }
#if !defined(_WIN64)
int _except_handler3(void *, void *, void *, void *) { return 0; }
int _except_handler4(void *, void *, void *, void *) { return 0; }
#endif
void *memset(void *d, int c, size_t n) {
  for (size_t i = 0; i < n; ++i) static_cast<volatile char *>(d)[i] = static_cast<char>(c);
  return d;
}
uintptr __security_cookie = static_cast<uintptr>(0x2B992DDFA232ULL);
#if defined(_WIN64)
void __security_check_cookie(uintptr c) {
  if (c != __security_cookie) for (;;) {}
}
#else
void __fastcall __security_check_cookie(uintptr c) {
  if (c != __security_cookie) for (;;) {}
}
#endif
void __guard_check_icall_nop(uintptr) {}
void *__guard_check_icall_fptr = reinterpret_cast<void *>(&__guard_check_icall_nop);
void *__guard_dispatch_icall_fptr = reinterpret_cast<void *>(&__guard_check_icall_nop);
}
extern "C" int rk_read(int *p) { return *p; }
void operator delete(void *, size_t) noexcept {}
void operator delete(void *) noexcept {}

// ---- the load config (what the CRT's loadcfg.c defines) ----
extern "C" {
extern void *__guard_fids_table;
extern unsigned long __guard_fids_count;
#if defined(_WIN64)
struct LoadConfig {
  unsigned Size, TimeDateStamp;
  unsigned short MajorVersion, MinorVersion;
  unsigned GlobalFlagsClear, GlobalFlagsSet, CriticalSectionDefaultTimeout;
  u64 DeCommitFreeBlockThreshold, DeCommitTotalFreeThreshold, LockPrefixTable, MaximumAllocationSize,
      VirtualMemoryThreshold, ProcessAffinityMask;
  unsigned ProcessHeapFlags;
  unsigned short CSDVersion, DependentLoadFlags;
  u64 EditList, SecurityCookie, SEHandlerTable, SEHandlerCount, GuardCFCheckFunctionPointer,
      GuardCFDispatchFunctionPointer, GuardCFFunctionTable, GuardCFFunctionCount;
  unsigned GuardFlags;
};
#else
struct LoadConfig {
  unsigned Size, TimeDateStamp;
  unsigned short MajorVersion, MinorVersion;
  unsigned GlobalFlagsClear, GlobalFlagsSet, CriticalSectionDefaultTimeout, DeCommitFreeBlockThreshold,
      DeCommitTotalFreeThreshold, LockPrefixTable, MaximumAllocationSize, VirtualMemoryThreshold, ProcessHeapFlags,
      ProcessAffinityMask;
  unsigned short CSDVersion, DependentLoadFlags;
  unsigned EditList, SecurityCookie, SEHandlerTable, SEHandlerCount, GuardCFCheckFunctionPointer,
      GuardCFDispatchFunctionPointer, GuardCFFunctionTable, GuardCFFunctionCount, GuardFlags;
};
#endif
extern const LoadConfig _load_config_used = {
    sizeof(LoadConfig), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    reinterpret_cast<uintptr>(&__security_cookie), 0, 0,
    reinterpret_cast<uintptr>(&__guard_check_icall_fptr), reinterpret_cast<uintptr>(&__guard_dispatch_icall_fptr),
    reinterpret_cast<uintptr>(&__guard_fids_table), reinterpret_cast<uintptr>(&__guard_fids_count),
    0x500 /* CF_INSTRUMENTED | CF_FUNCTION_TABLE_PRESENT */};
}

// ---- TLS: one callback ----
extern "C" {
unsigned long _tls_index = 0;
#pragma section(".tls", read, write)
#pragma section(".tls$ZZZ", read, write)
__declspec(allocate(".tls")) char _tls_start = 0;
__declspec(allocate(".tls$ZZZ")) char _tls_end = 0;
#pragma section(".CRT$XLA", read)
#pragma section(".CRT$XLB", read)
#pragma section(".CRT$XLZ", read)
typedef void(__stdcall *TlsCallback)(void *, unsigned long, void *);
__declspec(allocate(".CRT$XLA")) TlsCallback __xl_a = nullptr;
__declspec(allocate(".CRT$XLZ")) TlsCallback __xl_z = nullptr;
volatile int tls_seen = 0;
void __stdcall rk_tls_callback(void *, unsigned long reason, void *) { tls_seen = static_cast<int>(reason); }
__declspec(allocate(".CRT$XLB")) TlsCallback rk_tls_callback_ptr = rk_tls_callback;
struct TlsDirectory {
  uintptr StartAddressOfRawData, EndAddressOfRawData, AddressOfIndex, AddressOfCallBacks;
  unsigned SizeOfZeroFill, Characteristics;
};
extern const TlsDirectory _tls_used = {reinterpret_cast<uintptr>(&_tls_start), reinterpret_cast<uintptr>(&_tls_end),
                                       reinterpret_cast<uintptr>(&_tls_index),
                                       reinterpret_cast<uintptr>(&__xl_a + 1), 0, 0};
}

