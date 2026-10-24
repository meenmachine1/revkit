/* A stand-in for a Flutter app's libapp.so: the four snapshot symbols, the
   data ones starting with Dart's snapshot header (magic f5 f5 dc dc, the
   length, the kind: 3 for full AOT, the 32-character version hash, the
   feature string). */
#include <stdint.h>
struct __attribute__((packed)) header {
  uint32_t magic;
  int64_t length;
  int64_t kind;
  char hash[32];
  char features[128];
  unsigned char body[64];
};
#define HASH "90b56a561f70cd55e972cb49b79b3d8b"
#define FEATURES "product no-code_comments no-dwarf_stack_traces_mode arm64 android compressed-pointers"
__attribute__((used, aligned(32))) const struct header _kDartVmSnapshotData = {
    0xdcdcf5f5u, sizeof(struct header) - 4, 3, HASH, FEATURES, {1}};
__attribute__((used, aligned(32))) const struct header _kDartIsolateSnapshotData = {
    0xdcdcf5f5u, sizeof(struct header) - 4, 3, HASH, FEATURES, {2}};
__attribute__((used, aligned(32))) const unsigned char _kDartVmSnapshotInstructions[64] = {3};
__attribute__((used, aligned(32))) const unsigned char _kDartIsolateSnapshotInstructions[64] = {4};
