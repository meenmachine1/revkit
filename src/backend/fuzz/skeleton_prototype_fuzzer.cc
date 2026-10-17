// ParseSkeletonPrototype (parse_c.cc): a function prototype as text from a
// BSim database (ApplyBSimMatches' signature), any file an editor
// attaches, parsed as the program's C with every unknown type name made a
// placeholder structure, round after round. The input is the prototype.
// The program is a small raw x86-64 one; set GHIDRA_INSTALL_DIR.
#include "parse_c.h"

#include "revkit/lift/lifter.hh"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

using namespace revkit;

namespace {

std::shared_ptr<backend::Program> g_program;
backend::NamedTypes g_names;

}  // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  const char *root = std::getenv("GHIDRA_INSTALL_DIR");
  if (!root) {
    std::fprintf(stderr, "skeleton_prototype_fuzzer: set GHIDRA_INSTALL_DIR\n");
    std::abort();
  }
  lift::initialize(root);
  backend::Program::Options o;
  o.language_id = "x86:LE:64:default";
  o.compiler_spec_id = "gcc";
  o.debug_info = false;
  o.decompilers = 0;
  loader::RawOptions raw;
  raw.language = o.language_id;
  raw.container = loader::RawContainer::binary;
  o.raw = raw;
  g_program = backend::Program::Load(std::make_shared<loader::Bytes>(64), o);
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  const std::string decl(reinterpret_cast<const char *>(data), size);
  backend::ParseCContext c{*g_program, g_names, [](const std::string &) { return backend::TypeClosure{}; }, {}};
  std::vector<std::string> placeholders;
  std::string error;
  (void)backend::ParseSkeletonPrototype(c, decl, &placeholders, &error);
  return 0;
}
