#include "builders.hh"
#include "decompiler.h"

#include "revkit/inputs/inputs.h"
#include "revkit/lift/decompile.hh"
#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include <algorithm>
#include <deque>
#include <filesystem>
#include <map>
#include <set>
#include <iostream>
#include <thread>

namespace revkit::backend {
namespace {

std::string Text(const pb::DecompiledFunction &f) {
  std::string out;
  for (const auto &line : f.lines()) {
    if (!line.tokens().empty()) out.append(2 * line.indent(), ' ');
    for (const auto &t : line.tokens()) out += t.text();
    out += '\n';
  }
  return out;
}

// revkit::inputs' facts for the file, with renames laid over them: what
// the backend's QueryLookup answers, without the store. It records every
// address looked up.
class StaticLookup final : public RunLookup {
 public:
  explicit StaticLookup(std::shared_ptr<const lift::DecompilerInputs> in)
      : inputs_(in), index_(lift::lookup_inputs(std::move(in))) {}
  std::map<std::uint64_t, std::string> names;  // overrides
  std::set<std::uint64_t> looked_up;

  void freeze(bool) override {}
  std::vector<std::uint64_t> take_late() override { return {}; }
  bool says_anything(std::uint64_t) override { return false; }
  void prefetch(std::uint64_t) override {}
  std::vector<std::uint64_t> touched() const override { return {looked_up.begin(), looked_up.end()}; }

  const lift::FunctionFacts *function_at(std::uint64_t e) override {
    looked_up.insert(e);
    return renamed(index_->function_at(e));
  }
  std::optional<Body> body_containing(std::uint64_t a) override {
    looked_up.insert(a);
    auto b = index_->body_containing(a);
    if (b) b->function = renamed(b->function);
    return b;
  }
  const lift::DataFacts *data_containing(const std::string &s, std::uint64_t a) override {
    return index_->data_containing(s, a);
  }
  const lift::ExternalRefFacts *external_at(const std::string &s, std::uint64_t a) override {
    return index_->external_at(s, a);
  }
  const lift::LabelFacts *label_at(const std::string &s, std::uint64_t a) override { return index_->label_at(s, a); }
  std::optional<std::string> code_label_at(const std::string &s, std::uint64_t a) override {
    return index_->code_label_at(s, a);
  }
  std::optional<lift::Mutability> block_at(const std::string &s, std::uint64_t a) override {
    return index_->block_at(s, a);
  }
  const lift::DecompElement *type(std::uint64_t id) override { return index_->type(id); }
  std::vector<const lift::CommentFacts *> comments(std::uint64_t e) override { return index_->comments(e); }
  std::vector<std::pair<std::uint64_t, std::string>> flow_overrides(std::uint64_t e) override {
    return index_->flow_overrides(e);
  }
  std::vector<lift::TrackedFacts> tracked(std::uint64_t e) override { return index_->tracked(e); }
  void reset() override { owned_.clear(); }

 private:
  const lift::FunctionFacts *renamed(const lift::FunctionFacts *f) {
    if (f == nullptr) return f;
    auto n = names.find(f->entry);
    if (n == names.end()) return f;
    lift::FunctionFacts &copy = owned_.emplace_back(*f);
    copy.name = n->second;
    copy.label.clear();
    return &copy;
  }

  std::shared_ptr<const lift::DecompilerInputs> inputs_;
  std::unique_ptr<lift::FactLookup> index_;
  std::deque<lift::FunctionFacts> owned_;
};

struct Loaded {
  std::shared_ptr<const loader::Image> image;
  std::string language;
  std::shared_ptr<const lift::DecompilerInputs> inputs;
  ImageInputs base;

  DecompilerPool::Config config(unsigned instances = 1) const {
    DecompilerPool::Config c;
    c.image = image;
    c.language_id = language;
    c.max_instances = instances;
    return c;
  }
  StaticLookup lookup() const { return StaticLookup(inputs); }
  std::uint64_t entry(const std::string &name) const {
    for (const auto &f : inputs->functions)
      if (f.name == name) return f.entry;
    return 0;
  }
};

Loaded Load(const std::filesystem::path &path) {
  Loaded l;
  l.image = std::make_shared<const loader::Image>(
      loader::load_file(path, {.image_base = std::nullopt, .ghidra_image_base = true, .macho_slice = {}}));
  auto lang = loader::guess_language(*l.image);
  l.language = lang->id();
  auto analysis = inputs::analyze(*l.image, l.language);
  inputs::Program program{l.image, l.language, analysis.get(), inputs::read_debug_info(*l.image, path)};
  auto in = std::make_shared<lift::DecompilerInputs>(inputs::assemble(program));
  l.base = {in->address_prefix, in->patches, in->synthesized_memory, in->memory};
  l.inputs = std::move(in);
  return l;
}

class Decompiler : public ::testing::Test {
 protected:
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    lift::initialize(REVKIT_GHIDRA_ROOT);
  }
};

constexpr const char *kProgram = R"(
#include <stdio.h>
int counter;
__attribute__((noinline)) int checksum(const unsigned char *p, int n) {
  unsigned h = 0x811c9dc5;
  for (int i = 0; i < n; i++) h = (h ^ p[i]) * 0x1000193;
  counter++;
  return (int)h;
}
int main(int argc, char **argv) {
  int r = checksum((const unsigned char *)argv[0], argc);
  printf("%d\n", r);
  return r;
}
)";

TEST_F(Decompiler, TokensMapToAddressesAndVariables) {
  auto dir = testing::scratch_dir("backend-decompile");
  auto exe = dir / "prog";
  if (!testing::compile(REVKIT_TEST_CC, kProgram, "-O1", exe)) GTEST_SKIP() << "no C compiler";
  Loaded l = Load(exe);
  DecompilerPool pool(l.config());
  std::uint64_t main_entry = l.entry("main"), checksum = l.entry("checksum");
  ASSERT_NE(main_entry, 0u);
  ASSERT_NE(checksum, 0u);

  DecompileInputs in;
  in.entry = main_entry;
  in.exists = true;
  StaticLookup symbols = l.lookup();
  DecompileOutput out = pool.Decompile(in, l.base, symbols);
  const auto &f = out.function;
  std::string text = Text(f);
  std::cout << text;
  EXPECT_TRUE(f.warnings().empty()) << f.warnings(0);
  EXPECT_NE(text.find("checksum("), std::string::npos);
  EXPECT_NE(f.prototype().c_declaration().find("main("), std::string::npos);
  // Its own entry and the callee are among the lookups it reports, which
  // the bundle answered: the decompiler asked only what the parent looked
  // up (and the parent looked up a little more, predicting).
  EXPECT_TRUE(std::binary_search(out.touched.begin(), out.touched.end(), main_entry));
  EXPECT_TRUE(std::binary_search(out.touched.begin(), out.touched.end(), checksum));
  const std::set<std::uint64_t> touched(out.touched.begin(), out.touched.end());
  EXPECT_TRUE(std::includes(symbols.looked_up.begin(), symbols.looked_up.end(), touched.begin(), touched.end()));

  // The call names its target; statement tokens map to instructions.
  bool call = false;
  for (const auto &line : f.lines())
    for (const auto &t : line.tokens())
      if (t.kind() == pb::CODE_TOKEN_KIND_FUNCTION_NAME && t.text() == "checksum") {
        call = true;
        EXPECT_EQ(t.target().offset(), checksum);
        EXPECT_TRUE(t.has_address());
      }
  EXPECT_TRUE(call);
  ASSERT_GE(f.prototype().parameter_indices_size(), 1);
  const auto &param = f.variables(static_cast<int>(f.prototype().parameter_indices(0)));
  EXPECT_EQ(param.kind(), pb::VARIABLE_KIND_PARAMETER);
  EXPECT_EQ(param.storage_key(), "param:0");

  // A rename reaches call sites through the symbol lookups, and reverts:
  // the instance corrects what it applied in the earlier run.
  symbols.names[checksum] = "fnv1a";
  text = Text(pool.Decompile(in, l.base, symbols).function);
  EXPECT_NE(text.find("fnv1a("), std::string::npos) << text;
  symbols.names.clear();
  text = Text(pool.Decompile(in, l.base, symbols).function);
  EXPECT_NE(text.find("checksum("), std::string::npos) << text;

  DecompileInputs c;
  c.entry = checksum;
  c.exists = true;
  c.comments.push_back({checksum, pb::COMMENT_KIND_PLATE, "FNV-1a"});
  auto cs = pool.Decompile(c, l.base, symbols);
  std::cout << Text(cs.function);
  EXPECT_NE(Text(cs.function).find("/* FNV-1a */"), std::string::npos);
  EXPECT_NE(Text(cs.function).find("0x1000193"), std::string::npos);
}

TEST_F(Decompiler, LuaSample) {
  std::filesystem::path lua = std::filesystem::path(REVKIT_CORPUS) / "elf-x86_64/gcc-O2/debug/lua";
  if (!std::filesystem::exists(lua)) GTEST_SKIP() << "corpus not built";
  Loaded l = Load(lua);
  DecompilerPool pool(l.config());
  StaticLookup symbols = l.lookup();
  for (const char *name : {"main", "luaL_newstate", "lua_settop"}) {
    DecompileInputs in;
    in.entry = l.entry(name);
    in.exists = true;
    auto out = pool.Decompile(in, l.base, symbols);
    std::cout << "// " << out.milliseconds << " ms\n" << Text(out.function);
    for (const auto &w : out.function.warnings()) std::cout << "warning: " << w << "\n";
  }
}

}  // namespace
}  // namespace revkit::backend

