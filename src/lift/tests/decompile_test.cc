// Decompiling under given inputs (decomp_inputs.hh, decompile.hh) and the
// Ghidra-compatible behaviour of ImageArchitecture.

#include "builders.hh"

#include "revkit/lift/decomp_inputs.hh"
#include "revkit/lift/decompile.hh"
#include "revkit/lift/image_arch.hh"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include "funcdata.hh"

#include <memory>
#include <sstream>

namespace revkit::lift {
namespace {

using loader::Image;
using testing::ElfBuilder;
using testing::to_bytes;

constexpr std::uint64_t kText = 0x1000, kData = 0x2000, kRodata = 0x3000;

// x86-64 code:
//   0x1000 caller: mov edi,5; call 0x1010; ret
//   0x1010 callee: mov eax,edi; ret
//   0x1020 global: mov eax,[0x2000]; ret
//   0x1030 string: lea rax,[rip+0x1fc9] (0x3000); ret
//   0x1040 bad:    jmp 0x9000 (unmapped)
//   0x1050 nonascii: lea rax,[rip+...] (0x3010); ret
std::vector<std::uint8_t> program_text() {
  std::vector<std::uint8_t> t(0x60, 0xcc);
  auto put = [&](std::size_t at, std::initializer_list<std::uint8_t> bytes) {
    for (std::uint8_t b : bytes) t[at++] = b;
  };
  put(0x00, {0xbf, 0x05, 0x00, 0x00, 0x00, 0xe8, 0x06, 0x00, 0x00, 0x00, 0xc3});
  put(0x10, {0x89, 0xf8, 0xc3});
  put(0x20, {0x8b, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, 0xc3});
  put(0x30, {0x48, 0x8d, 0x05, 0xc9, 0x1f, 0x00, 0x00, 0xc3});  // 0x1037 + 0x1fc9 = 0x3000
  put(0x40, {0xe9, 0xbb, 0x7f, 0x00, 0x00});                     // 0x1045 + 0x7fbb = 0x9000
  put(0x50, {0x48, 0x8d, 0x05, 0xb9, 0x1f, 0x00, 0x00, 0xc3});  // 0x1057 + 0x1fb9 = 0x3010
  return t;
}

std::shared_ptr<const Image> program_image() {
  ElfBuilder b({.wide = true, .big = false, .machine = 62, .type = 2, .flags = 0, .entry = kText});
  b.add_load(".text", kText, program_text(), 5);
  b.add_load(".data", kData, std::vector<std::uint8_t>(16, 0), 6);
  std::vector<std::uint8_t> ro(0x20, 0);
  const char hello[] = "hello";
  std::copy(hello, hello + sizeof hello, ro.begin());
  const std::uint8_t bom[] = {0xef, 0xbb, 0xbf, 0};  // UTF-8, not US-ASCII
  std::copy(bom, bom + sizeof bom, ro.begin() + 0x10);
  b.add_load(".rodata", kRodata, ro, 4);
  return std::make_shared<const Image>(loader::parse(to_bytes(b.build())));
}

DecompElement typeref(const std::string &name, std::uint64_t id) {
  return {"typeref", {{"name", name}, {"id", id}}, {}};
}
DecompElement int_type() { return typeref("int", 0xc000000000000095ULL); }
DecompElement char_ptr() {
  return {"type",
          {{"name", std::string()}, {"metatype", std::string("ptr")}, {"size", std::int64_t{8}}},
          {typeref("char", 0xc00000000000007bULL)}};
}

FunctionFacts function(std::uint64_t entry, std::string name, std::uint64_t last) {
  FunctionFacts f;
  f.entry = entry;
  f.name = std::move(name);
  f.body = {{entry, last}};
  f.convention = "unknown";
  f.extrapop = 8;
  f.ret.type = {"void", {}, {}};
  f.ret.storage = std::vector<StorageVarnode>{};
  f.ret.void_storage = true;
  return f;
}

// `int callee(int x)`, as Ghidra sends an imported signature.
FunctionFacts typed_callee() {
  FunctionFacts f = function(0x1010, "callee", 0x1012);
  f.signature_source = SignatureSource::imported;
  f.convention = "__stdcall";
  f.ret = {int_type(), false, std::vector<StorageVarnode>{{"register", 0x0, 4}}, false, 4};
  ParamFacts x;
  x.name = "x";
  x.storage = {{"register", 0x38, 4}};  // EDI
  x.type = int_type();
  f.params.push_back(x);
  return f;
}

std::shared_ptr<DecompilerInputs> base_inputs() {
  auto in = std::make_shared<DecompilerInputs>();
  in->functions = {function(0x1000, "caller", 0x100a), typed_callee(), function(0x1020, "load_global", 0x1027),
                   function(0x1030, "string_ptr", 0x1037), function(0x1040, "jumps_away", 0x1044),
                   function(0x1050, "not_ascii", 0x1057)};
  in->functions[3].signature_source = SignatureSource::imported;
  in->functions[3].ret = {char_ptr(), false, std::vector<StorageVarnode>{{"register", 0x0, 8}}, false, 8};
  in->functions[5].signature_source = SignatureSource::imported;
  in->functions[5].ret = in->functions[3].ret;
  in->memory = {{".text", kText, kText + 0x5f, false, true, true, false, false, {}},
                {".data", kData, kData + 0xf, true, false, true, false, false, {}},
                {".rodata", kRodata, kRodata + 0x1f, false, false, true, false, false, {}}};
  return in;
}

class Decompile : public ::testing::Test {
 protected:
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    initialize(REVKIT_GHIDRA_ROOT);
  }

  static DecompileConfig config(std::shared_ptr<const DecompilerInputs> inputs, bool defaults = false) {
    DecompileConfig c;
    c.image = program_image();
    c.language_id = "x86:LE:64:default:gcc";
    c.inputs = std::move(inputs);
    c.default_names = defaults;
    c.default_extrapop = defaults;
    return c;
  }

  static std::string c_of(InputDecompiler &d, std::uint64_t entry) {
    DecompileResult r = d.decompile(entry);
    EXPECT_TRUE(r.ok) << r.error;
    return r.c;
  }
};

TEST_F(Decompile, CoreTypesAreGhidras) {
  auto img = program_image();
  ImageArchitecture gcc(img, "gcc", "x86:LE:64:default:gcc", &std::cerr);
  gcc.init_image();
  auto size_of = [](ImageArchitecture &a, const std::string &name) {
    ghidra::Datatype *t = a.types->findByName(name);
    return t == nullptr ? -1 : t->getSize();
  };
  EXPECT_EQ(size_of(gcc, "undefined1"), 1);
  EXPECT_EQ(size_of(gcc, "undefined"), -1);  // Ghidra's core types have no "undefined"
  EXPECT_EQ(size_of(gcc, "long"), 8);
  EXPECT_EQ(size_of(gcc, "longdouble"), 10);
  EXPECT_EQ(size_of(gcc, "wchar_t"), 4);
  EXPECT_EQ(size_of(gcc, "wchar16"), 2);
  EXPECT_EQ(size_of(gcc, "uint3"), 3);

  ImageArchitecture win(img, "win", "x86:LE:64:default:windows", &std::cerr);
  win.init_image();
  EXPECT_EQ(size_of(win, "longlong"), 8);
  EXPECT_EQ(size_of(win, "long"), -1);
  EXPECT_EQ(size_of(win, "float10"), 10);
  EXPECT_EQ(size_of(win, "wchar_t"), 2);
  // Java never tells the decompiler that long is 4 bytes on LLP64.
  EXPECT_EQ(win.types->getSizeOfLong(), 8);
}

TEST_F(Decompile, RegisterNamesFollowGhidrasJavaSide) {
  ImageArchitecture a(program_image(), "regs", "x86:LE:64:default:gcc", &std::cerr);
  a.init_image();
  ghidra::AddrSpace *reg = a.getSpaceByName("register");
  ASSERT_NE(reg, nullptr);
  EXPECT_EQ(a.translate->getRegisterName(reg, 0x30, 8), "RSI");
  EXPECT_EQ(a.translate->getRegisterName(reg, 0x30, 4), "ESI");
  EXPECT_EQ(a.translate->getRegisterName(reg, 0x30, 1), "SIL");
  EXPECT_EQ(a.translate->getRegisterName(reg, 0x30, 3), "ESI");  // smallest one at least as big
  EXPECT_EQ(a.translate->getRegisterName(reg, 0x34, 4), "");     // inside RSI: no name
  EXPECT_TRUE(a.register_starts_at(ghidra::Address(reg, 0x30)));
  EXPECT_FALSE(a.register_starts_at(ghidra::Address(reg, 0x34)));
}

TEST_F(Decompile, NamesAndSignaturesComeFromTheInputs) {
  InputDecompiler d(config(base_inputs()));
  EXPECT_TRUE(d.warnings().empty());
  const std::string caller = c_of(d, 0x1000);
  EXPECT_NE(caller.find("callee(5)"), std::string::npos) << caller;
  const std::string callee = c_of(d, 0x1010);
  EXPECT_NE(callee.find("int callee(int x)"), std::string::npos) << callee;
  EXPECT_NE(callee.find("return x;"), std::string::npos) << callee;
}

TEST_F(Decompile, EachFunctionStartsFromTheSameState) {
  InputDecompiler d(config(base_inputs()));
  const std::string first = c_of(d, 0x1000);
  c_of(d, 0x1010);
  c_of(d, 0x1020);
  EXPECT_EQ(c_of(d, 0x1000), first);
}

TEST_F(Decompile, DataSymbolsAndDefaultNames) {
  // With Ghidra's symbols: the global's name and type.
  auto in = base_inputs();
  DataFacts counter;
  counter.addr = kData;
  counter.name = "counter";
  counter.length = 4;
  counter.type = int_type();
  in->data.push_back(counter);
  InputDecompiler named(config(in));
  EXPECT_NE(c_of(named, 0x1020).find("return counter;"), std::string::npos);

  // Without: Ghidra's default name for referenced data.
  InputDecompiler defaults(config(base_inputs(), true));
  EXPECT_NE(c_of(defaults, 0x1020).find("DAT_00002000"), std::string::npos) << c_of(defaults, 0x1020);
}

TEST_F(Decompile, StringsDecodeAsJavaDoes) {
  InputDecompiler d(config(base_inputs()));
  EXPECT_NE(c_of(d, 0x1030).find("return \"hello\";"), std::string::npos) << c_of(d, 0x1030);
  // A UTF-8 byte-order mark isn't US-ASCII: not printed as a string.
  const std::string bom = c_of(d, 0x1050);
  EXPECT_EQ(bom.find('"'), std::string::npos) << bom;
}

TEST_F(Decompile, UnreadableCodeIsBadData) {
  InputDecompiler d(config(base_inputs()));
  const std::string c = c_of(d, 0x1040);
  EXPECT_NE(c.find("halt_baddata"), std::string::npos) << c;
  EXPECT_NE(c.find("Bad instruction"), std::string::npos) << c;
}

TEST_F(Decompile, CommentsFollowTheWarningsInTheHeader) {
  auto in = base_inputs();
  in->comments.push_back({0x1040, CommentFacts::plate, "plate text"});
  InputDecompiler d(config(in));
  const std::string c = c_of(d, 0x1040);
  const auto warning = c.find("WARNING: Control flow encountered bad instruction data");
  const auto plate = c.find("plate text");
  ASSERT_NE(warning, std::string::npos) << c;
  ASSERT_NE(plate, std::string::npos) << c;
  EXPECT_LT(warning, plate);
}

TEST_F(Decompile, ParallelMatchesSerial) {
  auto in = base_inputs();
  std::vector<std::uint64_t> entries;
  for (const FunctionFacts &f : in->functions) entries.push_back(f.entry);
  DecompileConfig serial = config(in);
  serial.threads = 1;
  serial.in_order = true;
  DecompileConfig parallel = config(in);
  parallel.threads = 4;
  DecompileStats stats;
  auto a = decompile_functions(serial, entries);
  auto b = decompile_functions(parallel, entries, &stats);
  EXPECT_EQ(stats.threads, 4u);
  ASSERT_EQ(a.size(), b.size());
  for (std::size_t i = 0; i < a.size(); ++i) {
    EXPECT_EQ(a[i].entry, entries[i]);
    EXPECT_EQ(b[i].entry, entries[i]);
    EXPECT_TRUE(a[i].ok) << a[i].error;
    EXPECT_EQ(a[i].c, b[i].c);
  }
}

TEST_F(Decompile, RunsStopAtTheirLimits) {
  struct Case {
    DecompileLimits limits;
    DecompileStop stop;
    const char *says;
  };
  std::vector<Case> cases(3);
  cases[0].limits.max_varnodes = 1;
  cases[0] = {cases[0].limits, DecompileStop::too_large, "too large"};
  cases[1].limits.timeout_seconds = 1e-9;
  cases[1] = {cases[1].limits, DecompileStop::timeout, "timed out"};
  cases[2].limits.cancelled = [] { return true; };
  cases[2] = {cases[2].limits, DecompileStop::cancelled, "cancelled"};
  const std::string expected = [&] {
    InputDecompiler fresh(config(base_inputs()));
    return c_of(fresh, 0x1000);
  }();
  for (const Case &c : cases) {
    InputDecompiler d(config(base_inputs()));
    RunHooks hooks;
    hooks.limits = &c.limits;
    DecompileResult r = d.decompile(0x1000, &hooks);
    EXPECT_FALSE(r.ok);
    EXPECT_TRUE(r.c.empty());
    EXPECT_EQ(r.stopped, c.stop);
    EXPECT_NE(r.error.find(c.says), std::string::npos) << r.error;
    EXPECT_TRUE(d.spoiled());
  }
  // Generous limits change nothing.
  DecompileLimits loose;
  loose.timeout_seconds = 600;
  loose.max_varnodes = 1 << 20;
  loose.cancelled = [] { return false; };
  InputDecompiler d(config(base_inputs()));
  RunHooks hooks;
  hooks.limits = &loose;
  DecompileResult r = d.decompile(0x1000, &hooks);
  EXPECT_TRUE(r.ok) << r.error;
  EXPECT_EQ(r.c, expected);
  EXPECT_GT(r.varnodes, 0u);
  EXPECT_FALSE(d.spoiled());
}

TEST_F(Decompile, WholeProgramRunsWithinItsBounds) {
  auto in = base_inputs();
  std::vector<std::uint64_t> entries;
  for (const FunctionFacts &f : in->functions) entries.push_back(f.entry);
  DecompileConfig plain = config(in);
  plain.threads = 2;
  const auto expected = decompile_functions(plain, entries);

  // Every run over its bound: each reports it, and a new instance takes
  // the next function.
  DecompileConfig tiny = plain;
  tiny.limits.max_varnodes = 1;
  DecompileStats stats;
  auto stopped = decompile_functions(tiny, entries, &stats);
  EXPECT_EQ(stats.stopped, entries.size());
  EXPECT_EQ(stats.rebuilt, entries.size());
  for (const DecompileResult &r : stopped) EXPECT_EQ(r.stopped, DecompileStop::too_large);

  // A budget too small for even one function: they run one at a time and
  // the output is the same (the varnode bound has a floor).
  DecompileConfig budget = plain;
  budget.threads = 4;
  budget.memory_budget = 1;
  auto bounded = decompile_functions(budget, entries, &stats);
  EXPECT_GT(stats.max_varnodes, 0u);
  ASSERT_EQ(bounded.size(), expected.size());
  for (std::size_t i = 0; i < expected.size(); ++i) {
    EXPECT_EQ(bounded[i].entry, expected[i].entry);
    EXPECT_EQ(bounded[i].c, expected[i].c);
    EXPECT_EQ(bounded[i].stopped, DecompileStop::none);
  }
}

TEST_F(Decompile, EncodingsMatchJava) {
  // HighFunction.encode for a callee: default names unlocked, the
  // prototype's model locked, the parameter typed and mapped to EDI.
  DecompElement e = encode_function_symbol(typed_callee(), 0x1010, false);
  const std::string xml = to_xml(e);
  EXPECT_NE(xml.find("<prototype extrapop=\"8\" model=\"__stdcall\" modellock=\"true\">"), std::string::npos) << xml;
  EXPECT_NE(xml.find("name=\"x\" typelock=\"true\" namelock=\"true\" merge=\"false\" cat=\"0\" index=\"0x0\""),
            std::string::npos)
      << xml;
  EXPECT_NE(xml.find("<addr space=\"register\" offset=\"0x38\" size=\"4\"/>"), std::string::npos) << xml;
  EXPECT_NE(xml.find("<returnsym typelock=\"true\">"), std::string::npos) << xml;
  // A default-named parameter is name-locked only for the function itself.
  FunctionFacts f = typed_callee();
  f.params[0].name = "param_1";
  EXPECT_NE(to_xml(encode_function_symbol(f, 0x1010, false)).find("namelock=\"false\""), std::string::npos);
  EXPECT_EQ(to_xml(encode_function_symbol(f, 0x1010, true)).find("namelock=\"false\""), std::string::npos);
}

}  // namespace
}  // namespace revkit::lift
