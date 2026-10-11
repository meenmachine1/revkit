#include "revkit/inputs/codec.h"
#include "revkit/inputs/inputs.h"
#include "revkit/inputs/library.h"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>

namespace revkit::inputs {
namespace {

namespace fs = std::filesystem;

TEST(ExternalBlock, EmptyForPe) {
  loader::Image image;
  image.format = loader::Format::pe;
  EXPECT_TRUE(external_block(image).empty());
}

TEST(FunctionSets, EntriesAndNoReturn) {
  analysis::FunctionList list;
  for (std::uint64_t e : {0x300u, 0x100u, 0x200u}) {
    analysis::FunctionInfo f;
    f.entry.offset = e;
    f.name = "f";
    f.no_return = e == 0x200 ? analysis::NoReturnReason::named : analysis::NoReturnReason::none;
    list.functions.push_back(f);
  }
  FunctionSets s = function_sets(list);
  EXPECT_EQ(s.entries, (std::vector<std::uint64_t>{0x100, 0x200, 0x300}));
  EXPECT_TRUE(s.is_entry(0x300));
  EXPECT_FALSE(s.is_entry(0x250));
  EXPECT_TRUE(s.is_no_return(0x200));
  EXPECT_FALSE(s.is_no_return(0x100));
  EXPECT_EQ(facts::decode_from_string<FunctionSets>(facts::encode_to_string(s)), s);
}

class Corpus : public ::testing::Test {
 protected:
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    path_ = fs::path(REVKIT_CORPUS_DIR) / "elf-x86_64/gcc-O2/debug/zlib";
    if (!fs::exists(path_)) GTEST_SKIP() << "corpus not built";
    lift::initialize(REVKIT_GHIDRA_ROOT);
    image_ = std::make_shared<const loader::Image>(
        loader::load_file(path_, {.image_base = std::nullopt, .ghidra_image_base = true}));
    language_ = loader::guess_language(*image_)->id();
  }
  fs::path path_;
  std::shared_ptr<const loader::Image> image_;
  std::string language_;
};

// Ghidra's ELF loader puts imported symbols in an EXTERNAL block past the
// image, and relocated GOT slots point into it.
TEST_F(Corpus, ExternalBlockAndRelocatedSlots) {
  ExternalBlock ext = external_block(*image_);
  ASSERT_FALSE(ext.empty());
  std::uint64_t last = 0;
  for (const loader::Block &b : image_->blocks) last = std::max(last, b.start + b.size - 1);
  EXPECT_GT(ext.start, last);
  EXPECT_EQ(ext.start % 0x1000, 0u);
  const ExternalSymbol *memcpy = ext.find("memcpy");
  ASSERT_NE(memcpy, nullptr);
  EXPECT_EQ(ext.at(memcpy->address), memcpy);
  bool slot = false;
  for (const auto &[addr, bytes] : relocation_patches(*image_, ext)) {
    if (bytes.size() != 8) continue;
    std::uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = v << 8 | bytes[i];
    slot |= v == memcpy->address;
  }
  EXPECT_TRUE(slot);
}

// The program's facts with debug info, through the codec unchanged, and a
// function's own facts from its flow.
TEST_F(Corpus, AssembleAndRoundTrip) {
  auto analysis = analyze(*image_, language_);
  Program program{image_, language_, analysis.get(), read_debug_info(*image_, path_)};
  ASSERT_NE(program.debug, nullptr);
  lift::DecompilerInputs in = assemble_program(program);
  auto inflate = std::find_if(in.functions.begin(), in.functions.end(),
                              [](const lift::FunctionFacts &f) { return f.name == "inflate"; });
  ASSERT_NE(inflate, in.functions.end());
  EXPECT_EQ(inflate->params.size(), 2u);
  EXPECT_FALSE(inflate->source_type.empty());
  EXPECT_FALSE(in.types.empty());
  EXPECT_FALSE(in.memory.empty());

  lift::DecompilerInputs back = facts::decode_from_string<lift::DecompilerInputs>(facts::encode_to_string(in));
  EXPECT_EQ(facts::encode_to_string(back), facts::encode_to_string(in));
  EXPECT_EQ(back.functions.size(), in.functions.size());

  const analysis::FunctionList &list = analysis->functions();
  auto f = std::find_if(list.functions.begin(), list.functions.end(),
                        [&](const analysis::FunctionInfo &x) { return x.entry.offset == inflate->entry; });
  ASSERT_NE(f, list.functions.end());
  lift::Lifter lifter(image_, loader::guess_language(*image_)->language);
  FunctionInputs own = assemble_function(program, {}, function_sets(list), *f, analysis->flow(inflate->entry),
                                         inflate->locals, lifter);
  // inflate dispatches on a jump table: its targets get LAB_ labels.
  EXPECT_FALSE(own.code_labels.empty());
  for (const lift::LabelFacts &l : own.code_labels) EXPECT_TRUE(l.name.starts_with("LAB_")) << l.name;
}

// Library prototypes by name: the C runtime's own _init takes none (Ghidra's
// generic_clib gives it OpenSSL's int _init(EVP_PKEY_CTX *ctx)), imports do,
// and nothing ends up locked under an unknown calling convention ("Unknown
// calling convention -- yet parameter storage is locked").
TEST_F(Corpus, CrtFunctionsTakeNoArchivePrototype) {
  auto analysis = analyze(*image_, language_);
  Program program{image_, language_, analysis.get(), read_debug_info(*image_, path_)};
  lift::DecompilerInputs in = assemble_program(program);
  auto init = std::find_if(in.functions.begin(), in.functions.end(),
                           [](const lift::FunctionFacts &f) { return f.name == "_init"; });
  ASSERT_NE(init, in.functions.end());
  EXPECT_EQ(init->signature_source, lift::SignatureSource::default_);
  EXPECT_TRUE(init->params.empty());
  bool import_typed = false;
  auto check = [&](const lift::FunctionFacts &f) {
    if (f.signature_source == lift::SignatureSource::default_) return;
    EXPECT_TRUE(f.convention && *f.convention != "unknown") << f.name;
  };
  for (const lift::FunctionFacts &f : in.functions) {
    check(f);
    import_typed |= f.name == "memcpy" && f.signature_source != lift::SignatureSource::default_;
  }
  for (const lift::ExternalRefFacts &x : in.external_refs)
    if (x.function) {
      check(*x.function);
      import_typed |= x.function->name == "memcpy" && x.function->signature_source != lift::SignatureSource::default_;
    }
  EXPECT_TRUE(import_typed);
  EXPECT_TRUE(crt_function("frame_dummy"));
  EXPECT_FALSE(crt_function("memcpy"));
}

// PointerDataType.getLabelString, then the address.
TEST(PointerName, AsGhidraNamesPointers) {
  SlotNames n;
  n.names = {{0x1000, "FUN_00001000"}, {0x2000, "main"}, {0x3000, "s_hello_00003000"}, {0x9000, "malloc"}};
  n.bodies = {{0x1000, 0x10ff}, {0x2000, 0x20ff}};
  n.pointers = {{0x5000, 0x6000}, {0x6000, 0x5000}, {0x7000, 0x5000}};
  EXPECT_EQ(pointer_name(0x4000, 0x1000, true, n), "PTR_FUN_00004000");     // a default label, cleaned
  EXPECT_EQ(pointer_name(0x4000, 0x2000, true, n), "PTR_main_00004000");    // a symbol, whole
  EXPECT_EQ(pointer_name(0x4000, 0x3000, true, n), "PTR_s_hello_00004000");
  EXPECT_EQ(pointer_name(0x4000, 0x1010, true, n), "PTR_LAB_00004000");     // in a body, unnamed
  EXPECT_EQ(pointer_name(0x4000, 0x8000, true, n), "PTR_DAT_00004000");
  EXPECT_EQ(pointer_name(0x4000, 0x9000, false, n), "PTR_malloc_00004000");  // EXTERNAL: named, not mapped
  EXPECT_EQ(pointer_name(0x4000, 0, true, n), "PTR_00004000");
  EXPECT_EQ(pointer_name(0x4000, 0x4000, true, n), "PTR_LOOP_00004000");
  EXPECT_EQ(pointer_name(0x5000, 0x6000, true, n), "PTR_LOOP_00005000");  // a cycle of two
  EXPECT_EQ(pointer_name(0x8800, 0x7000, true, n), "PTR_PTR_00008800");   // deeper than two
  // Where the space shows in default names (RISC-V), they stay whole.
  n.prefix = "ram_";
  n.names[0x1000] = "FUN_ram_00001000";
  EXPECT_EQ(pointer_name(0x4000, 0x1000, true, n), "PTR_FUN_ram_00001000_ram_00004000");
}

}  // namespace
}  // namespace revkit::inputs
