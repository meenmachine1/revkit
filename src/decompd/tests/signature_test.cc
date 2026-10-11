// Mode signature: BSim's features from the "normalize" action group, in
// workers, under the inputs' signature profile.

#include "builders.hh"

#include "revkit/decompd/batch.h"
#include "revkit/decompd/signature.h"
#include "revkit/inputs/profile.h"
#include "revkit/lift/decompile.hh"
#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdlib>
#include <memory>

namespace revkit::decompd {
namespace {

using lift::DecompilerInputs;
using lift::FunctionFacts;
using lift::StorageVarnode;
using loader::Image;
using testing::ElfBuilder;
using testing::to_bytes;

constexpr std::uint64_t kText = 0x1000, kData = 0x2000;

// x86-64:
//   0x1000 caller: mov edi,5; call 0x1010; add eax,1; ret
//   0x1010 callee: mov eax,edi; imul eax,edi; ret
//   0x1020 loop:   xor eax,eax; add eax,edi; dec edi; jnz 0x1022; ret
//   0x1030 global: mov eax,[0x2000]; add eax,[0x2004]; ret
std::vector<std::uint8_t> text() {
  std::vector<std::uint8_t> t(0x40, 0xcc);
  auto put = [&](std::size_t at, std::initializer_list<std::uint8_t> bytes) {
    for (std::uint8_t b : bytes) t[at++] = b;
  };
  put(0x00, {0xbf, 0x05, 0x00, 0x00, 0x00, 0xe8, 0x06, 0x00, 0x00, 0x00, 0x83, 0xc0, 0x01, 0xc3});
  put(0x10, {0x89, 0xf8, 0x0f, 0xaf, 0xc7, 0xc3});
  put(0x20, {0x31, 0xc0, 0x01, 0xf8, 0xff, 0xcf, 0x75, 0xfa, 0xc3});
  put(0x30, {0x8b, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, 0x03, 0x04, 0x25, 0x04, 0x20, 0x00, 0x00, 0xc3});
  return t;
}

std::shared_ptr<const Image> image() {
  ElfBuilder b({.wide = true, .big = false, .machine = 62, .type = 2, .flags = 0, .entry = kText});
  b.add_load(".text", kText, text(), 5);
  b.add_load(".data", kData, std::vector<std::uint8_t>(16, 0), 6);
  return std::make_shared<const Image>(loader::parse(to_bytes(b.build())));
}

FunctionFacts function(std::uint64_t entry, std::string name, std::uint64_t last) {
  FunctionFacts f;
  f.entry = entry;
  f.name = std::move(name);
  f.body = {{entry, last}};
  f.convention = "unknown";
  f.ret.type = {"void", {}, {}};
  f.ret.storage = std::vector<StorageVarnode>{};
  f.ret.void_storage = true;
  return f;
}

std::shared_ptr<DecompilerInputs> inputs() {
  auto in = std::make_shared<DecompilerInputs>();
  in->functions = {function(0x1000, "caller", 0x100d), function(0x1010, "callee", 0x1015),
                   function(0x1020, "loop", 0x1028), function(0x1030, "global", 0x103e)};
  in->memory = {{".text", kText, kText + 0x3f, false, true, true, false, false, {}},
                {".data", kData, kData + 0xf, true, false, true, false, false, {}}};
  return in;
}

const std::vector<std::uint64_t> kEntries = {0x1000, 0x1010, 0x1020, 0x1030};

class Signature : public ::testing::Test {
 protected:
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    lift::initialize(REVKIT_GHIDRA_ROOT);
    ::unsetenv("REVKIT_DECOMPD_FAULT");
  }
  void TearDown() override { ::unsetenv("REVKIT_DECOMPD_FAULT"); }

  static lift::DecompileConfig config(std::shared_ptr<DecompilerInputs> in = inputs(), unsigned threads = 2) {
    lift::DecompileConfig c;
    c.image = image();
    c.language_id = "x86:LE:64:default:gcc";
    c.inputs = std::move(in);
    c.threads = threads;
    return c;
  }
};

TEST_F(Signature, WorkersSignEveryFunction) {
  SignatureStats stats;
  SignatureBatchOptions o;
  o.signature.blocks = true;
  auto sigs = signature_functions(config(), kEntries, o, &stats);
  ASSERT_EQ(sigs.size(), kEntries.size());
  EXPECT_EQ(stats.signed_ok, kEntries.size());
  EXPECT_TRUE(stats.failures.empty());
  for (const auto &[entry, s] : sigs) {
    SCOPED_TRACE(entry);
    ASSERT_TRUE(s.ok()) << s.detail;
    EXPECT_FALSE(s.features.empty());
    EXPECT_TRUE(std::is_sorted(s.features.begin(), s.features.end()));
    EXPECT_EQ(s.settings, kSignatureSettings);
    EXPECT_EQ(s.bundle_hash.substr(0, 3), "b2-");
    // The blocks' features are the function's, attributed.
    std::vector<std::uint32_t> all;
    for (const BlockFeatures &b : s.blocks) all.insert(all.end(), b.features.begin(), b.features.end());
    std::sort(all.begin(), all.end());
    EXPECT_EQ(all, s.features);
  }
  // The loop has two blocks or more.
  EXPECT_GE(sigs.at(0x1020).blocks.size(), 2u);
  // The same in the in-process debugging mode, and payloads round-trip.
  PoolOptions local;
  local.in_process = true;
  auto again = signature_functions(config(), kEntries, o, nullptr, local);
  for (const auto &[entry, s] : sigs) {
    EXPECT_EQ(again.at(entry).features, s.features);
    EXPECT_EQ(decode_function_signature(encode_function_signature(s)), s);
  }
}

TEST_F(Signature, SameForAnyThreadCount) {
  auto one = signature_functions(config(inputs(), 1), kEntries);
  auto eight = signature_functions(config(inputs(), 8), kEntries);
  ASSERT_EQ(one.size(), eight.size());
  for (const auto &[entry, s] : one) {
    EXPECT_EQ(eight.at(entry).features, s.features);
    EXPECT_EQ(eight.at(entry).bundle_hash, s.bundle_hash);
  }
}

TEST_F(Signature, NamesTypesAndPrototypesDontReachSignatures) {
  auto plain = signature_functions(config(), kEntries);
  // Rename everything, give the callee a locked prototype and a local, the
  // caller a comment: none of it reaches a signature bundle.
  auto edited = inputs();
  for (FunctionFacts &f : edited->functions) f.name += "_renamed";
  FunctionFacts &callee = edited->functions[1];
  callee.signature_source = lift::SignatureSource::user_defined;
  callee.ret.type = {"type", {{"name", std::string("int")}, {"metatype", std::string("int")}, {"size", std::int64_t{4}}}, {}};
  callee.ret.storage = std::vector<StorageVarnode>{{"register", 0, 4}};
  callee.ret.void_storage = false;
  callee.ret.size = 4;
  edited->comments.push_back({0x1000, lift::CommentFacts::pre, "a comment"});
  auto renamed = signature_functions(config(edited), kEntries);
  for (const auto &[entry, s] : plain) {
    SCOPED_TRACE(entry);
    EXPECT_EQ(renamed.at(entry).features, s.features);
    EXPECT_EQ(renamed.at(entry).bundle_hash, s.bundle_hash);
  }
  // Debug info's no-return (DW_AT_noreturn) doesn't count where analysis's
  // no-return set is given.
  auto noreturn = inputs();
  noreturn->functions[1].noreturn = true;
  SignatureBatchOptions analysis_set;
  analysis_set.no_return = std::make_shared<const std::vector<std::uint64_t>>();
  auto ignored = signature_functions(config(noreturn), kEntries, analysis_set);
  EXPECT_EQ(ignored.at(0x1000).features, plain.at(0x1000).features);
  auto honoured = signature_functions(config(noreturn), kEntries);
  EXPECT_NE(honoured.at(0x1000).features, plain.at(0x1000).features);
  // The profile and the settings are part of the bundle.
  SignatureBatchOptions nosize;
  nosize.signature.settings = kSignatureSettingsNoSize;
  auto other = signature_functions(config(), kEntries, nosize);
  EXPECT_NE(other.at(0x1000).bundle_hash, plain.at(0x1000).bundle_hash);
  EXPECT_EQ(other.at(0x1000).settings, kSignatureSettingsNoSize);
}

TEST_F(Signature, ImportsAndUnknownEntriesAreSkipped) {
  auto in = inputs();
  FunctionFacts imp = function(0x1030, "abort", 0x1030);
  imp.label = "<EXTERNAL>_abort";
  in->functions[3] = imp;
  auto sigs = signature_functions(config(in), {0x1030, 0x1038});
  EXPECT_EQ(sigs.at(0x1030).status, FunctionSignature::Status::skipped);
  EXPECT_EQ(sigs.at(0x1030).detail, "import");
  EXPECT_EQ(sigs.at(0x1038).status, FunctionSignature::Status::skipped);
}

TEST_F(Signature, FailuresAreFacts) {
  ::setenv("REVKIT_DECOMPD_FAULT", "segv@0x1020", 1);
  SignatureStats stats;
  auto sigs = signature_functions(config(), kEntries, {}, &stats);
  const FunctionSignature &s = sigs.at(0x1020);
  EXPECT_EQ(s.status, FunctionSignature::Status::failed);
  ASSERT_TRUE(s.failure);
  EXPECT_EQ(*s.failure, FailureKind::segv);
  EXPECT_FALSE(s.bundle_hash.empty());
  ASSERT_EQ(stats.failures.size(), 1u);
  EXPECT_TRUE(sigs.at(0x1000).ok());
  // A varnode bound: a cooperative stop.
  ::unsetenv("REVKIT_DECOMPD_FAULT");
  SignatureBatchOptions tiny;
  tiny.max_varnodes = 1;
  auto stopped = signature_functions(config(), {0x1020}, tiny);
  EXPECT_EQ(stopped.at(0x1020).status, FunctionSignature::Status::failed);
}

TEST_F(Signature, BadSettingsFailCleanly) {
  SignatureBatchOptions bad;
  bad.signature.settings = 0x1000;
  auto sigs = signature_functions(config(), {0x1000}, bad);
  EXPECT_EQ(sigs.at(0x1000).status, FunctionSignature::Status::failed);
  EXPECT_NE(sigs.at(0x1000).detail.find("settings"), std::string::npos);
}

TEST(SignatureSettings, ByPointerSize) {
  EXPECT_EQ(default_signature_settings("x86:LE:64:default"), kSignatureSettings);
  EXPECT_EQ(default_signature_settings("ARM:LE:32:Cortex:default"), kSignatureSettings);
  EXPECT_EQ(default_signature_settings("toy:BE:16:default"), kSignatureSettingsNoSize);
  EXPECT_EQ(default_signature_settings("bad"), kSignatureSettingsNoSize);
}

TEST(SignatureProfile, StripsAllButImports) {
  FunctionFacts f;
  f.entry = 0x1234;
  f.name = "user_name";
  f.body = {{0x1234, 0x1240}};
  f.signature_source = lift::SignatureSource::user_defined;
  f.noreturn = true;
  f.locals.push_back({});
  f.context = {{"TMode", 1}};
  FunctionFacts s = inputs::strip_function(f, {});
  EXPECT_EQ(s.name, "FUN_1234");
  EXPECT_EQ(s.signature_source, lift::SignatureSource::default_);
  EXPECT_TRUE(s.noreturn);
  EXPECT_TRUE(s.locals.empty());
  EXPECT_EQ(s.body, f.body);
  EXPECT_EQ(s.context, f.context);
  f.label = "<EXTERNAL>_exit";
  f.name = "exit";
  inputs::SignatureProfile bare;
  bare.import_prototypes = false;
  EXPECT_EQ(inputs::strip_function(f, bare).name, "exit");
  EXPECT_EQ(inputs::strip_function(f, bare).signature_source, lift::SignatureSource::default_);
  EXPECT_EQ(inputs::strip_function(f, {}).signature_source, lift::SignatureSource::user_defined);
  EXPECT_EQ(inputs::strip_function(f, {}).name, "exit");
  EXPECT_NE(bare.id(), inputs::SignatureProfile{}.id());
}

}  // namespace
}  // namespace revkit::decompd
