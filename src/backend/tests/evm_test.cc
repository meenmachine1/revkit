// EVM contracts through the API (docs/evm.md), on OpenZeppelin's compiled
// ERC-20 (tests/data/evm, MIT): creation code as hex text imports as format
// "evm" with its runtime at 0 and the constructor at 0x100000; the
// dispatcher's functions are named by selector from the well-known table,
// JUMPDESTs labelled, computed jumps given their targets; the summary says
// how much of the control flow is known; the dispatcher and a function
// decompile.
#include "revkit/backend/image_backend.h"

#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>
#include <iterator>
#include <set>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
using api::CallContext;

std::string Text(const pb::DecompiledFunction &f) {
  std::string out;
  for (const auto &line : f.lines()) {
    for (const auto &t : line.tokens()) out += t.text();
    out += '\n';
  }
  return out;
}

class EvmImport : public ::testing::Test {
 protected:
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    backend_ = MakeImageBackend(o);
  }

  std::string Import(const std::string &file, const std::string &format = "") {
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path(std::string(REVKIT_EVM_DATA) + "/" + file);
    req.mutable_options()->set_format(format);
    pb::ImportProgramResponse resp;
    auto st = backend_->ImportProgram(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.program().program_id();
  }

  std::map<std::string, std::uint64_t> Functions(const std::string &id) {
    pb::ListFunctionsRequest req;
    req.set_program_id(id);
    req.mutable_page()->set_page_size(1000);
    pb::ListFunctionsResponse resp;
    EXPECT_TRUE(backend_->ListFunctions(ctx_, req, resp).ok());
    std::map<std::string, std::uint64_t> out;
    for (const auto &f : resp.functions()) out[f.name()] = f.entry().offset();
    return out;
  }

  pb::DecompileResponse Decompile(const std::string &id, std::uint64_t entry) {
    pb::DecompileRequest req;
    req.set_program_id(id);
    req.mutable_function()->set_offset(entry);
    req.mutable_options()->set_timeout_ms(60000);
    pb::DecompileResponse resp;
    auto st = backend_->Decompile(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  CallContext ctx_;
  std::unique_ptr<api::Backend> backend_;
};

TEST_F(EvmImport, CreationCodeHasItsRuntimeFunctionsAndJumps) {
  const std::string id = Import("erc20.creation.hex");
  pb::GetProgramSummaryRequest sreq;
  sreq.set_program_id(id);
  pb::GetProgramSummaryResponse sresp;
  ASSERT_TRUE(backend_->GetProgramSummary(ctx_, sreq, sresp).ok());
  const pb::ProgramSummary &s = sresp.summary();
  EXPECT_EQ(s.info().format(), "evm");
  EXPECT_EQ(s.language().language_id(), "EVM:BE:32:default");
  ASSERT_TRUE(s.has_evm());
  const pb::EvmSummary &e = s.evm();
  EXPECT_TRUE(e.creation());
  EXPECT_EQ(e.runtime_size(), 2140u);
  EXPECT_EQ(e.functions_size(), 11);
  std::set<std::string> names;
  for (const auto &f : e.functions()) names.insert(f.name());
  EXPECT_TRUE(names.contains("transfer") && names.contains("balanceOf")) << e.DebugString();
  EXPECT_GT(e.jumps(), 100u);
  EXPECT_GE(e.resolved_jumps() * 100, e.jumps() * 99) << e.DebugString();
  std::printf("ERC-20: %u jumps, %u direct, %u resolved, %u unresolved, %u unreached\n", e.jumps(), e.direct_jumps(),
              e.resolved_jumps(), e.unresolved_jumps(), e.unreached_jumps());
  EXPECT_GT(e.metadata_size(), 0u);
  bool blocks[2] = {false, false};
  for (const auto &b : s.memory()) {
    if (b.name() == "runtime") blocks[0] = b.range().first().offset() == 0;
    if (b.name() == "init") blocks[1] = b.range().first().offset() == 0x100000;
  }
  EXPECT_TRUE(blocks[0] && blocks[1]);

  const auto fns = Functions(id);
  ASSERT_TRUE(fns.contains("dispatcher") && fns.contains("constructor") && fns.contains("transfer"));
  EXPECT_EQ(fns.at("dispatcher"), 0u);
  EXPECT_EQ(fns.at("constructor"), 0x100000u);
  // The dispatcher compares the selector (shr(0xe0, calldataload(0))) with each function's.
  const pb::DecompileResponse d = Decompile(id, 0);
  EXPECT_FALSE(d.has_failure());
  const std::string c = Text(d.function());
  EXPECT_NE(c.find("calldataload"), std::string::npos) << c;
  EXPECT_NE(c.find("0xa9059cbb"), std::string::npos) << c;
  const pb::DecompileResponse t = Decompile(id, fns.at("transfer"));
  EXPECT_FALSE(t.has_failure());
  EXPECT_FALSE(Text(t.function()).empty());
}

TEST_F(EvmImport, RuntimeCodeAndRefusals) {
  const std::string id = Import("erc721.runtime.hex", "evm");
  pb::GetProgramSummaryRequest sreq;
  sreq.set_program_id(id);
  pb::GetProgramSummaryResponse sresp;
  ASSERT_TRUE(backend_->GetProgramSummary(ctx_, sreq, sresp).ok());
  EXPECT_FALSE(sresp.summary().evm().creation());
  const auto fns = Functions(id);
  EXPECT_TRUE(fns.contains("ownerOf") && fns.contains("supportsInterface") && fns.contains("dispatcher"));
  // Format "evm" on something that isn't.
  pb::ImportProgramRequest req;
  req.set_project_id("default");
  req.set_content("hello");
  req.mutable_options()->set_format("evm");
  pb::ImportProgramResponse resp;
  EXPECT_EQ(backend_->ImportProgram(ctx_, req, resp).code, api::StatusCode::kInvalidArgument);
}

}  // namespace
}  // namespace revkit::backend
