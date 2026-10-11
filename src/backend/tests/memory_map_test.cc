// The memory map after import (docs/memory-map.md): GetMemoryMap for every
// format, regions added, changed and removed as assertions, and what that
// does to analysis, references and the decompiler.
//
// The firmware is hand-assembled ARM (v4t, little endian), so the test
// needs no cross toolchain:
//
//   0x00  b main; the other vectors b .
//   0x20  main:       push {lr}; bl read_ram; bl read_const; bl 0x100000; pop {pc}
//   0x40  read_ram:   ldr r0, =0x20000000; ldr r0, [r0]; bx lr
//   0x50  read_const: ldr r0, =0x80000; ldr r0, [r0]; bx lr
//
// Nothing is mapped at 0x20000000 (RAM), 0x80000 (a constant in another
// file) or 0x100000 (a bootloader in another file) until regions add them.
#include "builders.hh"

#include "revkit/backend/image_backend.h"
#include "revkit/facts/engine.h"
#include "revkit/plugins/queries.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <filesystem>
#include <map>
#include <set>

namespace revkit::backend {
namespace {

namespace fs = std::filesystem;
namespace pb = ::revkit::v1;
using api::CallContext;
using api::StatusCode;

std::string Words(std::initializer_list<std::uint32_t> words) {
  std::string out;
  for (std::uint32_t w : words)
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<char>((w >> (8 * i)) & 0xff));
  return out;
}

std::string Firmware() {
  std::string fw = Words({0xEA000006});                       // 0x00 b main
  for (int i = 1; i < 8; ++i) fw += Words({0xEAFFFFFE});      // b .
  fw += Words({0xE52DE004, 0xEB000005, 0xEB000008, 0xEB03FFF3, 0xE49DF004, 0, 0, 0});  // 0x20 main
  fw += Words({0xE59F0004, 0xE5900000, 0xE12FFF1E, 0x20000000});  // 0x40 read_ram
  fw += Words({0xE59F0004, 0xE5900000, 0xE12FFF1E, 0x00080000});  // 0x50 read_const
  fw.resize(0x100, '\0');
  return fw;
}

// Another file: a header, then the constant 0x12345678 at offset 0x10.
std::string ConstantsFile() { return std::string(0x10, 'C') + Words({0x12345678, 0x9abcdef0}); }

// A bootloader: mov r0, #7; bx lr.
std::string BootFile() { return Words({0xE3A00007, 0xE12FFF1E}); }

class MemoryMapTest : public ::testing::Test {
 protected:
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  }

  static std::unique_ptr<api::Backend> Make(const std::string &project_dir = {}) {
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    o.project_dir = project_dir;
    return MakeImageBackend(o);
  }

  std::string Import(api::Backend &b) {
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_name("fw.bin");
    req.set_content(Firmware());
    pb::ImportOptions *o = req.mutable_options();
    o->set_format("raw");
    o->set_language_id("ARM:LE:32:v4t");
    o->set_compiler_spec_id("default");
    o->set_raw_permissions("r-x");  // flash: its literal pools are constants
    pb::ImportProgramResponse resp;
    auto st = b.ImportProgram(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.program().program_id();
  }

  static pb::Provenance User() {
    pb::Provenance p;
    p.set_kind(pb::PROVENANCE_KIND_USER);
    p.set_id("alice");
    return p;
  }

  static pb::MemoryRegion Region(const std::string &name, std::uint64_t start, std::uint64_t size, const char *perms,
                                 bool initialized = false, bool is_volatile = false) {
    pb::MemoryRegion r;
    r.set_name(name);
    r.set_start(start);
    r.set_size(size);
    r.set_read(perms[0] == 'r');
    r.set_write(perms[1] == 'w');
    r.set_execute(perms[2] == 'x');
    r.set_initialized(initialized);
    r.set_is_volatile(is_volatile);
    return r;
  }

  api::Status Add(api::Backend &b, const std::string &id, const pb::MemoryRegion &r, pb::AddMemoryRegionResponse &resp,
                  const std::string *content = nullptr, std::uint64_t file_offset = 0, std::uint64_t length = 0) {
    pb::AddMemoryRegionRequest req;
    req.set_program_id(id);
    *req.mutable_region() = r;
    *req.mutable_provenance() = User();
    if (content) {
      req.set_content(*content);
      req.set_file_name("other.bin");
      req.set_file_offset(file_offset);
      req.set_length(length);
    }
    return b.AddMemoryRegion(ctx_, req, resp);
  }

  pb::GetMemoryMapResponse Map(api::Backend &b, const std::string &id) {
    pb::GetMemoryMapRequest req;
    req.set_program_id(id);
    pb::GetMemoryMapResponse resp;
    auto st = b.GetMemoryMap(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  std::map<std::uint64_t, std::string> Functions(api::Backend &b, const std::string &id) {
    pb::ListFunctionsRequest req;
    req.set_program_id(id);
    pb::ListFunctionsResponse resp;
    EXPECT_TRUE(b.ListFunctions(ctx_, req, resp).ok());
    std::map<std::uint64_t, std::string> out;
    for (const auto &f : resp.functions()) out[f.entry().offset()] = f.name();
    return out;
  }

  std::set<std::uint64_t> XrefsTo(api::Backend &b, const std::string &id, std::uint64_t to) {
    pb::GetXrefsRequest req;
    req.set_program_id(id);
    req.mutable_address()->set_offset(to);
    req.set_direction(pb::XREF_DIRECTION_TO);
    pb::GetXrefsResponse resp;
    EXPECT_TRUE(b.GetXrefs(ctx_, req, resp).ok());
    std::set<std::uint64_t> out;
    for (const auto &x : resp.xrefs()) out.insert(x.from_address().offset());
    return out;
  }

  std::string Decompile(api::Backend &b, const std::string &id, std::uint64_t entry) {
    pb::DecompileRequest req;
    req.set_program_id(id);
    req.mutable_function()->set_offset(entry);
    req.mutable_options()->set_include_text(true);
    pb::DecompileResponse resp;
    auto st = b.Decompile(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.function().text();
  }

  std::string Read(api::Backend &b, const std::string &id, std::uint64_t at, std::uint32_t n) {
    pb::ReadMemoryRequest req;
    req.set_program_id(id);
    req.mutable_address()->set_offset(at);
    req.set_length(n);
    pb::ReadMemoryResponse resp;
    EXPECT_TRUE(b.ReadMemory(ctx_, req, resp).ok());
    return resp.data();
  }

  api::Status Retract(api::Backend &b, const std::string &id, std::uint64_t seq) {
    pb::RetractAssertionsRequest req;
    req.set_program_id(id);
    req.add_seqs(seq);
    *req.mutable_provenance() = User();
    pb::RetractAssertionsResponse resp;
    return b.RetractAssertions(ctx_, req, resp);
  }

  CallContext ctx_;
};

const pb::MemoryBlock *Find(const pb::GetMemoryMapResponse &m, const std::string &name) {
  for (const auto &b : m.blocks())
    if (b.name() == name) return &b;
  return nullptr;
}

TEST_F(MemoryMapTest, ServerAdvertisesTheFeature) {
  auto b = Make();
  pb::GetServerInfoResponse info;
  ASSERT_TRUE(b->GetServerInfo(ctx_, {}, info).ok());
  EXPECT_GE(info.api_minor(), 24u);
  EXPECT_NE(std::find(info.features().begin(), info.features().end(), "memory-map"), info.features().end());
}

// Every format has a map: the loader's blocks, where their bytes are.
TEST_F(MemoryMapTest, ListsTheBlocksOfElfPeAndRaw) {
  auto b = Make();
  // ELF: a code and a data segment and a .bss.
  testing::ElfBuilder elf({.wide = true, .big = false, .machine = 62, .type = 2, .flags = 0, .entry = 0x401000});
  elf.add_load(".text", 0x401000, {0x31, 0xc0, 0xc3}, 5);
  elf.add_load(".data", 0x402000, {1, 2, 3, 4}, 6);
  elf.add_load(".bss", 0x403000, {}, 6, 0x100, true);
  const std::vector<std::uint8_t> elf_bytes = elf.build();
  pb::ImportProgramRequest req;
  req.set_project_id("default");
  req.set_name("prog.elf");
  req.set_content(std::string(elf_bytes.begin(), elf_bytes.end()));
  pb::ImportProgramResponse resp;
  auto st = b->ImportProgram(ctx_, req, resp);
  ASSERT_TRUE(st.ok()) << st.message;
  auto map = Map(*b, resp.program().program_id());
  const pb::MemoryBlock *text = Find(map, ".text"), *bss = Find(map, ".bss");
  ASSERT_TRUE(text && bss);
  EXPECT_TRUE(text->execute() && !text->write());
  EXPECT_EQ(text->source().kind(), pb::MEMORY_BLOCK_SOURCE_KIND_IMAGE);
  EXPECT_TRUE(text->has_file_offset());
  EXPECT_TRUE(text->region_id().empty());
  EXPECT_TRUE(text->origin().has_derived());
  EXPECT_EQ(bss->range().last().offset() - bss->range().first().offset() + 1, 0x100u);

  // PE: its sections.
  testing::PeImage pe = testing::build_pe();
  req.set_name("prog.exe");
  req.set_content(std::string(pe.bytes.begin(), pe.bytes.end()));
  st = b->ImportProgram(ctx_, req, resp);
  ASSERT_TRUE(st.ok()) << st.message;
  map = Map(*b, resp.program().program_id());
  ASSERT_TRUE(Find(map, ".text"));
  EXPECT_EQ(Find(map, ".text")->source().kind(), pb::MEMORY_BLOCK_SOURCE_KIND_IMAGE);

  // Raw: the image as one block.
  const std::string id = Import(*b);
  map = Map(*b, id);
  ASSERT_EQ(map.blocks_size(), 1);
  EXPECT_EQ(map.blocks(0).name(), "ram");
  EXPECT_EQ(map.blocks(0).range().last().offset(), 0xffu);
  EXPECT_EQ(map.blocks(0).source().kind(), pb::MEMORY_BLOCK_SOURCE_KIND_IMAGE);
}

// The point of the feature: memory added after import changes what
// analysis and the decompiler see, and undo takes it back.
TEST_F(MemoryMapTest, AddedRegionsChangeAnalysisAndTheDecompiler) {
  auto b = Make();
  const std::string id = Import(*b);

  // Before: nothing at 0x20000000, 0x80000 or 0x100000.
  EXPECT_TRUE(XrefsTo(*b, id, 0x20000000).empty());
  EXPECT_FALSE(Functions(*b, id).contains(0x100000));
  const std::string ram_before = Decompile(*b, id, 0x40);
  const std::string const_before = Decompile(*b, id, 0x50);
  EXPECT_EQ(const_before.find("0x12345678"), std::string::npos) << const_before;

  // RAM at 0x20000000: the pointer read_ram loads becomes a data reference.
  pb::AddMemoryRegionResponse ram;
  auto st = Add(*b, id, Region("sram", 0x20000000, 0x1000, "rw-"), ram);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_FALSE(ram.region_id().empty());
  EXPECT_EQ(ram.block().source().kind(), pb::MEMORY_BLOCK_SOURCE_KIND_NONE);
  EXPECT_TRUE(ram.assertion().seq());
  EXPECT_EQ(ram.assertion().key().kind(), pb::FACT_KIND_MEMORY_REGION);
  EXPECT_FALSE(XrefsTo(*b, id, 0x20000000).empty());
  const std::string ram_after = Decompile(*b, id, 0x40);
  EXPECT_NE(ram_after.find("DAT_20000000"), std::string::npos) << "before:\n" << ram_before << "after:\n" << ram_after;

  // A constant from another file, read-only: the decompiler folds it.
  const std::string constants = ConstantsFile();
  pb::AddMemoryRegionResponse rom;
  st = Add(*b, id, Region("consts", 0x80000, 0, "r--"), rom, &constants, 0x10, 8);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(rom.block().range().last().offset(), 0x80007u);
  EXPECT_EQ(rom.block().source().kind(), pb::MEMORY_BLOCK_SOURCE_KIND_FILE);
  EXPECT_EQ(rom.block().source().file(), "other.bin");
  EXPECT_EQ(rom.block().source().file_offset(), 0x10u);
  EXPECT_EQ(Read(*b, id, 0x80000, 4), Words({0x12345678}));
  const std::string const_after = Decompile(*b, id, 0x50);
  EXPECT_NE(const_after.find("0x12345678"), std::string::npos) << "before:\n" << const_before << "after:\n" << const_after;

  // Volatile: no longer folded.
  pb::UpdateMemoryRegionRequest up;
  up.set_program_id(id);
  up.set_region_id(rom.region_id());
  *up.mutable_region() = Region("consts", 0x80000, 8, "r--", true, true);
  *up.mutable_provenance() = User();
  pb::UpdateMemoryRegionResponse upr;
  st = b->UpdateMemoryRegion(ctx_, up, upr);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_TRUE(upr.block().is_volatile());
  EXPECT_EQ(upr.block().source().kind(), pb::MEMORY_BLOCK_SOURCE_KIND_FILE);  // the bytes stay
  const std::string const_volatile = Decompile(*b, id, 0x50);
  EXPECT_EQ(const_volatile.find("0x12345678"), std::string::npos) << const_volatile;
  if (std::getenv("RK_SHOW_DECOMPILED"))
    std::cerr << "read_ram before:\n" << ram_before << "after RAM:\n" << ram_after << "read_const before:\n"
              << const_before << "after the file's bytes:\n" << const_after << "volatile:\n" << const_volatile;

  // A bootloader from another file: the call to it now reaches a function.
  const std::string boot = BootFile();
  pb::AddMemoryRegionResponse code;
  st = Add(*b, id, Region("boot", 0x100000, 0, "r-x"), code, &boot);
  ASSERT_TRUE(st.ok()) << st.message;
  auto fns = Functions(*b, id);
  ASSERT_TRUE(fns.contains(0x100000));
  EXPECT_NE(Decompile(*b, id, 0x100000).find("return 7;"), std::string::npos);

  // The map: the image and three regions, in address order, with origins.
  auto map = Map(*b, id);
  ASSERT_EQ(map.blocks_size(), 4);
  EXPECT_EQ(map.blocks(1).name(), "consts");
  EXPECT_EQ(map.blocks(2).name(), "boot");
  EXPECT_EQ(map.blocks(3).name(), "sram");
  EXPECT_TRUE(map.blocks(3).origin().has_asserted());
  EXPECT_EQ(map.blocks(3).origin().asserted().provenance().id(), "alice");

  // Undo the bootloader: the function goes; redo brings it back.
  st = Retract(*b, id, code.assertion().seq());
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_FALSE(Functions(*b, id).contains(0x100000));
  EXPECT_TRUE(Read(*b, id, 0x100000, 4).empty());

  // Remove the RAM: the reference goes.
  pb::RemoveMemoryRegionRequest rm;
  rm.set_program_id(id);
  rm.set_region_id(ram.region_id());
  *rm.mutable_provenance() = User();
  pb::RemoveMemoryRegionResponse rmr;
  st = b->RemoveMemoryRegion(ctx_, rm, rmr);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_TRUE(XrefsTo(*b, id, 0x20000000).empty());
  // ... and undoing the removal brings it back.
  ASSERT_TRUE(Retract(*b, id, rmr.assertion().seq()).ok());
  EXPECT_FALSE(XrefsTo(*b, id, 0x20000000).empty());

  // Blame names the region's edit.
  pb::BlameRequest bl;
  *bl.mutable_key() = ram.assertion().key();
  pb::BlameResponse blr;
  ASSERT_TRUE(b->Blame(ctx_, bl, blr).ok());
  EXPECT_NE(blr.value_text().find("sram 0x20000000-0x20000fff rw- uninitialized"), std::string::npos) << blr.value_text();
}

// What an edit costs (docs/memory-map.md, "What an edit recomputes"): the
// program's ProgramInfo changes, so discovery's flows run again and the
// fixpoint once; what they find is compared by fingerprint, so a region
// nothing refers to changes no function. Every decompilation runs again
// (the decompiler's memory blocks are part of each one's inputs). Undo
// returns to the same fingerprints.
TEST_F(MemoryMapTest, AnEditRerunsDiscoveryOnce) {
  auto b = Make();
  const std::string id = Import(*b);
  auto fns = Functions(*b, id);
  for (const auto &[entry, name] : fns) Decompile(*b, id, entry);
  ResetQueryCounters(*b, "default");
  pb::AddMemoryRegionResponse far;
  ASSERT_TRUE(Add(*b, id, Region("far", 0x40000000, 0x1000, "rw-"), far).ok());
  EXPECT_EQ(Functions(*b, id), fns);
  for (const auto &[entry, name] : fns) Decompile(*b, id, entry);
  auto c = QueryCounters(*b, "default");
  if (std::getenv("RK_SHOW_COUNTERS"))
    for (const auto &[rule, n] : c)
      if (n.executions) std::cerr << rule << ": " << n.executions << "\n";
  EXPECT_EQ(c.at("analysis.memory").executions, 1u);
  EXPECT_EQ(c.at("analysis.functions").executions, 1u);
  EXPECT_LE(c.at("analysis.flow").executions, fns.size() + 2);
  EXPECT_EQ(c.at("decompile.ghidra").executions, fns.size());
}

// Patches lay over a region's bytes as over the image's: the file's
// bytes, then the patch (docs/patching.md).
TEST_F(MemoryMapTest, PatchesLayOverARegionsBytes) {
  auto b = Make();
  const std::string id = Import(*b);
  const std::string boot = BootFile();
  pb::AddMemoryRegionResponse code;
  ASSERT_TRUE(Add(*b, id, Region("boot", 0x100000, 0, "r-x"), code, &boot).ok());
  pb::PatchBytesRequest req;
  req.set_program_id(id);
  req.mutable_address()->set_offset(0x100000);
  req.set_data(Words({0xE3A00009}));  // mov r0, #9
  *req.mutable_provenance() = User();
  pb::PatchBytesResponse resp;
  auto st = b->PatchBytes(ctx_, req, resp);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(Read(*b, id, 0x100000, 8), Words({0xE3A00009, 0xE12FFF1E}));
  EXPECT_NE(Decompile(*b, id, 0x100000).find("return 9;"), std::string::npos);
  // Analyzer plugins read the same: the region in their memory map, its
  // bytes as patched.
  facts::Snapshot snap = ProjectEngine(*b, "default").snapshot();
  plugins::StoreFacts<facts::Snapshot> pf(snap, analysis::ProgramKey{id});
  std::string got(8, '\0');
  EXPECT_EQ(pf.memory_read(0x100000, std::span(reinterpret_cast<std::byte *>(got.data()), got.size())), 8u);
  EXPECT_EQ(got, Words({0xE3A00009, 0xE12FFF1E}));
  EXPECT_NE(pf.program_info().find("boot"), std::string::npos);
}

// A region in another memory space (MemoryRegion.space): an 8051's
// external RAM, keyed as the program's other addresses in that space are.
TEST_F(MemoryMapTest, RegionsInAnotherMemorySpace) {
  auto b = Make();
  pb::ImportProgramRequest req;
  req.set_project_id("default");
  req.set_name("mcs51.bin");
  req.set_content(std::string("\x80\xfe", 2) + std::string(0xfe, '\0'));  // sjmp $
  pb::ImportOptions *o = req.mutable_options();
  o->set_format("raw");
  o->set_language_id("8051:BE:16:default");
  pb::MemoryRegion *x = o->add_regions();
  x->set_name("xram");
  x->set_start(0);
  x->set_size(0x100);
  x->set_read(true);
  x->set_write(true);
  x->set_space("EXTMEM");
  pb::ImportProgramResponse imported;
  auto st = b->ImportProgram(ctx_, req, imported);
  ASSERT_TRUE(st.ok()) << st.message;
  const std::string id = imported.program().program_id();
  auto map = Map(*b, id);
  const pb::MemoryBlock *xram = Find(map, "xram");
  ASSERT_TRUE(xram);
  const std::uint64_t base = xram->range().first().offset();
  ASSERT_NE(base, 0u);  // a key in EXTMEM, not the code space's 0
  pb::MemoryRegion more = Region("xio", 0x100, 0x100, "rw-", false, true);
  more.set_space("EXTMEM");
  pb::AddMemoryRegionResponse added;
  st = Add(*b, id, more, added);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(added.block().range().first().offset(), base + 0x100);
  // Over xram in EXTMEM: refused; the same offsets in CODE are free.
  pb::MemoryRegion over = Region("over", 0x80, 0x10, "rw-");
  over.set_space("EXTMEM");
  st = Add(*b, id, over, added);
  EXPECT_EQ(st.code, StatusCode::kInvalidArgument);
  EXPECT_NE(st.message.find("overlaps block xram"), std::string::npos) << st.message;
  pb::MemoryRegion bad = Region("nowhere", 0, 0x10, "rw-");
  bad.set_space("NOSUCH");
  EXPECT_EQ(Add(*b, id, bad, added).code, StatusCode::kInvalidArgument);
}

TEST_F(MemoryMapTest, RejectsOverlapsWrapsAndBadRequests) {
  auto b = Make();
  const std::string id = Import(*b);
  pb::AddMemoryRegionResponse resp;
  // Over the image.
  auto st = Add(*b, id, Region("low", 0x80, 0x100, "rw-"), resp);
  EXPECT_EQ(st.code, StatusCode::kInvalidArgument);
  EXPECT_NE(st.message.find("overlaps block ram [0x0, 0xff]"), std::string::npos) << st.message;
  // Past the top of the 32-bit space.
  st = Add(*b, id, Region("top", 0xfffff000, 0x2000, "rw-"), resp);
  EXPECT_EQ(st.code, StatusCode::kInvalidArgument);
  EXPECT_NE(st.message.find("past the top of the 32-bit address space"), std::string::npos) << st.message;
  // Over another region.
  ASSERT_TRUE(Add(*b, id, Region("a", 0x10000, 0x1000, "rw-"), resp).ok());
  const std::string a_id = resp.region_id();
  st = Add(*b, id, Region("b", 0x10800, 0x1000, "rw-"), resp);
  EXPECT_EQ(st.code, StatusCode::kInvalidArgument);
  EXPECT_NE(st.message.find("overlaps region a"), std::string::npos) << st.message;
  // Empty, unnamed, bytes past the file, a region smaller than its bytes.
  EXPECT_EQ(Add(*b, id, Region("e", 0x30000, 0, "rw-"), resp).code, StatusCode::kInvalidArgument);
  EXPECT_EQ(Add(*b, id, Region("", 0x30000, 0x10, "rw-"), resp).code, StatusCode::kInvalidArgument);
  const std::string boot = BootFile();
  EXPECT_EQ(Add(*b, id, Region("f", 0x30000, 0, "r-x"), resp, &boot, 0x100).code, StatusCode::kInvalidArgument);
  EXPECT_EQ(Add(*b, id, Region("f", 0x30000, 4, "r-x"), resp, &boot).code, StatusCode::kInvalidArgument);
  // validate_only checks without adding.
  pb::AddMemoryRegionRequest v;
  v.set_program_id(id);
  *v.mutable_region() = Region("v", 0x40000, 0x10, "rw-");
  v.set_validate_only(true);
  pb::AddMemoryRegionResponse vr;
  ASSERT_TRUE(b->AddMemoryRegion(ctx_, v, vr).ok());
  EXPECT_FALSE(vr.has_assertion());
  EXPECT_EQ(Map(*b, id).blocks_size(), 2);
  // Moving a region onto the image is refused; moving it elsewhere works.
  pb::UpdateMemoryRegionRequest up;
  up.set_program_id(id);
  up.set_region_id(a_id);
  *up.mutable_provenance() = User();
  *up.mutable_region() = Region("a", 0x0, 0x1000, "rw-");
  pb::UpdateMemoryRegionResponse upr;
  EXPECT_EQ(b->UpdateMemoryRegion(ctx_, up, upr).code, StatusCode::kInvalidArgument);
  *up.mutable_region() = Region("a2", 0x10800, 0x2000, "r--");  // overlapping only itself
  auto ust = b->UpdateMemoryRegion(ctx_, up, upr);
  ASSERT_TRUE(ust.ok()) << ust.message;
  EXPECT_EQ(upr.block().name(), "a2");
  EXPECT_EQ(upr.block().range().first().offset(), 0x10800u);
  // AppendAssertions doesn't take memory edits.
  pb::AppendAssertionsRequest app;
  app.set_program_id(id);
  *app.mutable_provenance() = User();
  app.add_assertions()->mutable_body()->mutable_memory_region()->set_name("x");
  pb::AppendAssertionsResponse appr;
  EXPECT_EQ(b->AppendAssertions(ctx_, app, appr).code, StatusCode::kInvalidArgument);
  // Unknown regions.
  pb::RemoveMemoryRegionRequest rm;
  rm.set_program_id(id);
  rm.set_region_id("nope");
  *rm.mutable_provenance() = User();
  pb::RemoveMemoryRegionResponse rmr;
  EXPECT_EQ(b->RemoveMemoryRegion(ctx_, rm, rmr).code, StatusCode::kNotFound);
}

// The image's own blocks: permissions, volatile and name may change, never
// their addresses or bytes, and they can't be removed.
TEST_F(MemoryMapTest, ImageBlocksTakeEditsButKeepTheirBytes) {
  auto b = Make();
  const std::string id = Import(*b);
  pb::UpdateMemoryRegionRequest up;
  up.set_program_id(id);
  up.mutable_block_start()->set_offset(0);
  *up.mutable_provenance() = User();
  *up.mutable_region() = Region("flash", 0, 0x100, "r-x", true, true);
  pb::UpdateMemoryRegionResponse upr;
  auto st = b->UpdateMemoryRegion(ctx_, up, upr);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(upr.block().name(), "flash");
  EXPECT_FALSE(upr.block().write());
  EXPECT_TRUE(upr.block().edited());
  EXPECT_EQ(upr.block().source().kind(), pb::MEMORY_BLOCK_SOURCE_KIND_IMAGE);
  // Functions are still there (the block is still code).
  EXPECT_TRUE(Functions(*b, id).contains(0x40));
  // Not its start, size or contents.
  *up.mutable_region() = Region("flash", 0x10, 0x100, "r-x", true);
  EXPECT_EQ(b->UpdateMemoryRegion(ctx_, up, upr).code, StatusCode::kInvalidArgument);
  *up.mutable_region() = Region("flash", 0, 0x100, "r-x", false);
  EXPECT_EQ(b->UpdateMemoryRegion(ctx_, up, upr).code, StatusCode::kInvalidArgument);
  // Not executable: no code, so no functions.
  *up.mutable_region() = Region("flash", 0, 0x100, "r--", true);
  ASSERT_TRUE(b->UpdateMemoryRegion(ctx_, up, upr).ok());
  EXPECT_TRUE(Functions(*b, id).empty());
  // Reverting the edits restores the loader's block; then there is nothing to revert.
  pb::RemoveMemoryRegionRequest rm;
  rm.set_program_id(id);
  rm.mutable_block_start()->set_offset(0);
  *rm.mutable_provenance() = User();
  pb::RemoveMemoryRegionResponse rmr;
  ASSERT_TRUE(b->RemoveMemoryRegion(ctx_, rm, rmr).ok());
  auto map = Map(*b, id);
  EXPECT_EQ(map.blocks(0).name(), "ram");
  EXPECT_FALSE(map.blocks(0).edited());
  EXPECT_TRUE(Functions(*b, id).contains(0x40));
  EXPECT_EQ(b->RemoveMemoryRegion(ctx_, rm, rmr).code, StatusCode::kFailedPrecondition);
}

// An undo can bring back a region another one has replaced since: the map
// keeps the first by address and id and reports the other, not mapped.
TEST_F(MemoryMapTest, AnUndoThatOverlapsIsReportedNotMapped) {
  auto b = Make();
  const std::string id = Import(*b);
  pb::AddMemoryRegionResponse a, c;
  ASSERT_TRUE(Add(*b, id, Region("a", 0x20000000, 0x1000, "rw-"), a).ok());
  pb::RemoveMemoryRegionRequest rm;
  rm.set_program_id(id);
  rm.set_region_id(a.region_id());
  *rm.mutable_provenance() = User();
  pb::RemoveMemoryRegionResponse rmr;
  ASSERT_TRUE(b->RemoveMemoryRegion(ctx_, rm, rmr).ok());
  ASSERT_TRUE(Add(*b, id, Region("c", 0x20000800, 0x1000, "rw-"), c).ok());
  ASSERT_TRUE(Retract(*b, id, rmr.assertion().seq()).ok());  // "a" is back
  auto map = Map(*b, id);
  ASSERT_EQ(map.blocks_size(), 2);
  EXPECT_EQ(map.blocks(1).name(), "a");  // the lower start wins
  ASSERT_EQ(map.rejected_size(), 1);
  EXPECT_EQ(map.rejected(0).name(), "c");
  EXPECT_NE(map.rejected(0).rejected().find("overlaps region a"), std::string::npos) << map.rejected(0).rejected();
}

// Regions, their bytes and their effect survive closing the project.
TEST_F(MemoryMapTest, PersistsAndReopens) {
  fs::path dir = testing::scratch_dir("memory-map-project");
  fs::remove_all(dir);
  std::string id, decompiled;
  pb::GetMemoryMapResponse before;
  {
    auto b = Make(dir.string());
    id = Import(*b);
    const std::string constants = ConstantsFile(), boot = BootFile();
    pb::AddMemoryRegionResponse r;
    ASSERT_TRUE(Add(*b, id, Region("consts", 0x80000, 0, "r--"), r, &constants, 0x10, 4).ok());
    ASSERT_TRUE(Add(*b, id, Region("boot", 0x100000, 0x1000, "r-x"), r, &boot).ok());
    before = Map(*b, id);
    decompiled = Decompile(*b, id, 0x50);
    EXPECT_NE(decompiled.find("0x12345678"), std::string::npos) << decompiled;
  }
  auto b = Make(dir.string());
  auto after = Map(*b, id);
  ASSERT_EQ(after.blocks_size(), before.blocks_size());
  for (int i = 0; i < after.blocks_size(); ++i) {
    EXPECT_EQ(after.blocks(i).name(), before.blocks(i).name());
    EXPECT_EQ(after.blocks(i).source().kind(), before.blocks(i).source().kind());
  }
  EXPECT_EQ(Read(*b, id, 0x100000, 8), BootFile());
  EXPECT_EQ(Read(*b, id, 0x100008, 4), std::string(4, '\0'));  // zero-filled past the bytes
  EXPECT_EQ(Decompile(*b, id, 0x50), decompiled);
  EXPECT_TRUE(Functions(*b, id).contains(0x100000));
}

}  // namespace
}  // namespace revkit::backend
