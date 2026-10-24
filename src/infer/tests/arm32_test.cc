// revkit::infer on 32-bit ARM: the fixture of tests/data/arm32 (ARM and
// Thumb code, an SDK's interrupt pair, seven arguments, veneers, a table of
// Thumb handlers, structures through word parameters), built at test time
// with clang and ld.lld and loaded as a raw image, as firmware is.

#include "builders.hh"

#include "revkit/analysis/analysis.h"
#include "revkit/facts/fact_db.h"
#include "revkit/facts/thread_pool.h"
#include "revkit/infer/infer.h"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include <cstdlib>
#include <fstream>
#include <map>
#include <sstream>

namespace revkit::infer {
namespace {

class Arm32 : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty() || std::string(REVKIT_ARM32_CLANG).empty() ||
        std::string(REVKIT_ARM32_LLD).empty() || std::string(REVKIT_ARM32_PYTHON).empty())
      return;
    lift::initialize(REVKIT_GHIDRA_ROOT);
    dir_ = new std::filesystem::path(testing::scratch_dir("infer-arm32"));
    const std::string cmd = std::string(REVKIT_ARM32_PYTHON) + " " + REVKIT_ARM32_FIXTURE + "/make_fixture.py --clang " +
                            REVKIT_ARM32_CLANG + " --lld " + REVKIT_ARM32_LLD + " --opt O2 --out " + dir_->string() +
                            " > " + (*dir_ / "make.log").string() + " 2>&1";
    if (std::system(cmd.c_str()) != 0) return;
    // Where each function is: the ELF's symbols (the image itself has none).
    loader::LoadOptions lo;
    for (const loader::Symbol &s : loader::load_file(*dir_ / "arm" / "arm32-O2.elf", lo).symbols)
      if (s.defined && s.type == loader::SymbolType::func) (*at_)[s.name] = s.value & ~std::uint64_t{1};
    loader::RawOptions raw;
    raw.language = "ARM:LE:32:v5t:default";
    raw.base = 0x02000000;
    raw.entry = 0x02000000;
    raw.regions = {loader::parse_raw_region("ram:2200000:10000"), loader::parse_raw_region("stack:23e0000:20000")};
    image_ = new std::shared_ptr<const loader::Image>(
        std::make_shared<const loader::Image>(loader::load_raw_file(*dir_ / "arm" / "arm32-O2.bin", raw)));
    db_ = new facts::FactDb();
    analysis::register_queries(db_->engine());
    register_queries(db_->engine());
    {
      auto tx = db_->begin();
      analysis::stage_image(tx, kProgram, **image_, analysis::describe(**image_, raw.language));
      stage_image(tx, kProgram, *image_, raw.language, "arm32-O2");
      tx.commit();
    }
    facts::ThreadPool pool(4);
    snap_ = new facts::Snapshot(db_->snapshot());
    result_ = new FixpointResult(run(*snap_, kProgram, &pool));
  }
  static void TearDownTestSuite() {
    delete result_;
    delete snap_;
    delete db_;
    delete image_;
    delete dir_;
  }
  void SetUp() override {
    if (result_ == nullptr) GTEST_SKIP() << "no Ghidra, clang or ld.lld for the ARM fixture";
  }

  static std::optional<Prototype> proto(const char *name) {
    auto it = at_->find(name);
    if (it == at_->end()) return std::nullopt;
    return prototype_for(*snap_, {kProgram, it->second});
  }
  static std::string show(const char *name) {
    auto p = proto(name);
    return p ? p->print(name, data_org(**image_)) : std::string("(none)");
  }

  static inline const analysis::ProgramKey kProgram{"arm32"};
  static inline std::filesystem::path *dir_ = nullptr;
  static inline std::map<std::string, std::uint64_t> *at_ = new std::map<std::string, std::uint64_t>();
  static inline std::shared_ptr<const loader::Image> *image_ = nullptr;
  static inline facts::FactDb *db_ = nullptr;
  static inline facts::Snapshot *snap_ = nullptr;
  static inline FixpointResult *result_ = nullptr;
};

TEST_F(Arm32, InferenceRunsOnArmAndThumb) {
  EXPECT_TRUE(supports("ARM:LE:32:v5t:default", **image_));
  EXPECT_TRUE(result_->converged);
  EXPECT_LE(result_->rounds, 16u);
}

// The SDK's restore takes the state its callers pass in r0 (ARM code
// written in assembly, called from ARM and Thumb code alike).
TEST_F(Arm32, InterruptRestoreTakesItsArgument) {
  auto p = proto("OS_RestoreInterrupts");
  ASSERT_TRUE(p) << show("OS_RestoreInterrupts");
  EXPECT_EQ(p->params.size(), 1u) << show("OS_RestoreInterrupts");
  auto d = proto("OS_DisableInterrupts");
  ASSERT_TRUE(d);
  EXPECT_TRUE(d->params.empty()) << show("OS_DisableInterrupts");
  EXPECT_FALSE(d->ret.is_void()) << show("OS_DisableInterrupts");
}

// Four arguments in r0-r3 and three on the stack.
TEST_F(Arm32, StackArgumentsPastR3) {
  auto p = proto("mix7");
  ASSERT_TRUE(p);
  EXPECT_EQ(p->params.size(), 7u) << show("mix7");
}

// Thumb code: decoded as Thumb, so its parameters are seen (h_read is
// reached only through a table of Thumb pointers).
TEST_F(Arm32, ThumbFunctionsAreObserved) {
  for (const char *name : {"queue_len", "h_read", "h_write", "run_handlers", "fmt_int"}) {
    auto p = proto(name);
    ASSERT_TRUE(p) << name;
    EXPECT_GE(p->params.size(), name == std::string("queue_len") ? 1u : 2u) << show(name);
  }
}

// A veneer and a Thumb-to-ARM stub have their targets' prototypes.
TEST_F(Arm32, ThunksTakeTheirTargetsPrototypes) {
  auto veneer = proto("dev_dispatch_veneer"), target = proto("dev_dispatch");
  ASSERT_TRUE(veneer && target);
  EXPECT_EQ(veneer->params.size(), target->params.size()) << show("dev_dispatch_veneer") << " / " << show("dev_dispatch");
  auto stub = proto("bd_read_from_thumb"), read = proto("bd_read");
  ASSERT_TRUE(stub && read);
  EXPECT_EQ(read->params.size(), 5u) << show("bd_read");
  EXPECT_EQ(stub->params.size(), read->params.size()) << show("bd_read_from_thumb");
}

// Block numbers, offsets and sizes stay integers; the device is a
// structure (a word parameter read and written at several offsets).
TEST_F(Arm32, IntegersStayIntegersAndStructuresArePointers) {
  auto read = proto("bd_read");
  ASSERT_TRUE(read && read->params.size() == 5) << show("bd_read");
  EXPECT_TRUE(read->params[0].is_pointer()) << show("bd_read");
  for (std::size_t i : {1u, 2u, 4u}) EXPECT_FALSE(read->params[i].is_pointer()) << show("bd_read");
  auto erase = proto("bd_erase");
  ASSERT_TRUE(erase && erase->params.size() == 2) << show("bd_erase");
  EXPECT_FALSE(erase->params[1].is_pointer()) << show("bd_erase");
  for (const char *name : {"dev_init", "dev_touch", "h_read"}) {
    auto p = proto(name);
    ASSERT_TRUE(p && !p->params.empty()) << show(name);
    ASSERT_TRUE(p->params[0].is_pointer()) << show(name);
    EXPECT_EQ(p->params[0].target().meta, Meta::struct_) << show(name);
  }
  auto init = proto("dev_init");
  ASSERT_EQ(init->params.size(), 4u) << show("dev_init");
  EXPECT_FALSE(init->params[1].is_pointer()) << show("dev_init");
  EXPECT_FALSE(result_->structures.empty());
}

}  // namespace
}  // namespace revkit::infer
