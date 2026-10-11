// The demangler analysis through the API (docs/demangle.md): demangled
// names in the function list, symbols, listing and decompiler, searches by
// either spelling, and the mangled signature's prototype at import rank.
#include "builders.hh"

#include "revkit/backend/image_backend.h"

#include <gtest/gtest.h>

#include <filesystem>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
using api::CallContext;

// A C++ library with no standard library, built stripped: its exports
// keep their mangled names.
constexpr const char *kLibrary = R"(
namespace geo {
struct Point { double x, y; };
class Shape {
 public:
  explicit Shape(int id);
  virtual ~Shape();
  virtual double area() const;
  void scale(double factor);
  double grow(double factor);
  static int count();
  int id_;
  double size_;
};
static int created;
Shape::Shape(int id) : id_(id), size_(1) { ++created; }
Shape::~Shape() { --created; }
double Shape::area() const { return size_ * size_; }
__attribute__((noinline)) void Shape::scale(double factor) { size_ *= factor; }
double Shape::grow(double factor) {
  scale(factor);
  return area();
}
int Shape::count() { return created; }
__attribute__((noinline)) double distance(const Point &a, const Point &b) {
  double dx = a.x - b.x, dy = a.y - b.y;
  return dx * dx + dy * dy;
}
double far(const Point *pts, int n) {
  double best = 0;
  for (int i = 1; i < n; ++i) {
    double d = distance(pts[0], pts[i]);
    if (d > best) best = d;
  }
  return best;
}
}  // namespace geo
)";

std::string Text(const pb::DecompiledFunction &f) {
  std::string out;
  for (const auto &line : f.lines()) {
    for (const auto &t : line.tokens()) out += t.text();
    out += '\n';
  }
  return out;
}

class DemangleTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) return;
    auto dir = testing::scratch_dir("demangle");
    lib_ = dir / "libgeo.so";
    compiled_ = testing::compile(REVKIT_TEST_CC, kLibrary,
                                 "-x c++ -O1 -fPIC -shared -fno-exceptions -fno-rtti -fno-inline -s", lib_);
  }

  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!compiled_) GTEST_SKIP() << "no C++ compiler";
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    backend_ = MakeImageBackend(o);
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path(lib_.string());
    pb::ImportProgramResponse resp;
    auto st = backend_->ImportProgram(ctx_, req, resp);
    ASSERT_TRUE(st.ok()) << st.message;
    id_ = resp.program().program_id();
  }

  std::vector<pb::Function> Functions(const std::string &contains = {}) {
    pb::ListFunctionsRequest req;
    req.set_program_id(id_);
    req.set_name_contains(contains);
    req.mutable_page()->set_page_size(5000);
    pb::ListFunctionsResponse resp;
    EXPECT_TRUE(backend_->ListFunctions(ctx_, req, resp).ok());
    return {resp.functions().begin(), resp.functions().end()};
  }

  // The function itself, not a PLT stub named after it.
  pb::Function Function(const std::string &name) {
    for (const pb::Function &f : Functions())
      if (f.name() == name && !f.thunk()) return f;
    ADD_FAILURE() << "no function " << name;
    return {};
  }

  pb::DecompiledFunction Decompile(std::uint64_t entry) {
    pb::DecompileRequest req;
    req.set_program_id(id_);
    req.mutable_function()->set_offset(entry);
    pb::DecompileResponse resp;
    auto st = backend_->Decompile(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.function();
  }

  api::Status Retype(std::uint64_t entry, const std::string &c, pb::ProvenanceKind who) {
    pb::AppendAssertionsRequest req;
    req.set_program_id(id_);
    req.mutable_provenance()->set_kind(who);
    req.mutable_provenance()->set_id(who == pb::PROVENANCE_KIND_USER ? "alice" : "model");
    auto *r = req.add_assertions()->mutable_body()->mutable_retype();
    r->mutable_target()->mutable_address()->set_offset(entry);
    r->mutable_type()->set_c_declaration(c);
    pb::AppendAssertionsResponse resp;
    return backend_->AppendAssertions(ctx_, req, resp);
  }

  static inline std::filesystem::path lib_;
  static inline bool compiled_ = false;
  CallContext ctx_;
  std::unique_ptr<api::Backend> backend_;
  std::string id_;
};

TEST_F(DemangleTest, FunctionListShowsDemangledNames) {
  pb::Function scale = Function("geo::Shape::scale");
  EXPECT_EQ(scale.demangled().mangled(), "_ZN3geo5Shape5scaleEd");
  EXPECT_EQ(scale.demangled().full(), "geo::Shape::scale(double)");
  EXPECT_EQ(scale.name_origin().derived().rule(), "analysis.demangler");
  pb::Function ctor = Function("geo::Shape::Shape");
  EXPECT_FALSE(ctor.demangled().mangled().empty());
  Function("geo::Shape::~Shape");
  Function("geo::distance");
  for (const pb::Function &f : Functions()) EXPECT_FALSE(f.name().starts_with("_Z")) << f.name();
}

TEST_F(DemangleTest, SearchFindsEitherSpelling) {
  // (The function and its PLT stub.)
  auto by_demangled = Functions("shape::scale");
  ASSERT_FALSE(by_demangled.empty());
  for (const pb::Function &f : by_demangled) EXPECT_EQ(f.name(), "geo::Shape::scale");
  auto by_mangled = Functions("_ZN3geo5Shape5scale");
  ASSERT_EQ(by_mangled.size(), by_demangled.size());
  for (const pb::Function &f : by_mangled) EXPECT_EQ(f.name(), "geo::Shape::scale");

  pb::ListSymbolsRequest req;
  req.set_program_id(id_);
  req.set_name_equals("_ZN3geo8distanceERKNS_5PointES2_");
  pb::ListSymbolsResponse resp;
  ASSERT_TRUE(backend_->ListSymbols(ctx_, req, resp).ok());
  ASSERT_GE(resp.symbols_size(), 1);
  EXPECT_EQ(resp.symbols(0).name(), "geo::distance");
  EXPECT_EQ(resp.symbols(0).demangled().mangled(), "_ZN3geo8distanceERKNS_5PointES2_");
}

TEST_F(DemangleTest, PrototypeFromTheMangledName) {
  pb::Function scale = Function("geo::Shape::scale");
  EXPECT_EQ(scale.prototype(), "undefined geo::Shape::scale(geo::Shape *this, double param_2)");
  EXPECT_EQ(scale.prototype_origin().derived().rule(), "analysis.demangler");
  pb::Function distance = Function("geo::distance");
  EXPECT_EQ(distance.prototype(), "undefined geo::distance(const geo::Point *param_1, const geo::Point *param_2)");
  // The decompiler is given it: `this` typed, in the class's namespace.
  const std::string c = Text(Decompile(scale.entry().offset()));
  EXPECT_NE(c.find("geo::Shape::scale(Shape *this,double param_2)"), std::string::npos) << c;
  // Callers name the callee as the decompiler qualifies it from there,
  // and the token carries the other spellings.
  pb::DecompiledFunction grow = Decompile(Function("geo::Shape::grow").entry().offset());
  EXPECT_NE(Text(grow).find("scale("), std::string::npos) << Text(grow);
  bool mangled_token = false;
  for (const auto &line : grow.lines())
    for (const auto &t : line.tokens())
      if (t.demangled().mangled() == "_ZN3geo5Shape5scaleEd") mangled_token = true;
  EXPECT_TRUE(mangled_token);
  pb::DecompiledFunction far = Decompile(Function("geo::far").entry().offset());
  EXPECT_NE(Text(far).find("distance("), std::string::npos) << Text(far);
  EXPECT_EQ(Text(far).find("_ZN"), std::string::npos) << Text(far);
}

TEST_F(DemangleTest, PrototypeRanksAsAnImport) {
  const std::uint64_t entry = Function("geo::Shape::scale").entry().offset();
  // An agent's prototype doesn't replace the demangled one...
  ASSERT_TRUE(Retype(entry, "int scale(int x)", pb::PROVENANCE_KIND_AGENT).ok());
  pb::Function after_agent = Function("geo::Shape::scale");
  EXPECT_EQ(after_agent.prototype(), "undefined geo::Shape::scale(geo::Shape *this, double param_2)");
  EXPECT_EQ(after_agent.prototype_origin().derived().rule(), "analysis.demangler");
  EXPECT_NE(Text(Decompile(entry)).find("Shape *this"), std::string::npos);
  // ...the user's does.
  ASSERT_TRUE(Retype(entry, "int scale(int x)", pb::PROVENANCE_KIND_USER).ok());
  pb::Function after_user = Function("geo::Shape::scale");
  EXPECT_EQ(after_user.prototype(), "int scale(int x)");
  EXPECT_TRUE(after_user.prototype_origin().has_asserted());
  EXPECT_NE(Text(Decompile(entry)).find("(int x)"), std::string::npos) << Text(Decompile(entry));
}

TEST_F(DemangleTest, ListingCarriesTheOtherSpellings) {
  const std::uint64_t entry = Function("geo::Shape::scale").entry().offset();
  pb::GetListingRequest req;
  req.set_program_id(id_);
  req.mutable_addresses()->mutable_start()->set_offset(entry);
  req.mutable_addresses()->set_rows_before(4);
  req.mutable_addresses()->set_max_rows(12);
  req.set_header_rows(true);
  pb::GetListingResponse resp;
  auto st = backend_->GetListing(ctx_, req, resp);
  ASSERT_TRUE(st.ok()) << st.message;
  bool label = false, signature = false;
  for (const auto &row : resp.rows()) {
    if (row.kind() != pb::LISTING_ROW_KIND_HEADER || row.address().offset() != entry) continue;
    if (row.header().kind() == pb::LISTING_HEADER_KIND_LABEL) {
      label = true;
      EXPECT_EQ(row.header().text(), "geo::Shape::scale");
      EXPECT_EQ(row.header().demangled().mangled(), "_ZN3geo5Shape5scaleEd");
      ASSERT_EQ(row.labels_size(), 1);
      EXPECT_EQ(row.labels(0).demangled().mangled(), "_ZN3geo5Shape5scaleEd");
    }
    if (row.header().kind() == pb::LISTING_HEADER_KIND_SIGNATURE) {
      signature = true;
      EXPECT_EQ(row.header().text(), "undefined geo::Shape::scale(geo::Shape *this, double param_2)");
    }
  }
  EXPECT_TRUE(label);
  EXPECT_TRUE(signature);
}

TEST_F(DemangleTest, ARenameReplacesTheDemangledName) {
  const std::uint64_t entry = Function("geo::Shape::scale").entry().offset();
  pb::AppendAssertionsRequest req;
  req.set_program_id(id_);
  req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  req.mutable_provenance()->set_id("alice");
  auto *r = req.add_assertions()->mutable_body()->mutable_rename();
  r->mutable_target()->mutable_address()->set_offset(entry);
  r->set_name("resize");
  pb::AppendAssertionsResponse resp;
  ASSERT_TRUE(backend_->AppendAssertions(ctx_, req, resp).ok());
  pb::Function f = Function("resize");
  EXPECT_FALSE(f.has_demangled());  // the shown name isn't the demangled one
  // The decompiler prints the new name alone, not in the old namespaces.
  const std::string c = Text(Decompile(entry));
  EXPECT_NE(c.find("resize(Shape *this"), std::string::npos) << c;
  EXPECT_EQ(c.find("geo::Shape::resize"), std::string::npos) << c;
}

}  // namespace
}  // namespace revkit::backend
