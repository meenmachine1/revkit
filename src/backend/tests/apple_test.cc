// Apple applications through the API (docs/apple-apps.md), on
// tests/data/apple's fixtures (build.sh: clang and ld64.lld, then
// make_bundle.py): an .ipa and a macOS .app as file systems, their bundles
// (layout, Info.plist, executable, code signature, nested bundles,
// interface files, provisioning profile), property lists, a main
// executable imported with the framework it loads by @rpath (and an app
// extension finding the same one through @executable_path/../..), and a
// program's code signature in its summary.
#include "apple_fixture.h"

#include "revkit/backend/image_backend.h"

#include <gtest/gtest.h>

#include <map>
#include <set>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
using api::CallContext;

class AppleApi : public ::testing::Test {
 protected:
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    const auto &d = apple_testing::bundles(REVKIT_TEST_CLANG, REVKIT_TEST_LD64, REVKIT_APPLE_FIXTURE);
    if (!d) GTEST_SKIP() << "clang or ld64.lld missing, or the fixtures didn't build";
    dir_ = *d;
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    backend_ = MakeImageBackend(o);
  }

  std::string Open(const std::filesystem::path &p) {
    pb::OpenFileSystemRequest req;
    req.set_project_id("default");
    req.set_host_path(p.string());
    pb::OpenFileSystemResponse resp;
    auto st = backend_->OpenFileSystem(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.session_id();
  }
  std::map<std::string, pb::FileSystemEntry> List(const std::string &sid, const std::string &path) {
    pb::ListFileSystemRequest req;
    req.set_session_id(sid);
    req.set_path(path);
    req.set_detect(true);
    pb::ListFileSystemResponse resp;
    auto st = backend_->ListFileSystem(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    std::map<std::string, pb::FileSystemEntry> out;
    for (const auto &e : resp.entries()) out[e.name()] = e;
    return out;
  }
  pb::GetAppleBundleResponse Bundle(const std::string &sid, const std::string &path) {
    pb::GetAppleBundleRequest req;
    req.set_session_id(sid);
    req.set_path(path);
    pb::GetAppleBundleResponse resp;
    auto st = backend_->GetAppleBundle(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }
  const pb::AppleBundleRef *Nested(const pb::AppleBundle &b, const std::string &kind) {
    for (const auto &n : b.nested())
      if (n.kind() == kind) return &n;
    return nullptr;
  }
  pb::ImportFromFileSystemResponse Import(const std::string &sid, const std::string &path) {
    pb::ImportFromFileSystemRequest req;
    req.set_session_id(sid);
    req.set_project_id("default");
    req.add_paths(path);
    req.mutable_options()->set_import_libraries(true);
    req.mutable_options()->set_library_depth(1);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    pb::ImportFromFileSystemResponse resp;
    auto st = backend_->ImportFromFileSystem(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  std::filesystem::path dir_;
  std::unique_ptr<api::Backend> backend_;
  CallContext ctx_;
};

TEST_F(AppleApi, AnIpaListsItsBundlesAndFormats) {
  const std::string sid = Open(dir_ / "Demo.ipa");
  auto payload = List(sid, "/Payload");
  ASSERT_TRUE(payload.count("Demo.app"));
  EXPECT_EQ(payload["Demo.app"].bundle_kind(), "app");
  auto app = List(sid, "/Payload/Demo.app");
  EXPECT_EQ(app["Info.plist"].content_kind(), "plist:binary");
  EXPECT_EQ(app["embedded.mobileprovision"].content_kind(), "mobileprovision");
  EXPECT_EQ(app["SettingsController.nib"].content_kind(), "nib:archive");
  EXPECT_NE(app["SettingsController.nib"].detected().find("NIBArchive"), std::string::npos);
  EXPECT_EQ(app["Demo"].detected_kind(), "macho");
  auto fw = List(sid, "/Payload/Demo.app/Frameworks");
  EXPECT_EQ(fw["Greeter.framework"].bundle_kind(), "framework");
  EXPECT_EQ(List(sid, "/Payload/Demo.app/Frameworks/Greeter.framework")["Info.plist"].content_kind(), "plist:xml");
  EXPECT_EQ(List(sid, "/Payload/Demo.app/Base.lproj")["Main.storyboardc"].bundle_kind(), "storyboardc");
  // The .ipa itself, from a session on its directory.
  const std::string outer = Open(dir_);
  auto top = List(outer, "/");
  EXPECT_EQ(top["Demo.ipa"].content_kind(), "ipa");
  EXPECT_NE(top["Demo.ipa"].detected().find("iOS app"), std::string::npos);
  EXPECT_EQ(top["MacDemo.app"].bundle_kind(), "app");
}

TEST_F(AppleApi, TheIosBundle) {
  const std::string sid = Open(dir_ / "Demo.ipa");
  // The archive's root finds Payload/Demo.app; so does the app's directory
  // and a file inside it.
  for (const char *path : {"/", "/Payload/Demo.app", "/Payload/Demo.app/Base.lproj/Main.storyboardc/Info.plist"}) {
    SCOPED_TRACE(path);
    const pb::GetAppleBundleResponse r = Bundle(sid, path);
    EXPECT_EQ(r.bundle().path(), "/Payload/Demo.app");
  }
  const pb::GetAppleBundleResponse r = Bundle(sid, "/");
  ASSERT_EQ(r.apps_size(), 1);
  EXPECT_EQ(r.apps(0).identifier(), "com.example.demo");
  const pb::AppleBundle &b = r.bundle();
  EXPECT_EQ(b.kind(), "app");
  EXPECT_EQ(b.layout(), "shallow");
  EXPECT_EQ(b.platform(), "ios");
  EXPECT_EQ(b.container_path(), "zip://Demo.ipa!/Payload/Demo.app");
  EXPECT_EQ(b.info_plist_path(), "/Payload/Demo.app/Info.plist");
  EXPECT_EQ(b.info().identifier(), "com.example.demo");
  EXPECT_EQ(b.info().short_version(), "1.2.3");
  EXPECT_EQ(b.info().minimum_os(), "15.0");
  ASSERT_EQ(b.info().url_schemes_size(), 2);
  EXPECT_EQ(b.info().url_schemes(1), "demo-auth");
  ASSERT_EQ(b.info().usage_descriptions_size(), 2);
  EXPECT_EQ(b.info().usage_descriptions(1).key(), "NSLocationWhenInUseUsageDescription");
  EXPECT_EQ(b.info().exported_types(0).identifier(), "com.example.demo.document");
  EXPECT_EQ(b.info().background_modes_size(), 2);
  ASSERT_TRUE(b.info_plist().has_dict_value());
  EXPECT_EQ(b.executable_path(), "/Payload/Demo.app/Demo");
  EXPECT_NE(b.executable_detected().find("Mach-O 64-bit arm64"), std::string::npos);
  // The main executable's signature: read, not verified.
  ASSERT_GE(b.code_signature().code_directories_size(), 1);
  const pb::CodeDirectory &cd = b.code_signature().code_directories(0);
  EXPECT_EQ(cd.identifier(), "com.example.demo");
  EXPECT_EQ(cd.team_id(), "ABCDE12345");
  EXPECT_EQ(cd.flag_names(0), "runtime");
  bool app_id = false;
  for (const auto &e : b.code_signature().entitlements().dict_value().entries())
    app_id |= e.key() == "application-identifier" && e.value().string_value() == "ABCDE12345.com.example.demo";
  EXPECT_TRUE(app_id);
  EXPECT_GT(b.code_signature().size(), 0u);
  // Nested bundles, by where they sit.
  const pb::AppleBundleRef *fw = Nested(b, "framework");
  ASSERT_NE(fw, nullptr);
  EXPECT_EQ(fw->role(), "framework");
  EXPECT_EQ(fw->identifier(), "com.example.greeter");
  EXPECT_EQ(fw->executable_path(), "/Payload/Demo.app/Frameworks/Greeter.framework/Greeter");
  const pb::AppleBundleRef *ext = Nested(b, "appex");
  ASSERT_NE(ext, nullptr);
  EXPECT_EQ(ext->role(), "app-extension");
  EXPECT_EQ(ext->extension_point(), "com.apple.share-services");
  EXPECT_EQ(ext->executable_path(), "/Payload/Demo.app/PlugIns/Share.appex/Share");
  EXPECT_EQ(b.nested_size(), 2);
  std::set<std::string> ib(b.interface_files().begin(), b.interface_files().end());
  EXPECT_TRUE(ib.count("/Payload/Demo.app/Base.lproj/Main.storyboardc"));
  EXPECT_TRUE(ib.count("/Payload/Demo.app/SettingsController.nib"));
  EXPECT_EQ(b.provisioning_profile_path(), "/Payload/Demo.app/embedded.mobileprovision");
  EXPECT_EQ(b.provisioning_profile().name(), "Demo Development");
  EXPECT_EQ(b.provisioning_profile().kind(), "development");
  EXPECT_EQ(b.provisioning_profile().provisioned_devices(), 2u);
  EXPECT_EQ(b.code_resources_path(), "/Payload/Demo.app/_CodeSignature/CodeResources");
  EXPECT_TRUE(b.warnings().empty()) << b.warnings(0);
  // The framework by itself; the extension too.
  const pb::AppleBundle f = Bundle(sid, fw->path()).bundle();
  EXPECT_EQ(f.info().package_type(), "FMWK");
  EXPECT_EQ(f.code_signature().code_directories(0).identifier(), "Greeter");
  EXPECT_TRUE(f.code_signature().adhoc());
  EXPECT_EQ(Bundle(sid, ext->path()).bundle().info().principal_class(), "ShareViewController");
  // Not a bundle, nor in one.
  pb::GetAppleBundleRequest bad;
  bad.set_session_id(Open(dir_));
  bad.set_path("/bin/Demo");
  pb::GetAppleBundleResponse bad_resp;
  EXPECT_EQ(backend_->GetAppleBundle(ctx_, bad, bad_resp).code, api::StatusCode::kNotFound);
}

TEST_F(AppleApi, TheMacBundleAndAVersionedFramework) {
  const std::string sid = Open(dir_);
  const pb::AppleBundle b = Bundle(sid, "/MacDemo.app").bundle();
  EXPECT_EQ(b.layout(), "deep");
  EXPECT_EQ(b.platform(), "macos");
  EXPECT_EQ(b.info().identifier(), "com.example.macdemo");
  EXPECT_EQ(b.info().minimum_os(), "12.0");
  EXPECT_EQ(b.info().main_nib(), "MainMenu");
  EXPECT_EQ(b.executable_path(), "/MacDemo.app/Contents/MacOS/MacDemo");
  ASSERT_EQ(b.nested_size(), 1);
  EXPECT_EQ(b.nested(0).identifier(), "com.example.greeter");
  EXPECT_EQ(b.nested(0).executable_path(), "/MacDemo.app/Contents/Frameworks/Greeter.framework/Versions/A/Greeter");
  ASSERT_EQ(b.interface_files_size(), 1);
  EXPECT_EQ(b.interface_files(0), "/MacDemo.app/Contents/Resources/MainMenu.nib");
  const pb::AppleBundle f = Bundle(sid, b.nested(0).path()).bundle();
  EXPECT_EQ(f.layout(), "versioned");
  EXPECT_EQ(f.info_plist_path(), "/MacDemo.app/Contents/Frameworks/Greeter.framework/Versions/A/Resources/Info.plist");
  EXPECT_EQ(List(sid, "/MacDemo.app/Contents/Resources")["MainMenu.nib"].content_kind(), "nib:keyed");
}

TEST_F(AppleApi, PropertyLists) {
  const std::string sid = Open(dir_ / "Demo.ipa");
  pb::ReadPropertyListRequest req;
  req.set_session_id(sid);
  req.set_path("/Payload/Demo.app/Info.plist");
  pb::ReadPropertyListResponse resp;
  ASSERT_TRUE(backend_->ReadPropertyList(ctx_, req, resp).ok());
  EXPECT_EQ(resp.format(), "binary");
  EXPECT_FALSE(resp.truncated());
  EXPECT_FALSE(resp.keyed_archive());
  EXPECT_GT(resp.values(), 50u);
  ASSERT_TRUE(resp.root().has_dict_value());
  bool id = false;
  for (const auto &e : resp.root().dict_value().entries())
    id |= e.key() == "CFBundleIdentifier" && e.value().string_value() == "com.example.demo";
  EXPECT_TRUE(id);
  // A small budget: entries left out, and said so.
  req.set_max_values(5);
  pb::ReadPropertyListResponse small;
  ASSERT_TRUE(backend_->ReadPropertyList(ctx_, req, small).ok());
  EXPECT_TRUE(small.truncated());
  EXPECT_LE(small.root().dict_value().entries_size(), 5);  // nested values count too
  EXPECT_GT(small.root().omitted(), 0u);
  // A provisioning profile's plist; a keyed archive (from the macOS app).
  req.set_max_values(0);
  req.set_path("/Payload/Demo.app/embedded.mobileprovision");
  pb::ReadPropertyListResponse profile;
  ASSERT_TRUE(backend_->ReadPropertyList(ctx_, req, profile).ok());
  EXPECT_EQ(profile.format(), "mobileprovision");
  pb::ReadPropertyListRequest keyed;
  keyed.set_session_id(Open(dir_));
  keyed.set_path("/MacDemo.app/Contents/Resources/MainMenu.nib");
  pb::ReadPropertyListResponse kr;
  ASSERT_TRUE(backend_->ReadPropertyList(ctx_, keyed, kr).ok());
  EXPECT_TRUE(kr.keyed_archive());
  // Not a plist.
  req.set_path("/Payload/Demo.app/Demo");
  pb::ReadPropertyListResponse not_plist;
  EXPECT_EQ(backend_->ReadPropertyList(ctx_, req, not_plist).code, api::StatusCode::kInvalidArgument);
}

TEST_F(AppleApi, TheMainExecutableWithItsFramework) {
  const std::string sid = Open(dir_ / "Demo.ipa");
  // Demo loads @rpath/Greeter.framework/Greeter with the rpath
  // @executable_path/Frameworks.
  const pb::ImportFromFileSystemResponse r = Import(sid, "/Payload/Demo.app/Demo");
  ASSERT_EQ(r.items_size(), 2);
  EXPECT_EQ(r.items(0).action(), "imported");
  EXPECT_EQ(r.items(1).action(), "imported");
  EXPECT_EQ(r.items(1).library_of(), "Demo");
  EXPECT_EQ(r.items(1).path(), "/Payload/Demo.app/Frameworks/Greeter.framework/Greeter");
  EXPECT_EQ(r.items(1).program().name(), "Greeter");
  for (const auto &m : r.libraries_not_found())
    EXPECT_NE(m.name(), "@rpath/Greeter.framework/Greeter");
  const std::string greeter = r.items(1).program().program_id();
  // The extension finds the same framework through
  // @executable_path/../../Frameworks: linked, not imported again.
  const pb::ImportFromFileSystemResponse s = Import(sid, "/Payload/Demo.app/PlugIns/Share.appex/Share");
  ASSERT_EQ(s.items_size(), 1);
  pb::ListProgramLibrariesRequest lr;
  lr.set_program_id(s.items(0).program().program_id());
  pb::ListProgramLibrariesResponse libs;
  ASSERT_TRUE(backend_->ListProgramLibraries(ctx_, lr, libs).ok());
  bool linked = false;
  for (const auto &l : libs.libraries()) linked |= l.name() == "@rpath/Greeter.framework/Greeter" && l.program_id() == greeter;
  EXPECT_TRUE(linked);

  // The program's summary has its code signature.
  pb::GetProgramSummaryRequest sr;
  sr.set_program_id(r.items(0).program().program_id());
  pb::GetProgramSummaryResponse summary;
  ASSERT_TRUE(backend_->GetProgramSummary(ctx_, sr, summary).ok());
  const pb::CodeSignature &sig = summary.summary().macho().code_signature();
  ASSERT_EQ(sig.code_directories_size(), 2);
  EXPECT_EQ(sig.code_directories(0).identifier(), "com.example.demo");
  EXPECT_EQ(sig.code_directories(1).hash_type(), "sha256");
  EXPECT_TRUE(sig.code_directories(1).alternate());
  ASSERT_EQ(sig.requirements_size(), 1);
  EXPECT_EQ(sig.requirements(0).type_name(), "designated");
  EXPECT_EQ(sig.certificates(0).organizational_unit(), "ABCDE12345");
  EXPECT_TRUE(sig.has_der_entitlements());
  EXPECT_TRUE(sig.entitlements().has_dict_value());
}

TEST_F(AppleApi, AMacExecutableFindsItsVersionedFramework) {
  const std::string sid = Open(dir_);
  // @rpath/Greeter.framework/Versions/A/Greeter, rpath @executable_path/../Frameworks.
  const pb::ImportFromFileSystemResponse r = Import(sid, "/MacDemo.app/Contents/MacOS/MacDemo");
  ASSERT_EQ(r.items_size(), 2);
  EXPECT_EQ(r.items(1).path(), "/MacDemo.app/Contents/Frameworks/Greeter.framework/Versions/A/Greeter");
}

// Interface Builder (api_minor 101, feature "ui-actions").
const pb::UiAction *Action(const pb::ListUiActionsResponse &r, const std::string &selector) {
  for (const auto &a : r.actions())
    if (a.selector() == selector) return &a;
  return nullptr;
}

TEST_F(AppleApi, UiActionsBeforeTheProgramIsImported) {
  const std::string sid = Open(dir_ / "Demo.ipa");
  pb::ListUiActionsRequest req;
  req.set_session_id(sid);
  req.set_path("/");
  req.set_include_documents(true);
  pb::ListUiActionsResponse r;
  auto st = backend_->ListUiActions(ctx_, req, r);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(r.program_id(), "");
  ASSERT_EQ(r.documents_size(), 3);  // the scene's two nibs (the view's runtime.nib) and SettingsController.nib
  std::map<std::string, const pb::InterfaceDocument *> docs;
  for (const auto &d : r.documents()) docs[d.path()] = &d;
  const auto *view = docs["/Payload/Demo.app/Base.lproj/Main.storyboardc/BYZ-38-t0r-view-8bC-Xf-vdC.nib/runtime.nib"];
  ASSERT_NE(view, nullptr);
  EXPECT_EQ(view->storyboard(), "/Payload/Demo.app/Base.lproj/Main.storyboardc");
  EXPECT_EQ(view->owner_class(), "ViewController");
  EXPECT_EQ(view->owner_class_from(), "storyboard");
  EXPECT_GT(view->objects_size(), 3);
  EXPECT_EQ(r.actions_size(), 6);
  const pb::UiAction *tap = Action(r, "buttonTapped:");
  ASSERT_NE(tap, nullptr);
  EXPECT_EQ(tap->resolution(), "no-program");
  EXPECT_EQ(tap->target(), "files-owner");
  EXPECT_EQ(tap->target_class(), "ViewController");
  EXPECT_EQ(tap->control_class(), "UIButton");
  EXPECT_EQ(tap->control_label(), "Tap me");
  ASSERT_EQ(tap->events_size(), 1);
  EXPECT_EQ(tap->events(0), "touchUpInside");
  // One nib by itself.
  req.set_path("/Payload/Demo.app/SettingsController.nib");
  pb::ListUiActionsResponse one;
  ASSERT_TRUE(backend_->ListUiActions(ctx_, req, one).ok());
  EXPECT_EQ(one.documents_size(), 1);
  EXPECT_EQ(one.actions_size(), 3);
}

TEST_F(AppleApi, UiActionsResolveToTheirMethods) {
  const std::string sid = Open(dir_ / "Demo.ipa");
  const pb::ImportFromFileSystemResponse imp = Import(sid, "/Payload/Demo.app/Demo");
  const std::string demo = imp.items(0).program().program_id();
  pb::ListUiActionsRequest req;
  req.set_session_id(sid);
  req.set_path("/Payload/Demo.app");
  pb::ListUiActionsResponse r;
  auto st = backend_->ListUiActions(ctx_, req, r);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(r.program_id(), demo);  // found by the executable's container path
  // The storyboard scene's view: File's Owner is its ViewController.
  const pb::UiAction *tap = Action(r, "buttonTapped:");
  ASSERT_NE(tap, nullptr);
  EXPECT_EQ(tap->resolution(), "resolved");
  EXPECT_EQ(tap->method(), "-[ViewController buttonTapped:]");
  EXPECT_EQ(tap->function_name(), "-[ViewController buttonTapped:]");
  EXPECT_TRUE(tap->has_implementation());
  EXPECT_NE(tap->implementation().offset(), 0u);
  EXPECT_EQ(Action(r, "sliderChanged:")->method(), "-[ViewController sliderChanged:]");
  // The first responder: the one class implementing copyAll:.
  const pb::UiAction *copy = Action(r, "copyAll:");
  EXPECT_EQ(copy->target(), "first-responder");
  EXPECT_EQ(copy->resolution(), "resolved-by-selector");
  EXPECT_EQ(copy->method(), "-[TextResponder copyAll:]");
  // A standalone nib whose name is a class's: UIKit's default nib name.
  const pb::UiAction *save = Action(r, "save:");
  EXPECT_EQ(save->target_class(), "SettingsController");
  EXPECT_EQ(save->target_class_from(), "nib-name");
  EXPECT_EQ(save->resolution(), "resolved");
  EXPECT_EQ(save->method(), "-[SettingsController save:]");
  EXPECT_EQ(Action(r, "undefinedAction:")->resolution(), "unresolved");
  // Outlets: File's Owner's class.
  bool outlet = false;
  for (const auto &o : r.outlets())
    outlet |= o.name() == "greetingLabel" && o.source_class() == "ViewController" && o.destination_class() == "GreetingLabel";
  EXPECT_TRUE(outlet);
  // Against a program named explicitly: the framework has none of these.
  req.set_program_id(imp.items(1).program().program_id());
  pb::ListUiActionsResponse other;
  ASSERT_TRUE(backend_->ListUiActions(ctx_, req, other).ok());
  EXPECT_EQ(Action(other, "buttonTapped:")->resolution(), "external");
}

TEST_F(AppleApi, MacUiActionsAndAKeyedArchive) {
  const std::string sid = Open(dir_);
  Import(sid, "/MacDemo.app/Contents/MacOS/MacDemo");
  pb::ListUiActionsRequest req;
  req.set_session_id(sid);
  req.set_path("/MacDemo.app");
  pb::ListUiActionsResponse r;
  ASSERT_TRUE(backend_->ListUiActions(ctx_, req, r).ok());
  ASSERT_EQ(r.documents_size(), 1);
  EXPECT_EQ(r.documents(0).format(), "nib:keyed");
  EXPECT_EQ(r.documents(0).owner_class(), "NSApplication");
  const pb::UiAction *about = Action(r, "showAbout:");
  ASSERT_NE(about, nullptr);
  EXPECT_EQ(about->target(), "object");
  EXPECT_EQ(about->target_class(), "AppDelegate");
  EXPECT_EQ(about->control_class(), "NSMenuItem");
  EXPECT_EQ(about->control_label(), "About MacDemo");
  EXPECT_EQ(about->resolution(), "resolved");
  EXPECT_EQ(about->method(), "-[AppDelegate showAbout:]");
  EXPECT_EQ(Action(r, "copyAll:")->resolution(), "resolved-by-selector");
  ASSERT_EQ(r.outlets_size(), 1);
  EXPECT_EQ(r.outlets(0).source_class(), "NSApplication");
  EXPECT_EQ(r.outlets(0).destination_class(), "AppDelegate");
  // The archive, resolved.
  pb::ReadPropertyListRequest pr;
  pr.set_session_id(sid);
  pr.set_path("/MacDemo.app/Contents/Resources/MainMenu.nib");
  pr.set_resolve_keyed_archive(true);
  pb::ReadPropertyListResponse plist;
  ASSERT_TRUE(backend_->ReadPropertyList(ctx_, pr, plist).ok());
  ASSERT_TRUE(plist.root().has_dict_value());
  EXPECT_EQ(plist.root().dict_value().entries(0).key(), "$top");
  const auto &top = plist.root().dict_value().entries(0).value().dict_value();
  EXPECT_EQ(top.entries(0).key(), "IB.objectdata");
  const auto &data = top.entries(0).value().dict_value();
  EXPECT_EQ(data.entries(0).key(), "$class");
  EXPECT_EQ(data.entries(0).value().string_value(), "NSIBObjectData");
}

}  // namespace
}  // namespace revkit::backend
