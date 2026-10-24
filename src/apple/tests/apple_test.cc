// revkit::apple on tests/data/apple's fixtures (make_bundle.py writes the
// plists, signatures and profiles with Python's plistlib and its own DER
// writer; build.sh links the Mach-O files with clang and ld64.lld), on
// OpenSSL-made CMS where the openssl tool is here, and on hand-built
// hostile input.
#include "apple_fixture.h"

#include "revkit/apple/bundle.hh"
#include "revkit/apple/codesign.hh"
#include "revkit/apple/ib.hh"
#include "revkit/apple/plist.hh"
#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include <cmath>
#include <cstring>

namespace revkit::apple {
namespace {

using apple_testing::read_file;

const std::filesystem::path *plist_dir() {
  const auto &d = apple_testing::plists(REVKIT_APPLE_FIXTURE);
  return d ? &*d : nullptr;
}

const std::filesystem::path *bundle_dir() {
  const auto &d = apple_testing::bundles(REVKIT_TEST_CLANG, REVKIT_TEST_LD64, REVKIT_APPLE_FIXTURE);
  return d ? &*d : nullptr;
}

#define NEED_PLISTS()                  \
  const auto *P = plist_dir();         \
  if (!P) GTEST_SKIP() << "no python3"
#define NEED_BUNDLES()                 \
  const auto *B = bundle_dir();        \
  if (!B) GTEST_SKIP() << "clang or ld64.lld missing, or the fixtures didn't build"

std::span<const std::byte> bytes(const std::string &s) { return std::as_bytes(std::span(s.data(), s.size())); }

void check_values(const Value &v) {
  ASSERT_TRUE(v.is(Value::Type::dict));
  EXPECT_EQ(v.get("int")->as_int(), 7);
  EXPECT_EQ(v.get("neg")->as_int(), -5);
  const Value *big = v.get("big");
  ASSERT_TRUE(big && big->is(Value::Type::integer));
  EXPECT_TRUE(big->big);
  EXPECT_EQ(big->unsigned_value, UINT64_MAX);
  EXPECT_EQ(v.get("real")->real, 2.5);
  EXPECT_EQ(v.get("yes")->as_bool(), true);
  EXPECT_EQ(v.get("no")->as_bool(), false);
  ASSERT_TRUE(v.get("date")->is(Value::Type::date));
  EXPECT_EQ(iso8601(v.get("date")->real), "2026-10-18T12:00:00Z");
  ASSERT_TRUE(v.get("data")->is(Value::Type::data));
  EXPECT_EQ(v.get("data")->bytes, std::string("\x00\x01\xfe", 3));
  EXPECT_EQ(v.string_at("unicode"), "caf\xc3\xa9 \xf0\x9f\x98\x80");
  const Value *list = v.get("nested")->get("list");
  ASSERT_TRUE(list && list->array.size() == 3);
  EXPECT_EQ(list->array[1].bytes, "two");
  EXPECT_EQ(list->array[2].array.at(0).real, 3.0);
  EXPECT_TRUE(v.get("empty")->is(Value::Type::dict));
  EXPECT_TRUE(v.get("none")->is(Value::Type::array) && v.get("none")->array.empty());
}

TEST(ApplePlist, BinaryAndXmlReadTheSameValues) {
  NEED_PLISTS();
  const auto bin = read_file(*P / "values-binary.plist");
  const auto xml = read_file(*P / "values-xml.plist");
  EXPECT_EQ(sniff(bin), Format::binary);
  EXPECT_EQ(sniff(xml), Format::xml);
  Parsed b = parse(bin), x = parse(xml);
  EXPECT_EQ(b.format, Format::binary);
  EXPECT_EQ(x.format, Format::xml);
  check_values(b.root);
  check_values(x.root);
  // Written back and read again.
  check_values(parse(bytes(to_xml(b.root))).root);
}

TEST(ApplePlist, InfoPlistKeys) {
  NEED_PLISTS();
  for (const char *f : {"info-binary.plist", "info-xml.plist", "info-utf16.plist"}) {
    SCOPED_TRACE(f);
    const BundleInfo i = bundle_info(parse(read_file(*P / f)).root);
    EXPECT_EQ(i.identifier, "com.example.demo");
    EXPECT_EQ(i.executable, "Demo");
    EXPECT_EQ(i.display_name, "Demo App");
    EXPECT_EQ(i.version, "42");
    EXPECT_EQ(i.short_version, "1.2.3");
    EXPECT_EQ(i.package_type, "APPL");
    EXPECT_EQ(i.minimum_os, "15.0");
    EXPECT_EQ(i.device_families, (std::vector<std::string>{"iphone", "ipad"}));
    EXPECT_EQ(i.url_schemes, (std::vector<std::string>{"demo", "demo-auth"}));
    EXPECT_EQ(i.queried_url_schemes, (std::vector<std::string>{"maps"}));
    EXPECT_EQ(i.background_modes, (std::vector<std::string>{"audio", "remote-notification"}));
    ASSERT_EQ(i.usage_descriptions.size(), 2u);
    EXPECT_EQ(i.usage_descriptions[0].key, "NSCameraUsageDescription");
    EXPECT_EQ(i.usage_descriptions[0].text, "Scan codes with the camera.");
    ASSERT_EQ(i.document_types.size(), 1u);
    EXPECT_EQ(i.document_types[0].role, "Editor");
    EXPECT_EQ(i.document_types[0].content_types, (std::vector<std::string>{"com.example.demo.document"}));
    ASSERT_EQ(i.exported_types.size(), 1u);
    EXPECT_EQ(i.exported_types[0].identifier, "com.example.demo.document");
    EXPECT_EQ(i.exported_types[0].extensions, (std::vector<std::string>{"demo"}));
    EXPECT_EQ(i.exported_types[0].mime_types, (std::vector<std::string>{"application/x-demo"}));
    ASSERT_EQ(i.imported_types.size(), 1u);
    EXPECT_EQ(i.imported_types[0].extensions, (std::vector<std::string>{"md", "markdown"}));
    EXPECT_EQ(i.main_storyboard, "Main");
    EXPECT_EQ(i.ats_exception_domains, (std::vector<std::string>{"example.org"}));
    EXPECT_FALSE(i.allows_arbitrary_loads);
    EXPECT_TRUE(i.requires_iphone_os);
    EXPECT_EQ(i.sdk, "iphoneos17.0");
  }
}

TEST(ApplePlist, XmlSyntax) {
  const std::string doc =
      "\xef\xbb\xbf<?xml version=\"1.0\"?>\n<!DOCTYPE plist [ <!ENTITY x \"no\"> ]>\n<!-- c -->"
      "<plist version=\"1.0\"><dict><key>a&amp;b</key><string>&lt;&#x41;&#66;<![CDATA[<raw>]]></string>"
      "<key>e</key><string/><key>h</key><integer> 0x1F </integer><key>n</key><integer>-9223372036854775808</integer>"
      "<key>r</key><real>-infinity</real><key>t</key><true></true><key>d</key><data>AAE C\n/w==</data>"
      "<key>a&amp;b</key><string>last</string></dict></plist>";
  const Value v = parse(bytes(doc)).root;
  EXPECT_EQ(v.dict.size(), 7u);
  EXPECT_EQ(v.string_at("a&b"), "last");  // a repeated key: the last wins
  EXPECT_EQ(v.dict[0].key, "a&b");        // in the first one's place
  EXPECT_EQ(v.string_at("e"), "");
  EXPECT_EQ(v.get("h")->as_int(), 31);
  EXPECT_EQ(v.get("n")->as_int(), INT64_MIN);
  EXPECT_TRUE(std::isinf(v.get("r")->real) && v.get("r")->real < 0);
  EXPECT_EQ(v.get("t")->as_bool(), true);
  EXPECT_EQ(v.get("d")->bytes, std::string("\x00\x01\x02\xff", 4));
  // A string with CDATA and references.
  const Value s = parse(bytes("<plist><string>&lt;&#x41;&#66;<![CDATA[<raw>]]></string></plist>")).root;
  EXPECT_EQ(s.bytes, "<AB<raw>");
}

TEST(ApplePlist, MalformedXmlIsRefused) {
  for (const char *bad : {
           "<plist><dict><key>a</key></dict></plist>",           // a key without a value
           "<plist><dict><string>a</string></dict></plist>",     // a value without a key
           "<plist><string>&bogus;</string></plist>",            // an unknown entity
           "<plist><string>a<b/>c</string></plist>",             // markup in a string
           "<plist><integer>12x</integer></plist>",              // not a number
           "<plist><integer>99999999999999999999</integer></plist>",  // past 64 bits
           "<plist><date>2026-13-01T00:00:00Z</date></plist>",   // month 13
           "<plist><array><string>a</string></plist>",           // unclosed
           "<plist><string>a</string></plist><x/>",              // text after
           "<plist><unknown/></plist>",
           "<plist></plist>",
       }) {
    SCOPED_TRACE(bad);
    EXPECT_THROW(parse(bytes(bad)), Error);
  }
  EXPECT_THROW(parse(bytes("{ a = b; }")), Error);  // OpenStep: not read
}

TEST(ApplePlist, LimitsHold) {
  std::string deep = "<plist>";
  for (int i = 0; i < 200; ++i) deep += "<array>";
  for (int i = 0; i < 200; ++i) deep += "</array>";
  deep += "</plist>";
  EXPECT_THROW(parse(bytes(deep)), LimitError);
  Limits small;
  small.max_input = 16;
  EXPECT_THROW(parse(bytes("<plist><string>long enough</string></plist>"), small), LimitError);
}

// A binary plist from objects (already encoded) and a top object; one-byte
// offsets and references.
std::string bplist(const std::vector<std::string> &objects, unsigned top = 0) {
  std::string out = "bplist00";
  std::vector<unsigned> offsets;
  for (const std::string &o : objects) {
    offsets.push_back(static_cast<unsigned>(out.size()));
    out += o;
  }
  const std::size_t table = out.size();
  for (unsigned o : offsets) out += static_cast<char>(o);
  std::string trailer(32, '\0');
  trailer[6] = 1;  // offset size
  trailer[7] = 1;  // ref size
  trailer[15] = static_cast<char>(objects.size());
  trailer[23] = static_cast<char>(top);
  trailer[31] = static_cast<char>(table);
  return out + trailer;
}

TEST(ApplePlist, HostileBinaryIsRefused) {
  // A cycle: an array holding itself.
  EXPECT_THROW(parse(bytes(bplist({std::string("\xa1\x00", 2)}))), Error);
  // Sharing that doubles at each level: 2^40 values from 41 objects.
  std::vector<std::string> doubling;
  for (int i = 0; i < 40; ++i) doubling.push_back(std::string("\xa2") + static_cast<char>(i + 1) + static_cast<char>(i + 1));
  doubling.push_back("\x10\x07");
  EXPECT_THROW(parse(bytes(bplist(doubling))), LimitError);
  // A reference past the object count.
  EXPECT_THROW(parse(bytes(bplist({std::string("\xa1\x05", 2)}))), Error);
  // A string longer than the file.
  EXPECT_THROW(parse(bytes(bplist({std::string("\x5f\x10\x7f", 3)}))), Error);
  // A key that isn't a string.
  EXPECT_THROW(parse(bytes(bplist({std::string("\xd1\x01\x01", 3), "\x10\x01"}))), Error);
  // Good ones parse: a dict of one, and a 16-bit UTF-16 string.
  const Value d = parse(bytes(bplist({std::string("\xd1\x01\x02", 3), "\x51k", std::string("\x61\x00\xe9", 3)}))).root;
  EXPECT_EQ(d.string_at("k"), "\xc3\xa9");
  // A bad trailer: the offset table outside the file.
  std::string bad = bplist({"\x10\x07"});
  bad[bad.size() - 1] = 120;
  EXPECT_THROW(parse(bytes(bad)), Error);
  // Truncations of a real one never crash.
  NEED_PLISTS();
  const auto good = read_file(*P / "values-binary.plist");
  for (std::size_t n = 0; n < good.size(); n += 7) {
    try {
      parse(std::span(good).first(n));
    } catch (const Error &) {
    }
  }
}

TEST(AppleDates, Iso8601RoundTrips) {
  EXPECT_EQ(iso8601(0), "2001-01-01T00:00:00Z");
  EXPECT_EQ(parse_iso8601("2001-01-01T00:00:00Z"), 0.0);
  EXPECT_EQ(iso8601(*parse_iso8601("1969-07-20T20:17:40Z")), "1969-07-20T20:17:40Z");
  EXPECT_FALSE(parse_iso8601("2026-10-18"));
  EXPECT_FALSE(parse_iso8601("2026-10-18T25:00:00Z"));
}

void check_demo_signature(const CodeSignature &sig) {
  ASSERT_EQ(sig.code_directories.size(), 2u);
  const CodeDirectory &cd = sig.code_directories[0];
  EXPECT_EQ(cd.slot, 0u);
  EXPECT_FALSE(cd.alternate);
  EXPECT_EQ(cd.identifier, "com.example.demo");
  EXPECT_EQ(cd.team_id, "ABCDE12345");
  EXPECT_EQ(cd.version, 0x20400u);
  EXPECT_EQ(cd.flag_names, (std::vector<std::string>{"runtime"}));
  EXPECT_EQ(cd.hash_name, "sha1");
  EXPECT_EQ(cd.page_size, 4096u);
  EXPECT_EQ(cd.special_hashes, (std::vector<std::string>{"requirements", "entitlements", "der-entitlements"}));
  EXPECT_EQ(cd.exec_seg_flag_names, (std::vector<std::string>{"main-binary"}));
  EXPECT_EQ(cd.cdhash.size(), 40u);
  const CodeDirectory &alt = sig.code_directories[1];
  EXPECT_TRUE(alt.alternate);
  EXPECT_EQ(alt.hash_name, "sha256");
  EXPECT_EQ(alt.cdhash.size(), 40u);  // truncated to 20 bytes, as codesign prints it
  EXPECT_NE(alt.cdhash, cd.cdhash);
  ASSERT_TRUE(sig.entitlements);
  EXPECT_EQ(sig.entitlements->string_at("application-identifier"), "ABCDE12345.com.example.demo");
  EXPECT_EQ(sig.entitlements->get("get-task-allow")->as_bool(), true);
  EXPECT_NE(sig.entitlements_xml.find("<plist"), std::string::npos);
  ASSERT_TRUE(sig.der_entitlements);
  EXPECT_EQ(sig.der_entitlements->string_at("aps-environment"), "development");
  EXPECT_EQ(sig.der_entitlements->strings_at("keychain-access-groups"),
            (std::vector<std::string>{"ABCDE12345.com.example.demo"}));
  ASSERT_EQ(sig.requirements.size(), 1u);
  EXPECT_EQ(sig.requirements[0].type_name, "designated");
  EXPECT_EQ(sig.requirements[0].text,
            "identifier \"com.example.demo\" and anchor apple generic and certificate leaf[subject.CN] = \"Apple "
            "Development: Jane Doe (ABCDE12345)\" and certificate 1[field.1.2.840.113635.100.6.2.1] /* exists */");
  EXPECT_TRUE(sig.has_cms);
  EXPECT_FALSE(sig.adhoc);
  ASSERT_EQ(sig.certificates.size(), 2u);
  EXPECT_EQ(sig.certificates[0].common_name, "Apple Development: Jane Doe (ABCDE12345)");
  EXPECT_EQ(sig.certificates[0].organizational_unit, "ABCDE12345");
  EXPECT_EQ(sig.certificates[0].issuer, "Apple Worldwide Developer Relations Certification Authority");
  EXPECT_EQ(sig.blobs.size(), 6u);
  EXPECT_TRUE(sig.warnings.empty()) << sig.warnings.front();
}

TEST(AppleCodeSignature, SuperBlobParts) {
  NEED_PLISTS();
  check_demo_signature(parse_code_signature(read_file(*P / "signature.bin")));
}

TEST(AppleCodeSignature, MalformedBlobs) {
  EXPECT_THROW(parse_code_signature(bytes("not a signature")), Error);
  NEED_PLISTS();
  const auto good = read_file(*P / "signature.bin");
  // Truncated: an error or warnings, never a crash; flipped bytes too.
  for (std::size_t n = 0; n < good.size(); n += 13) {
    try {
      parse_code_signature(std::span(good).first(n));
    } catch (const Error &) {
    }
  }
  std::vector<std::byte> flipped = good;
  for (std::size_t i = 0; i < flipped.size(); i += 5) {
    flipped[i] ^= std::byte{0x5a};
    try {
      parse_code_signature(flipped);
    } catch (const Error &) {
    }
    flipped[i] ^= std::byte{0x5a};
  }
}

TEST(AppleCodeSignature, InTheDemoAppsExecutable) {
  NEED_BUNDLES();
  const auto file = read_file(*B / "Demo.app" / "Demo");
  const loader::Image img = loader::parse_macho(std::make_shared<loader::Bytes>(file.begin(), file.end()), {});
  ASSERT_TRUE(img.macho && img.macho->code_signature);
  const auto blob = std::span(file).subspan(img.macho->code_signature_offset, img.macho->code_signature_size);
  check_demo_signature(parse_code_signature(blob));
  // ld64.lld's own ad-hoc signature of the framework: linker-signed.
  const auto fw = read_file(*B / "Demo.app" / "Frameworks" / "Greeter.framework" / "Greeter");
  const loader::Image fimg = loader::parse_macho(std::make_shared<loader::Bytes>(fw.begin(), fw.end()), {});
  ASSERT_TRUE(fimg.macho && fimg.macho->code_signature);
  const CodeSignature lld = parse_code_signature(
      std::span(fw).subspan(fimg.macho->code_signature_offset, fimg.macho->code_signature_size));
  ASSERT_EQ(lld.code_directories.size(), 1u);
  EXPECT_EQ(lld.code_directories[0].identifier, "Greeter");
  EXPECT_EQ(lld.code_directories[0].flag_names, (std::vector<std::string>{"adhoc", "linker-signed"}));
  EXPECT_EQ(lld.code_directories[0].hash_name, "sha256");
  EXPECT_TRUE(lld.adhoc);
  EXPECT_FALSE(lld.has_cms);
  EXPECT_FALSE(entitlements_of(lld));
}

void check_profile(const ProvisioningProfile &p) {
  EXPECT_EQ(p.name, "Demo Development");
  EXPECT_EQ(p.uuid, "6F9619FF-8B86-D011-B42D-00C04FC964FF");
  EXPECT_EQ(p.team_identifiers, (std::vector<std::string>{"ABCDE12345"}));
  EXPECT_EQ(p.team_name, "Jane Doe");
  EXPECT_EQ(p.application_identifier, "ABCDE12345.com.example.demo");
  EXPECT_EQ(p.platforms, (std::vector<std::string>{"iOS"}));
  EXPECT_EQ(p.provisioned_devices, 2u);
  EXPECT_EQ(p.kind, "development");
  ASSERT_TRUE(p.expiration_date);
  EXPECT_EQ(iso8601(*p.expiration_date), "2027-01-02T03:04:05Z");
  EXPECT_EQ(p.developer_certificates, 1u);
  ASSERT_TRUE(p.entitlements);
  EXPECT_EQ(p.entitlements->string_at("aps-environment"), "development");
}

TEST(AppleProvisioning, ProfileInTheDemoApp) {
  NEED_BUNDLES();
  const ProvisioningProfile p = parse_provisioning_profile(read_file(*B / "Demo.app" / "embedded.mobileprovision"));
  check_profile(p);
  ASSERT_EQ(p.signer_certificates.size(), 2u);
  EXPECT_EQ(p.signer_certificates[1].common_name, "Apple Root CA");
  EXPECT_THROW(parse_provisioning_profile(bytes("garbage")), Error);
}

// OpenSSL's own CMS, DER and (with -stream) BER with indefinite lengths
// and a constructed octet string.
TEST(AppleProvisioning, OpenSslMadeProfiles) {
  NEED_BUNDLES();
  if (std::system("openssl version >/dev/null 2>&1") != 0) GTEST_SKIP() << "no openssl";
  const auto dir = apple_testing::scratch("openssl");
  // The profile's plist: the same one make_bundle.py wrapped.
  const auto ours = read_file(*B / "Demo.app" / "embedded.mobileprovision");
  const ProvisioningProfile p = parse_provisioning_profile(ours);
  {
    std::ofstream(dir / "profile.plist") << to_xml(p.plist);
  }
  const std::string d = dir.string();
  const std::string make =
      "cd '" + d + "' && openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 2 "
      "-subj '/CN=Test Signer/OU=ABCDE12345/O=Test/C=US' >/dev/null 2>&1 && "
      "openssl cms -sign -in profile.plist -signer cert.pem -inkey key.pem -outform DER -nodetach -binary "
      "-out der.mobileprovision && "
      "openssl cms -sign -in profile.plist -signer cert.pem -inkey key.pem -outform DER -nodetach -binary -stream "
      "-out ber.mobileprovision";
  ASSERT_EQ(std::system(make.c_str()), 0);
  for (const char *f : {"der.mobileprovision", "ber.mobileprovision"}) {
    SCOPED_TRACE(f);
    const ProvisioningProfile q = parse_provisioning_profile(read_file(dir / f));
    check_profile(q);
    ASSERT_EQ(q.signer_certificates.size(), 1u);
    EXPECT_EQ(q.signer_certificates[0].common_name, "Test Signer");
    EXPECT_EQ(q.signer_certificates[0].organizational_unit, "ABCDE12345");
  }
}

// ---- Interface Builder ---------------------------------------------------------

const IbObject *by_class(const IbDocument &d, std::string_view custom) {
  for (const IbObject &o : d.objects)
    if (o.custom_class == custom) return &o;
  return nullptr;
}
const IbConnection *by_label(const IbDocument &d, std::string_view label) {
  for (const IbConnection &c : d.connections)
    if (c.label == label) return &c;
  return nullptr;
}

TEST(AppleNib, ArchiveTables) {
  NEED_PLISTS();
  const NibArchive a = parse_nib_archive(read_file(*P / "settings.nib"));
  EXPECT_EQ(a.format_version, 1u);
  EXPECT_EQ(a.coder_version, 10u);
  ASSERT_GT(a.objects.size(), 10u);
  EXPECT_EQ(a.objects[0].class_name, "NSObject");  // the root, its NUL dropped
  ASSERT_NE(a.objects[0].get("UINibConnectionsKey"), nullptr);
  EXPECT_EQ(a.objects[0].get("UINibConnectionsKey")->type, NibValue::Type::ref);
  EXPECT_EQ(control_event_names((1 << 6) | (1 << 12) | (1 << 30)),
            (std::vector<std::string>{"touchUpInside", "valueChanged", "0x40000000"}));
}

TEST(AppleNib, AStandaloneNibsObjectsAndConnections) {
  NEED_PLISTS();
  const IbDocument d = read_interface_builder(read_file(*P / "settings.nib"));
  EXPECT_EQ(d.format, "nib:archive");
  const IbObject *owner = by_class(d, "UIProxyObject");
  ASSERT_NE(owner, nullptr);
  EXPECT_EQ(owner->placeholder, "files-owner");
  ASSERT_EQ(d.connections.size(), 4u);
  const IbConnection *save = by_label(d, "save:");
  ASSERT_NE(save, nullptr);
  EXPECT_EQ(save->kind, IbConnection::Kind::action);
  EXPECT_EQ(save->events, (std::vector<std::string>{"touchUpInside"}));
  ASSERT_TRUE(save->source && save->destination);
  EXPECT_EQ(d.object(*save->source)->label, "Save");
  EXPECT_EQ(d.object(*save->destination)->placeholder, "files-owner");
  const IbConnection *undefined = by_label(d, "undefinedAction:");
  ASSERT_NE(undefined, nullptr);
  EXPECT_EQ(d.object(*undefined->destination)->placeholder, "first-responder");
  EXPECT_EQ(by_label(d, "view")->kind, IbConnection::Kind::outlet);
  EXPECT_TRUE(d.warnings.empty());
}

TEST(AppleNib, AStoryboardScene) {
  NEED_PLISTS();
  const IbDocument view = read_interface_builder(read_file(*P / "scene-view.nib"));
  const IbObject *label = by_class(view, "GreetingLabel");
  ASSERT_NE(label, nullptr);
  EXPECT_EQ(label->class_name, "UIClassSwapper");
  EXPECT_EQ(label->original_class, "UILabel");
  EXPECT_EQ(label->label, "Hello");
  const IbObject *root = by_class(view, "UIView");
  ASSERT_NE(root, nullptr);
  ASSERT_TRUE(label->parent);
  EXPECT_EQ(*label->parent, root->id);
  const IbConnection *slider = by_label(view, "sliderChanged:");
  ASSERT_NE(slider, nullptr);
  EXPECT_EQ(slider->events, (std::vector<std::string>{"valueChanged"}));
  EXPECT_EQ(view.object(*slider->source)->custom_class, "UISlider");
  const IbDocument scene = read_interface_builder(read_file(*P / "scene-controller.nib"));
  const IbObject *vc = by_class(scene, "ViewController");
  ASSERT_NE(vc, nullptr);
  EXPECT_EQ(vc->nib_name, "BYZ-38-t0r-view-8bC-Xf-vdC");
  EXPECT_EQ(vc->storyboard_identifier, "UIViewController-BYZ-38-t0r");
}

TEST(AppleNib, AKeyedArchiveNib) {
  NEED_PLISTS();
  const IbDocument d = read_interface_builder(read_file(*P / "keyed.plist"));
  EXPECT_EQ(d.format, "nib:keyed");
  const IbObject *delegate = by_class(d, "AppDelegate");
  ASSERT_NE(delegate, nullptr);
  EXPECT_EQ(delegate->class_name, "NSCustomObject");
  const IbObject *app = by_class(d, "NSApplication");
  ASSERT_NE(app, nullptr);
  EXPECT_EQ(app->placeholder, "files-owner");
  EXPECT_EQ(by_class(d, "FirstResponder")->placeholder, "first-responder");
  ASSERT_EQ(d.connections.size(), 3u);
  const IbConnection *about = by_label(d, "showAbout:");
  ASSERT_NE(about, nullptr);
  EXPECT_EQ(d.object(*about->source)->label, "About MacDemo");
  EXPECT_EQ(d.object(*about->destination)->custom_class, "AppDelegate");
  EXPECT_TRUE(about->events.empty());
  EXPECT_EQ(by_label(d, "delegate")->kind, IbConnection::Kind::outlet);
  // The menu items' parent is the menu.
  const IbObject *item = d.object(*about->source);
  ASSERT_TRUE(item->parent);
  EXPECT_EQ(d.object(*item->parent)->class_name, "NSMenu");
}

TEST(AppleKeyedArchive, ResolvesObjectsOnce) {
  NEED_PLISTS();
  const Value plist = parse(read_file(*P / "keyed.plist")).root;
  ASSERT_TRUE(KeyedArchive::is_keyed_archive(plist));
  const KeyedArchive ka(plist);
  const auto data = ka.top("IB.objectdata");
  ASSERT_TRUE(data);
  EXPECT_EQ(ka.class_name(*data), "NSIBObjectData");
  EXPECT_EQ(ka.array(*data, "NSConnections").size(), 3u);
  const Value r = ka.resolve();
  const Value *top = r.get("$top")->get("IB.objectdata");
  ASSERT_TRUE(top);
  EXPECT_EQ(top->string_at("$class"), "NSIBObjectData");
  const Value *conns = top->get("NSConnections");
  ASSERT_TRUE(conns && conns->is(Value::Type::array));
  ASSERT_EQ(conns->array.size(), 3u);
  EXPECT_EQ(conns->array[0].string_at("$class"), "NSNibControlConnector");
  EXPECT_EQ(conns->array[0].string_at("NSLabel"), "showAbout:");
  // The menu item is expanded once (under NSRoot's tree or the first
  // connection), and referenced afterwards.
  std::size_t refs = 0;
  std::function<void(const Value &)> walk = [&](const Value &v) {
    if (v.get("$ref")) ++refs;
    for (const Value &x : v.array) walk(x);
    for (const DictEntry &e : v.dict) walk(e.value);
  };
  walk(r);
  EXPECT_GT(refs, 0u);
  EXPECT_THROW(KeyedArchive(parse(read_file(*P / "values-xml.plist")).root), Error);
}

TEST(AppleNib, HostileArchivesAreRefused) {
  NEED_PLISTS();
  const auto good = read_file(*P / "settings.nib");
  // A version we don't read; tables out of order; a reference past the
  // object table.
  auto bad = good;
  bad[10] = std::byte{2};
  EXPECT_THROW(parse_nib_archive(bad), Error);
  bad = good;
  bad[22] = std::byte{0xff};
  bad[23] = std::byte{0xff};
  EXPECT_THROW(parse_nib_archive(bad), Error);
  EXPECT_THROW(read_interface_builder(bytes("NIBArchive")), Error);
  EXPECT_THROW(read_interface_builder(bytes("not a nib")), Error);
  // Truncations and flipped bytes: an error or a smaller graph, never a crash.
  for (std::size_t n = 0; n < good.size(); n += 9) {
    try {
      read_interface_builder(std::span(good).first(n));
    } catch (const Error &) {
    }
  }
  std::vector<std::byte> flipped = good;
  for (std::size_t i = 0; i < flipped.size(); i += 3) {
    flipped[i] ^= std::byte{0x41};
    try {
      read_interface_builder(flipped);
    } catch (const Error &) {
    }
    flipped[i] ^= std::byte{0x41};
  }
}

TEST(AppleBundle, Kinds) {
  EXPECT_EQ(bundle_kind("Demo.app"), "app");
  EXPECT_EQ(bundle_kind("Greeter.FRAMEWORK"), "framework");
  EXPECT_EQ(bundle_kind("Share.appex"), "appex");
  EXPECT_EQ(bundle_kind("Main.storyboardc"), "storyboardc");
  EXPECT_EQ(bundle_kind("app"), "");
  EXPECT_EQ(bundle_kind(".app"), "");
  EXPECT_EQ(bundle_kind("notes.txt"), "");
}

}  // namespace
}  // namespace revkit::apple
