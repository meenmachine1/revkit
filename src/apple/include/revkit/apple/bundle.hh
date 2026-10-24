// Apple bundles (docs/apple-apps.md): what an Info.plist says, and how a
// bundle directory is laid out, as Apple's Bundle Programming Guide and
// Information Property List reference describe them.
#pragma once

#include "revkit/apple/plist.hh"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::apple {

struct DocumentType {
  std::string name;  // CFBundleTypeName
  std::string role;  // CFBundleTypeRole: "Editor", "Viewer", ...
  std::string handler_rank;  // LSHandlerRank
  std::vector<std::string> content_types;  // LSItemContentTypes
  std::vector<std::string> extensions;     // CFBundleTypeExtensions
};

struct TypeDeclaration {
  std::string identifier;   // UTTypeIdentifier
  std::string description;  // UTTypeDescription
  std::vector<std::string> conforms_to;
  std::vector<std::string> extensions;  // UTTypeTagSpecification's public.filename-extension
  std::vector<std::string> mime_types;
};

struct UsageDescription {
  std::string key;   // "NSCameraUsageDescription"
  std::string text;  // what the app tells the user
};

struct BundleInfo {
  std::string identifier;         // CFBundleIdentifier
  std::string name;               // CFBundleName
  std::string display_name;       // CFBundleDisplayName
  std::string executable;         // CFBundleExecutable
  std::string version;            // CFBundleVersion
  std::string short_version;      // CFBundleShortVersionString
  std::string package_type;       // CFBundlePackageType: "APPL", "FMWK", "XPC!", "BNDL", ...
  std::string minimum_os;         // MinimumOSVersion (iOS), else LSMinimumSystemVersion (macOS)
  std::vector<std::string> supported_platforms;  // CFBundleSupportedPlatforms
  std::vector<std::string> device_families;      // UIDeviceFamily: "iphone", "ipad", "tv", "watch", "carplay", "mac"
  std::vector<std::string> url_schemes;          // CFBundleURLTypes' CFBundleURLSchemes
  std::vector<std::string> queried_url_schemes;  // LSApplicationQueriesSchemes
  std::vector<DocumentType> document_types;      // CFBundleDocumentTypes
  std::vector<std::string> background_modes;     // UIBackgroundModes
  std::vector<UsageDescription> usage_descriptions;  // every *UsageDescription key, sorted
  std::vector<TypeDeclaration> exported_types;   // UTExportedTypeDeclarations
  std::vector<TypeDeclaration> imported_types;   // UTImportedTypeDeclarations
  std::vector<std::string> required_capabilities;  // UIRequiredDeviceCapabilities
  std::string extension_point;    // NSExtension's NSExtensionPointIdentifier
  std::string principal_class;    // NSPrincipalClass, else NSExtensionPrincipalClass
  std::string main_storyboard;    // UIMainStoryboardFile, else NSMainStoryboardFile
  std::string main_nib;           // NSMainNibFile
  std::string launch_storyboard;  // UILaunchStoryboardName
  bool allows_arbitrary_loads = false;  // NSAppTransportSecurity
  std::vector<std::string> ats_exception_domains;
  std::string sdk;                // DTSDKName
  std::string xcode;              // DTXcode
  std::string build_machine_os;   // BuildMachineOSBuild
  bool requires_iphone_os = false;  // LSRequiresIPhoneOS
};

BundleInfo bundle_info(const Value &info_plist);

// A bundle directory's kind from its name's extension: "app", "framework",
// "appex", "bundle", "xpc", "plugin", "kext", "systemextension", "dext",
// "qlgenerator", "mdimporter", "prefpane", "saver", "storyboardc" (a
// compiled storyboard); "" for none.
std::string bundle_kind(std::string_view directory_name);

}  // namespace revkit::apple
