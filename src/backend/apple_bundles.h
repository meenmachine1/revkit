// Apple bundles, property lists and code signatures in the API
// (api_minor 100, feature "apple-bundles"; docs/apple-apps.md):
// FileSystemService.GetAppleBundle and ReadPropertyList over a session, and
// the messages revkit::apple's readers fill (a program's code signature in
// its summary too).
#pragma once

#include "filesystems.h"
#include "revkit/apple/bundle.hh"
#include "revkit/apple/codesign.hh"
#include "revkit/apple/ib.hh"
#include "revkit/apple/plist.hh"
#include "revkit/objc/objc.h"
#include "revkit/v1/apple.pb.h"

#include <cstdint>
#include <string>

namespace revkit::backend {

// How much of a plist a response carries.
struct PlistBudget {
  std::uint64_t values_left = 20000;
  std::uint32_t max_data = 4096;
  bool truncated = false;
};
void FillPlist(const apple::Value &v, pb::PlistValue *out, PlistBudget &budget);
void FillCodeSignature(const apple::CodeSignature &sig, pb::CodeSignature *out);
void FillProvisioningProfile(const apple::ProvisioningProfile &p, pb::ProvisioningProfile *out);
void FillBundleInfo(const apple::BundleInfo &b, pb::AppleBundleInfo *out);

// A directory entry's bundle kind (FileSystemEntry.bundle_kind): its name's
// extension, when it holds what a bundle does.
std::string BundleKindOf(const container::FileSystem &fs, std::uint32_t entry);

// The code signature of a Mach-O program's file (the default slice of a
// universal one), read from `read`; nullopt without one. Problems inside
// it are its warnings.
std::optional<apple::CodeSignature> ReadCodeSignature(
    const std::function<std::vector<std::byte>(std::uint64_t, std::size_t)> &read, std::uint64_t file_size,
    apple::SignatureRange *where = nullptr);

api::Status GetAppleBundle(FsSession &s, const api::CallContext &ctx, const pb::GetAppleBundleRequest &req,
                           pb::GetAppleBundleResponse &resp);
api::Status ReadPropertyList(FsSession &s, const api::CallContext &ctx, const pb::ReadPropertyListRequest &req,
                             pb::ReadPropertyListResponse &resp);

// Interface Builder (api_minor 101, feature "ui-actions"): the compiled
// nibs at or below a path (a bundle's, an .ipa's first app's, a
// .storyboardc's, a nib's), each with File's Owner's class where the
// storyboard or the archive says it.
struct InterfaceDoc {
  std::string path;        // the nib file read
  std::string storyboard;  // its .storyboardc ("" none)
  std::string owner_class, owner_from;
  apple::IbDocument doc;
};
struct InterfaceDocs {
  std::vector<InterfaceDoc> docs;
  std::vector<std::string> warnings;
  // The bundle's main executable (session path, container path), when the
  // path was a bundle.
  std::string executable_path, executable_container_path;
};
api::Status CollectInterfaceDocs(FsSession &s, const api::CallContext &ctx, const std::string &path, InterfaceDocs &out);

// The actions and outlets of the documents, resolved in `md` (null: no
// program). `address` and `name` give an implementation's API address and
// its function's current name.
void ResolveUiActions(InterfaceDocs &docs, const objc::Metadata *md,
                      const std::function<pb::Address(std::uint64_t)> &address,
                      const std::function<std::string(std::uint64_t)> &name, bool include_documents,
                      pb::ListUiActionsResponse &resp);

}  // namespace revkit::backend
