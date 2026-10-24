// FileSystemService's Android calls (api_minor 98, feature "android";
// docs/android.md): GetAndroidPackage, DecodeAndroidXml and
// ListAndroidResources over an APK in a file system session.
#pragma once

#include "filesystems.h"

namespace revkit::backend {

api::Status GetAndroidPackage(FsSession &s, const api::CallContext &ctx, const pb::GetAndroidPackageRequest &req,
                              pb::GetAndroidPackageResponse &resp);
api::Status DecodeAndroidXml(FsSession &s, const api::CallContext &ctx, const pb::DecodeAndroidXmlRequest &req,
                             pb::DecodeAndroidXmlResponse &resp);
api::Status ListAndroidResources(FsSession &s, const api::CallContext &ctx, const pb::ListAndroidResourcesRequest &req,
                                 pb::ListAndroidResourcesResponse &resp);

}  // namespace revkit::backend
