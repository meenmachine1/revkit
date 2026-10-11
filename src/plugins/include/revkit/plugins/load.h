// Loader plugins into revkit's image model.
#pragma once

#include "revkit/loader/image.hh"
#include "revkit/plugins/host.h"

#include <memory>
#include <string>

namespace revkit::plugins {

struct PluginImage {
  loader::Image image;
  std::string language;  // "x86:LE:64:default"
  std::string compiler;  // "default" when the plugin gave none
};

// Runs a loader plugin on a file and builds a loader::Image from its
// blocks, entry point and symbols: blocks are file-backed regions (the
// rest of a block reads as zero), function symbols are discovery seeds.
// Throws loader::LoadError when the plugin fails or its result doesn't fit
// (overlapping blocks, a language string that names no pointer size).
PluginImage load_with(const Plugin &plugin, std::shared_ptr<const loader::Bytes> file);

}  // namespace revkit::plugins
