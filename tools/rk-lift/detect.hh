#pragma once

#include <string>

namespace rklift {

// rk-lift --detect: prints revkit::detect's report of `file` as JSON; with
// `features`, every candidate's sweep too. Returns the exit status: 0 for a
// confident answer, 1 for a refusal or none, 2 if the file can't be read.
int run_detect(const std::string &file, const std::string &ghidra_root, unsigned threads, bool features);

}  // namespace rklift
