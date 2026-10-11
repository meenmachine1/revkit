// revkit::infer's decompiler worker mode (revkit::decompd::Mode::observe),
// for rk-decompd: a worker must register it before it serves rk-infer.
#pragma once

namespace revkit::infer {

void register_decompd_mode();

}  // namespace revkit::infer
