// The image backend's decompiler worker mode (revkit::decompd::Mode::tokens),
// for rk-decompd: a worker must register it before it serves the daemon.
#pragma once

namespace revkit::backend {

void RegisterDecompdModes();

}  // namespace revkit::backend
