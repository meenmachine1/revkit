// Peripheral plugins as machine peripherals (docs/firmware-emulation.md,
// docs/plugins.md): a machine description's "plugin:NAME" kind becomes a
// live plugin instance, its register accesses, ticks, input and interrupt
// inputs calls into it, its imports the machine's clock, lines, output and
// (with the "bus" grant) memory.
#pragma once

#include "revkit/emu/machine.hh"
#include "revkit/plugins/host.h"

#include <memory>

namespace revkit::plugins {

// Makes peripherals of kind "plugin:NAME" from `host`'s loaded peripheral
// plugins (other kinds: nullptr with no error, for the built-ins). The host
// must outlive the machines.
emu::PeripheralFactory peripheral_factory(const Host &host);

}  // namespace revkit::plugins
