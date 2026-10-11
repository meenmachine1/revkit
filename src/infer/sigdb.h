// Library signatures for imports, matched by name.
//
// The databases are generated from system headers by
// tools/rk-sigdb/gen_sigdb.py (glibc for LP64 ELF targets, mingw-w64 for
// Windows) and compiled in. One line per function: name, return type,
// parameter types, and "..." for a variadic function, in Ghidra's notation
// with typedefs resolved.
#pragma once

#include "revkit/infer/vtype.h"
#include "revkit/loader/image.hh"

#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace revkit::infer {

// The C types system headers give values most often, by size, as a prior
// for values whose type evidence is missing or weak.
struct Priors {
  // A value in an integer register whose type is unknown (param or return).
  VType unknown_param(std::uint8_t size) const;
  VType unknown_return(std::uint8_t size) const;
  // An integer whose signedness and rank aren't known.
  VType integer_param(std::uint8_t size) const;
  VType integer_return(std::uint8_t size) const;
  // What a pointer to unknown points to.
  VType pointee;

  std::map<std::uint8_t, VType> params, returns, returns_upto, int_params, int_returns;
};

class SigDb {
 public:
  explicit SigDb(std::string_view text);

  // The prototype of an imported function, with types sized for `org`.
  // Versioned ELF names (memcpy@GLIBC_2.14) and glibc's ISO aliases
  // (__isoc99_sscanf, __isoc23_strtol) find the plain name.
  std::optional<Prototype> find(std::string_view name, const DataOrg &org) const;
  // What a function passed as parameter `index` (0-based) of an imported
  // function is called as (qsort's comparator).
  std::optional<Prototype> callback(std::string_view name, std::size_t index, const DataOrg &org) const;
  std::size_t size() const { return entries_.size(); }

  // The database for an image's platform: Windows for PE, glibc otherwise.
  static const SigDb &for_image(const loader::Image &image);

  // Priors from the glibc headers' prototypes, with sizes for `org`.
  static const Priors &priors(const DataOrg &org);

 private:
  const std::vector<std::string> *lookup(std::string_view name) const;
  std::unordered_map<std::string, std::vector<std::string>> entries_;
};

}  // namespace revkit::infer
