// Whether a language's whole instruction set fits the code: what the code
// that control flow reaches decodes to, against what real code of the
// language is made of (profiles.inc). A processor derived from another
// shares its branches, so the sweep's control-flow evidence can't tell
// the two apart; the rest of the instruction set can.
#include "revkit/detect/detect.hh"

#include <algorithm>

namespace revkit::detect {

namespace {

using Mnemonics = std::pair<std::string_view, std::uint32_t>;

#include "profiles.inc"

}  // namespace

std::uint32_t Profile::count(std::string_view mnemonic) const {
  const auto it = std::lower_bound(mnemonics.begin(), mnemonics.end(), mnemonic,
                                   [](const Mnemonics &m, std::string_view v) { return m.first < v; });
  return it != mnemonics.end() && it->first == mnemonic ? it->second : 0;
}

const Profile *profile(std::string_view processor, int bits, std::string_view mode) {
  for (const Profile &p : kProfiles)
    if (p.processor == processor && p.bits == bits && p.mode == mode) return &p;
  return nullptr;
}

Fit fit(const Features &code, const Features &noise, const Profile *profile) {
  Fit out;
  out.reached = code.reached;
  out.cut = code.reached_invalid;
  if (profile == nullptr || profile->total == 0) return out;
  out.profiled = true;
  auto census = [&](const Features &f, std::uint64_t &counted, std::uint64_t &rare) {
    for (const auto &[form, n] : f.reached_forms) {
      counted += n;
      if (static_cast<double>(profile->count(form.first)) < Fit::kRare * static_cast<double>(profile->total)) rare += n;
    }
  };
  census(code, out.counted, out.rare);
  census(noise, out.noise_counted, out.noise_rare);
  return out;
}

}  // namespace revkit::detect
