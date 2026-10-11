// The candidates: one per processor, byte order and address size the
// install has a language for, in each decoding mode.
#include "revkit/detect/detect.hh"

#include "revkit/lift/lifter.hh"

#include <algorithm>
#include <array>
#include <map>
#include <tuple>

namespace revkit::detect {

namespace {

// Languages that aren't machine code for a processor.
constexpr std::array<std::string_view, 6> kNotMachineCode = {"DATA", "Dalvik", "JVM", "BPF", "eBPF", "Toy"};

// The variant that stands for its group: the one that decodes the most, so
// a sweep doesn't stumble on instructions of a later revision. Which
// variant the code needs is decided afterwards.
constexpr std::array<std::string_view, 6> kPreferred = {"v8", "v8A", "default", "RV64GC", "RV32GC", "RV64G"};

int preference(const std::string &variant) {
  for (std::size_t i = 0; i < kPreferred.size(); ++i)
    if (variant == kPreferred[i]) return static_cast<int>(i);
  return static_cast<int>(kPreferred.size());
}

// The mode a variant name stands for, if it decodes another instruction
// set; "" otherwise.
std::string_view mode_of(const std::string &variant) {
  if (variant.find("16e") != std::string::npos) return "mips16e";
  if (variant.starts_with("micro")) return "micromips";
  if (variant.starts_with("VLE")) return "vle";
  return "";
}

}  // namespace

std::vector<Candidate> candidates() {
  // Groups in id order (list_languages sorts), so the result is stable.
  std::map<std::tuple<std::string, bool, int>, std::vector<lift::LanguageSummary>> groups;
  for (lift::LanguageSummary &l : lift::list_languages()) {
    if (l.deprecated) continue;
    if (std::find(kNotMachineCode.begin(), kNotMachineCode.end(), l.processor) != kNotMachineCode.end()) continue;
    if (l.id.find(":LEBE:") != std::string::npos) continue;  // mixed byte order: its plain siblings stand for it
    groups[{l.processor, l.big_endian, l.size}].push_back(std::move(l));
  }
  std::vector<Candidate> out, modes;
  for (auto &[key, all] : groups) {
    // Variants that decode another instruction set altogether (MIPS16e,
    // microMIPS, PowerPC VLE) are modes of their own, not variants of the
    // group's.
    std::vector<lift::LanguageSummary> group;
    for (lift::LanguageSummary &l : all) {
      // The id's own variant field: the summary's may be a longer name.
      const std::string variant = l.id.substr(l.id.rfind(':') + 1);
      if (const std::string_view m = mode_of(variant); !m.empty()) {
        Candidate c;
        c.language = l.id;
        c.mode = std::string(m);
        // microMIPS languages start in MIPS32, VLE ones in Book E; MIPS16e
        // ones in MIPS16e.
        if (m == "micromips") c.context = {{"ISA_MODE", 1}};
        if (m == "vle") c.context = {{"vle", 1}};
        c.languages = {l.id};
        modes.push_back(std::move(c));
      } else {
        group.push_back(std::move(l));
      }
    }
    if (group.empty()) continue;
    const lift::LanguageSummary *best = &group.front();
    for (const lift::LanguageSummary &l : group)
      if (preference(l.variant) < preference(best->variant)) best = &l;
    Candidate c;
    c.language = best->id;
    for (const lift::LanguageSummary &l : group) c.languages.push_back(l.id);
    out.push_back(c);
    // ARM's other instruction set, where the language has it.
    if (std::get<0>(key) == "ARM") {
      c.mode = "thumb";
      c.context = {{"TMode", 1}};
      out.push_back(std::move(c));
    }
  }
  for (Candidate &m : modes) out.push_back(std::move(m));
  return out;
}

}  // namespace revkit::detect
