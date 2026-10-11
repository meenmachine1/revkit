#include "revkit/cparse/spec.h"

#include "revkit/lift/abi.hh"

namespace revkit::cparse {

DataOrganization read_data_organization(const std::string &language_id, const std::string &compiler_id) {
  const lift::DataOrganization raw = lift::read_data_organization(language_id, compiler_id);
  DataOrganization o;
  auto get = [&](const char *name) -> std::optional<std::uint32_t> {
    auto it = raw.values.find(name);
    if (it == raw.values.end() || it->second < 0 || it->second > 1024) return std::nullopt;
    return static_cast<std::uint32_t>(it->second);
  };
  o.absolute_max_alignment = get("absolute_max_alignment");
  o.machine_alignment = get("machine_alignment");
  o.default_alignment = get("default_alignment");
  o.default_pointer_alignment = get("default_pointer_alignment");
  o.pointer_size = get("pointer_size");
  o.wchar_size = get("wchar_size");
  o.short_size = get("short_size");
  o.integer_size = get("integer_size");
  o.long_size = get("long_size");
  o.long_long_size = get("long_long_size");
  o.float_size = get("float_size");
  o.double_size = get("double_size");
  o.long_double_size = get("long_double_size");
  o.char_signed = raw.char_signed;
  for (const auto &[s, a] : raw.size_alignment)
    if (s > 0 && s <= 64 && a > 0 && a <= 64) o.size_alignment.emplace_back(std::uint32_t(s), std::uint32_t(a));
  o.ms_bitfields = raw.ms_bitfields;
  return o;
}

Profile profile_for_language(const std::string &language_id, const std::string &compiler_id, const std::string &format,
                             std::vector<std::string> *notes) {
  ProfileInputs in;
  in.language_id = language_id;
  in.compiler_id = compiler_id;
  in.format = format;
  in.data_org = read_data_organization(language_id, compiler_id);
  return profile_for(in, notes);
}

}  // namespace revkit::cparse
