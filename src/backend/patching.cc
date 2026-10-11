// Assemblers, contexts, live patches and export settings for PatchService.

#include "patching.h"

#include <google/protobuf/util/json_util.h>

#include <algorithm>
#include <cstdio>

namespace revkit::backend {

Assemblers::Lease::~Lease() {
  if (!owner_ || !a_) return;
  std::lock_guard lock(owner_->mu_);
  auto &idle = owner_->idle_[language_];
  if (idle.size() < 4) idle.push_back(std::move(a_));
}

Assemblers::Lease Assemblers::Take(const std::string &language) {
  {
    std::lock_guard lock(mu_);
    auto &idle = idle_[language];
    if (!idle.empty()) {
      auto a = std::move(idle.back());
      idle.pop_back();
      return Lease(this, language, std::move(a));
    }
  }
  return Lease(this, language, std::make_unique<assembler::Assembler>(language));
}

std::vector<std::uint32_t> ContextAt(assembler::Assembler &as, const analysis::ProgramInfo &info,
                                     std::uint64_t address, bool thumb,
                                     const google::protobuf::Map<std::string, std::uint32_t> &overrides,
                                     std::string *described) {
  std::vector<std::uint32_t> words = as.default_context();
  std::vector<std::pair<std::string, std::uint32_t>> set;
  for (const analysis::ContextSetting &c : info.context)
    if (address >= c.range.first && address <= c.range.last && as.set_context(words, c.name, c.value))
      set.emplace_back(c.name, c.value);
  if (thumb && !info.isa_context.empty() && as.set_context(words, info.isa_context, 1))
    set.emplace_back(info.isa_context, 1);
  for (const auto &[name, value] : overrides)
    if (as.set_context(words, name, value)) set.emplace_back(name, value);
  if (described) {
    described->clear();
    std::map<std::string, std::uint32_t> last(set.begin(), set.end());
    for (const auto &[name, value] : set) last[name] = value;
    for (const auto &[name, value] : last) {
      if (!described->empty()) *described += ' ';
      *described += name + "=" + std::to_string(value);
    }
  }
  return words;
}

std::vector<LivePatch> LivePatches(const facts::Snapshot &snap, facts::SpaceId space, std::uint64_t first,
                                   std::uint64_t last) {
  std::vector<LivePatch> out;
  const std::uint64_t from = first >= facts::kMaxPatchBytes - 1 ? first - (facts::kMaxPatchBytes - 1) : 0;
  for (std::uint64_t b : *snap.get<facts::AssertedBuckets>({facts::FactKind::Patch, space})) {
    if (b < (from >> facts::kBucketShift) || b > (last >> facts::kBucketShift)) continue;
    for (const auto &[offset, sub] : *snap.get<facts::AssertedKeys>(facts::BucketKey{facts::FactKind::Patch, space, b})) {
      if (!sub.empty() || offset < from || offset > last) continue;
      const facts::FactKey k{facts::FactKind::Patch, facts::Address{space, offset}, sub};
      auto v = snap.get<facts::AssertedFact>(k);
      const std::string *bytes = std::get_if<std::string>(&*v);
      if (bytes == nullptr || bytes->empty() || offset + (bytes->size() - 1) < first) continue;
      out.push_back({k, offset, *bytes});
    }
  }
  std::sort(out.begin(), out.end(), [](const LivePatch &a, const LivePatch &b) { return a.address < b.address; });
  return out;
}

std::vector<patch::Patch> PatchesInOrder(const facts::Snapshot &snap, facts::SpaceId space) {
  std::vector<std::pair<std::string, patch::Patch>> ordered;
  for (const LivePatch &p : LivePatches(snap, space))
    ordered.push_back({*snap.get<facts::AssertedOrder>(p.key), {p.address, p.bytes}});
  std::sort(ordered.begin(), ordered.end(), [](const auto &a, const auto &b) { return a.first < b.first; });
  std::vector<patch::Patch> out;
  for (auto &[order, p] : ordered) out.push_back(std::move(p));
  return out;
}

std::string EncodeSettings(const pb::ExportSettings &s) {
  std::string out;
  google::protobuf::util::JsonPrintOptions o;
  o.always_print_primitive_fields = false;
  (void)google::protobuf::util::MessageToJsonString(s, &out, o);
  return out;
}

bool DecodeSettings(const std::string &text, pb::ExportSettings &out) {
  google::protobuf::util::JsonParseOptions o;
  o.ignore_unknown_fields = true;
  return google::protobuf::util::JsonStringToMessage(text, &out, o).ok();
}

patch::Spec SpecFromPb(const pb::ChecksumSpec &s) {
  patch::Spec out;
  out.algorithm = static_cast<patch::Algorithm>(s.algorithm());
  out.start = s.start();
  out.end = s.end();
  out.skip_padding = s.skip_padding();
  out.field = s.field();
  out.field_offset = s.field_offset();
  out.field_width = s.field_width() ? s.field_width() : 4;
  out.field_big_endian = s.field_big_endian();
  out.name = s.name();
  return out;
}

pb::ChecksumSpec SpecToPb(const patch::Spec &s) {
  pb::ChecksumSpec out;
  out.set_algorithm(static_cast<pb::ChecksumAlgorithm>(s.algorithm));
  out.set_start(s.start);
  out.set_end(s.end);
  out.set_skip_padding(s.skip_padding);
  out.set_field(s.field);
  out.set_field_offset(s.field_offset);
  out.set_field_width(s.field_width);
  out.set_field_big_endian(s.field_big_endian);
  out.set_name(s.name);
  return out;
}

std::string HexBytes(std::string_view bytes) {
  std::string out;
  char buf[4];
  for (char c : bytes) {
    std::snprintf(buf, sizeof buf, "%02x", static_cast<unsigned char>(c));
    out += buf;
  }
  return out;
}

}  // namespace revkit::backend
