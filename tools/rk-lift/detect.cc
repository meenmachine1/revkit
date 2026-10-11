// rk-lift --detect: what revkit::detect says of a file, as JSON
// (scripts/detect_score.py documents the report).
#include "detect.hh"

#include "json.hh"

#include "revkit/detect/detect.hh"
#include "revkit/lift/lifter.hh"

#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>

namespace rklift {

namespace {

// Instruction forms as {"mnemonic/length": count}.
Json forms_json(const std::map<std::pair<std::string, std::uint32_t>, std::uint32_t> &forms) {
  Json::Object out;
  for (const auto &[form, count] : forms) out[form.first + "/" + std::to_string(form.second)] = Json(std::uint64_t{count});
  return out;
}

Json features_json(const revkit::detect::Features &f, bool with_forms) {
  auto n = [](std::uint64_t v) { return Json(v); };
  Json::Object out{{"bytes", n(f.bytes)},
                      {"valid_bytes", n(f.valid_bytes)},
                      {"instructions", n(f.instructions)},
                      {"invalid", n(f.invalid)},
                      {"unimplemented", n(f.unimplemented)},
                      {"callother", n(f.callother)},
                      {"rare", n(f.rare)},
                      {"branches", n(f.branches)},
                      {"branch_near", n(f.branch_near)},
                      {"branch_start", n(f.branch_start)},
                      {"calls", n(f.calls)},
                      {"call_in_file", n(f.call_in_file)},
                      {"call_shared", n(f.call_shared)},
                      {"absolute", n(f.absolute)},
                      {"absolute_swept", n(f.absolute_swept)},
                      {"absolute_start", n(f.absolute_start)},
                      {"abs_pairs", n(f.abs_pairs)},
                      {"abs_pairs_near", n(f.abs_pairs_near)},
                      {"fill_bytes", n(f.fill_bytes)},
                      {"returns", n(f.returns)},
                      {"return_then_start", n(f.return_then_start)},
                      {"indirect", n(f.indirect)},
                      {"sp_reads", n(f.sp_reads)},
                      {"sp_writes", n(f.sp_writes)},
                      {"reached", n(f.reached)},
                      {"reached_odd", n(f.reached_odd)},
                      {"reached_invalid", n(f.reached_invalid)},
                      {"seconds", f.seconds}};
  if (with_forms) {
    out["forms"] = forms_json(f.forms);
    out["reached_forms"] = forms_json(f.reached_forms);
  }
  return out;
}

}  // namespace

int run_detect(const std::string &file, const std::string &ghidra_root, unsigned threads, bool features) {
  std::ifstream in(file, std::ios::binary);
  if (!in) {
    std::cerr << "rk-lift: " << file << ": can't read it\n";
    return 2;
  }
  const std::vector<char> raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  revkit::lift::initialize(ghidra_root);
  revkit::detect::Options options;
  options.threads = threads;
  const revkit::detect::Report r =
      revkit::detect::detect(std::as_bytes(std::span<const char>(raw.data(), raw.size())), options);

  Json::Object doc;
  doc["refusal"] = r.refusal ? Json(Json::Object{{"reason", r.refusal->reason}, {"detail", r.refusal->detail}}) : Json();
  Json::Array suggestions;
  for (const revkit::detect::Suggestion &s : r.suggestions) {
    Json::Array ties, regions, evidence;
    for (const std::string &t : s.tie_group) ties.emplace_back(t);
    for (const std::string &g : s.regions) regions.emplace_back(g);
    for (const revkit::detect::Evidence &e : s.evidence) evidence.push_back(Json::Object{{"about", e.about}, {"text", e.text}});
    Json::Array details;
    for (const revkit::detect::RegionSuggestion &g : s.region_details) {
      Json::Array why;
      for (const std::string &t : g.evidence) why.emplace_back(t);
      details.push_back(Json::Object{{"region", g.spec},
                                     {"kind", std::string(name(g.kind))},
                                     {"start", hex(g.start)},
                                     {"size", hex(g.size)},
                                     {"confidence", std::string(name(g.confidence))},
                                     {"evidence", std::move(why)}});
    }
    suggestions.push_back(Json::Object{
        {"language", s.language},
        {"tie_group", std::move(ties)},
        {"base", s.base ? Json(hex(*s.base)) : Json()},
        {"offset", hex(s.offset)},
        {"regions", std::move(regions)},
        {"region_details", std::move(details)},
        {"confidence", Json::Object{{"processor", std::string(name(s.processor))},
                                    {"variant", std::string(name(s.variant))},
                                    {"base", std::string(name(s.base_confidence))},
                                    {"offset", std::string(name(s.offset_confidence))}}},
        {"score", s.score},
        {"evidence", std::move(evidence)}});
  }
  doc["suggestions"] = std::move(suggestions);
  Json::Array segments;
  for (const revkit::detect::Segment &s : r.segments)
    segments.push_back(Json::Object{{"offset", hex(s.offset)}, {"size", hex(s.size)}, {"kind", std::string(name(s.kind))}});
  doc["segments"] = std::move(segments);
  if (features) {
    Json::Array sweeps;
    // The instruction forms of the best few only: every candidate's would
    // make the report large.
    constexpr std::size_t kWithForms = 6;
    for (const revkit::detect::Sweep &s : r.sweeps) {
      const bool with_forms = sweeps.size() < kWithForms;
      sweeps.push_back(Json::Object{{"candidate", s.candidate.label()},
                                    {"language", s.candidate.language},
                                    {"score", s.score()},
                                    {"quality", Json::Object{{"branches", s.quality.branches},
                                                             {"calls", s.quality.calls},
                                                             {"returns", s.quality.returns},
                                                             {"absolute", s.quality.absolute},
                                                             {"jumps", s.quality.jumps},
                                                             {"plain", s.quality.plain}}},
                                    {"features", features_json(s.features, with_forms)},
                                    {"noise", features_json(s.noise, with_forms)},
                                    {"shifted", features_json(s.shifted, false)}});
    }
    doc["sweeps"] = std::move(sweeps);
  }
  Json(std::move(doc)).write_document(std::cout);
  // 1: nothing to apply without the user (a refusal, or no confident answer).
  const bool confident = !r.refusal && !r.suggestions.empty() &&
                         r.suggestions.front().processor == revkit::detect::Confidence::high;
  return confident ? 0 : 1;
}

}  // namespace rklift
