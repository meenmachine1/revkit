#include "go_import.h"

#include "program.h"

#include "revkit/loader/gopclntab.hh"

#include <set>

namespace revkit::backend {

namespace {

using facts::FactKind;

pb::AssertionBody RenameBody(std::uint64_t a, const std::string &name) {
  pb::AssertionBody body;
  body.mutable_rename()->mutable_target()->mutable_address()->set_offset(a);
  body.mutable_rename()->set_name(name);
  return body;
}

}  // namespace

std::optional<AnalysisFacts> CollectGoAnalysis(const Program &program, const std::vector<DebugFacts> &debug) {
  const loader::Image &image = program.image();
  if (image.format == loader::Format::raw) return std::nullopt;
  std::string error;
  std::optional<loader::GoPclntab> t = loader::read_go_pclntab(image, &error);
  AnalysisFacts out;
  out.source = "go";
  if (!t) {
    if (error.empty()) return std::nullopt;
    out.warnings.push_back(error);
    return out;
  }
  const std::map<std::uint64_t, std::string> known = FileAndDebugNames(program, debug);
  std::size_t functions = 0, names = 0, lines = 0, no_return = 0;
  std::set<std::uint64_t> seen;
  for (const loader::GoFunction &f : t->functions) {
    // go:buildid is the build ID string at the start of the text, not code.
    if (f.name == "go:buildid" || f.name == "go.buildid") continue;
    if (!program.executable(f.entry) || !seen.insert(f.entry).second) continue;
    AnalysisAssertion bounds;
    bounds.kind = FactKind::FunctionBounds;
    bounds.address = f.entry;
    bounds.value = facts::AddressSet{};
    bounds.body.mutable_function_bounds()->mutable_entry()->set_offset(f.entry);
    out.assertions.push_back(std::move(bounds));
    ++functions;
    const std::string name = loader::go_display_name(f.name);
    if (!known.contains(f.entry)) {
      out.assertions.push_back({FactKind::Name, f.entry, {}, name, RenameBody(f.entry, name)});
      ++names;
    }
    // Ghidra's "Golang source:" plate comment, with Go's own spelling when
    // the name had to change.
    std::string plate;
    if (!f.file.empty()) {
      plate = "Go source: " + f.file;
      if (f.line > 0) plate += ":" + std::to_string(f.line);
      ++lines;
    }
    if (name != f.name) plate += std::string(plate.empty() ? "" : "\n") + "Go name: " + f.name;
    if (!plate.empty()) {
      AnalysisAssertion c;
      c.kind = FactKind::Comment;
      c.address = f.entry;
      c.sub = "plate";
      c.value = plate;
      pb::Comment *pc = c.body.mutable_comment();
      pc->mutable_address()->set_offset(f.entry);
      pc->set_kind(pb::COMMENT_KIND_PLATE);
      pc->set_text(plate);
      out.assertions.push_back(std::move(c));
    }
    if (loader::go_function_no_return(f.name)) {
      AnalysisAssertion n;
      n.kind = FactKind::NoReturn;
      n.address = f.entry;
      n.value = std::int64_t{1};
      n.body.mutable_no_return()->mutable_function()->set_offset(f.entry);
      n.body.mutable_no_return()->set_no_return(true);
      out.assertions.push_back(std::move(n));
      ++no_return;
    }
  }
  out.counts["functions"] = functions;
  out.counts["names"] = names;
  out.counts["source_lines"] = lines;
  out.counts["no_return_functions"] = no_return;
  out.warnings.push_back("pclntab " + std::string(loader::to_string(t->version)) + " layout");
  for (const std::string &w : t->warnings) out.warnings.push_back(w);
  return out;
}

}  // namespace revkit::backend
