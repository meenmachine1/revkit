#include "bsim_catalog.h"

#include <algorithm>
#include <filesystem>
#include <sstream>

namespace revkit::backend {

std::vector<std::string> DecodeBsimAttached(const std::string &text) {
  std::vector<std::string> out;
  std::istringstream in(text);
  for (std::string line; std::getline(in, line);)
    if (line.starts_with("attach ") && line.size() > 7) {
      std::string p = line.substr(7);
      if (std::find(out.begin(), out.end(), p) == out.end()) out.push_back(std::move(p));
    }
  return out;
}

std::string EncodeBsimAttached(const std::vector<std::string> &paths) {
  std::string out;
  for (const std::string &p : paths) out += "attach " + p + "\n";
  return out;
}

std::shared_ptr<BsimEntry> BsimCatalog::Open(const std::string &path) {
  {
    std::lock_guard lock(mu_);
    auto it = open_.find(path);
    if (it != open_.end()) {
      std::lock_guard use(it->second->mu);
      it->second->db.reload();
      return it->second;
    }
  }
  auto e = std::make_shared<BsimEntry>(bsim::Database::open(path));
  std::lock_guard lock(mu_);
  return open_.try_emplace(path, e).first->second;
}

std::shared_ptr<BsimEntry> BsimCatalog::Create(const std::string &path, bsim::DatabaseInfo info) {
  auto e = std::make_shared<BsimEntry>(bsim::Database::create(path, std::move(info)));
  std::lock_guard lock(mu_);
  open_[path] = e;
  return e;
}

pb::BSimTemplate ToProto(bsim::Template t) {
  switch (t) {
    case bsim::Template::w64: return pb::BSIM_TEMPLATE_64;
    case bsim::Template::w32: return pb::BSIM_TEMPLATE_32;
    case bsim::Template::nosize: return pb::BSIM_TEMPLATE_NOSIZE;
  }
  return pb::BSIM_TEMPLATE_UNSPECIFIED;
}

bsim::Template FromProto(pb::BSimTemplate t, bsim::Template fallback) {
  switch (t) {
    case pb::BSIM_TEMPLATE_64: return bsim::Template::w64;
    case pb::BSIM_TEMPLATE_32: return bsim::Template::w32;
    case pb::BSIM_TEMPLATE_NOSIZE: return bsim::Template::nosize;
    default: return fallback;
  }
}

void FillBsimDatabase(const std::string &id, const bsim::Database &db, pb::BSimDatabase &out) {
  const bsim::DatabaseInfo &i = db.info();
  out.set_id(id);
  out.set_name(i.name);
  out.set_description(i.description);
  out.set_template_(ToProto(i.weights));
  out.set_settings(i.settings);
  out.set_lsh_k(i.lsh.k);
  out.set_lsh_l(i.lsh.l);
  out.set_executables(static_cast<std::uint32_t>(db.executables().size()));
  out.set_functions(db.function_count());
  out.mutable_created()->set_seconds(i.created);
}

void FillBsimExecutable(const bsim::Executable &e, pb::BSimExecutable &out) {
  out.set_id(e.id);
  out.set_name(e.name);
  out.set_path(e.path);
  out.set_language(e.language);
  out.set_compiler(e.compiler);
  out.set_md5(e.md5);
  out.mutable_ingested()->set_seconds(e.ingested);
  out.set_source(e.source);
  for (const auto &[k, v] : e.categories) (*out.mutable_categories())[k] = v;
  out.set_function_count(e.function_count);
}

void FillBsimFunction(const bsim::Executable &e, const bsim::FunctionRecord &f, pb::BSimFunction &out) {
  out.set_name(f.name);
  out.mutable_entry()->set_offset(f.entry);
  out.set_prototype(f.prototype);
  out.set_size(f.size);
  out.set_default_name((f.flags & bsim::kDefaultName) != 0);
  out.set_feature_count(static_cast<std::uint32_t>(f.features.size()));
  out.set_executable_id(e.id);
}

}  // namespace revkit::backend
