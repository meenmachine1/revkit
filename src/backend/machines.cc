#include "machines.h"

#include "revkit/emu/machine.hh"

#include <algorithm>
#include <cctype>
#include <ctime>
#include <fstream>
#include <sstream>

namespace revkit::backend {

using api::Error;
using api::Status;
using api::StatusCode;
namespace fs = std::filesystem;

namespace {

bool ValidName(const std::string &n) {
  if (n.empty() || n.size() > 64 || n[0] == '.') return false;
  return std::all_of(n.begin(), n.end(), [](char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '-';
  });
}

std::string Describe(const std::string &text) {
  try {
    const emu::MachineSpec s = emu::parse_machine(text);
    return s.description.empty() ? s.name : s.description;
  } catch (const emu::MachineError &) {
    return {};
  }
}

std::optional<std::string> ReadFile(const fs::path &p) {
  std::ifstream in(p, std::ios::binary);
  if (!in) return std::nullopt;
  std::stringstream s;
  s << in.rdbuf();
  return s.str();
}

void Fill(const MachineProgram &p, const std::string &name, const std::string &text, std::int64_t modified, bool persisted,
          pb::MachineInfo *out) {
  out->set_name(name);
  out->set_program_id(p.program_id);
  out->set_description(Describe(text));
  out->set_modified_unix(modified);
  out->set_bytes(text.size());
  out->set_persisted(persisted);
}

std::int64_t Modified(const fs::path &f) {
  std::error_code ec;
  const auto t = fs::last_write_time(f, ec);
  if (ec) return 0;
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::file_clock::to_sys(t).time_since_epoch())
      .count();
}

}  // namespace

Status MachineStore::List(const MachineProgram &p, pb::ListMachinesResponse &resp) {
  if (!p.dir.empty()) {
    std::error_code ec;
    std::vector<fs::path> files;
    for (const auto &e : fs::directory_iterator(p.dir, ec))
      if (e.is_regular_file() && e.path().extension() == ".json") files.push_back(e.path());
    std::sort(files.begin(), files.end());
    for (const fs::path &f : files) {
      auto text = ReadFile(f);
      if (!text) continue;
      Fill(p, f.stem().string(), *text, Modified(f), true, resp.add_machines());
    }
    return Status::Ok();
  }
  std::lock_guard lock(mu_);
  for (const auto &[name, saved] : memory_[p.program_id]) Fill(p, name, saved.text, saved.modified, false, resp.add_machines());
  return Status::Ok();
}

std::optional<std::string> MachineStore::Load(const MachineProgram &p, const std::string &name) {
  if (!ValidName(name)) return std::nullopt;
  if (!p.dir.empty()) return ReadFile(p.dir / (name + ".json"));
  std::lock_guard lock(mu_);
  auto &m = memory_[p.program_id];
  auto it = m.find(name);
  if (it == m.end()) return std::nullopt;
  return it->second.text;
}

Status MachineStore::Get(const MachineProgram &p, const std::string &name, pb::GetMachineResponse &resp) {
  auto text = Load(p, name);
  if (!text) return Error(StatusCode::kNotFound, "no machine " + name + " for " + p.program_id);
  std::int64_t modified = 0;
  if (!p.dir.empty()) {
    modified = Modified(p.dir / (name + ".json"));
  } else {
    std::lock_guard lock(mu_);
    modified = memory_[p.program_id][name].modified;
  }
  Fill(p, name, *text, modified, !p.dir.empty(), resp.mutable_info());
  resp.set_machine(*text);
  return Status::Ok();
}

Status MachineStore::Save(const MachineProgram &p, const std::string &name, const std::string &text,
                          pb::SaveMachineResponse &resp) {
  if (!ValidName(name)) return Error(StatusCode::kInvalidArgument, "a machine's name is 1-64 characters of [A-Za-z0-9._-]");
  if (text.size() > kMaxBytes) return Error(StatusCode::kInvalidArgument, "a machine description is at most 4 MiB");
  try {
    emu::parse_machine(text);
  } catch (const emu::MachineError &e) {
    return Error(StatusCode::kInvalidArgument, std::string("machine: ") + e.what());
  }
  const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
  if (!p.dir.empty()) {
    std::error_code ec;
    fs::create_directories(p.dir, ec);
    std::size_t n = 0;
    for (const auto &e : fs::directory_iterator(p.dir, ec)) n += e.path().extension() == ".json" && e.path().stem() != name;
    if (n >= kMaxMachines) return Error(StatusCode::kResourceExhausted, "a program keeps at most 64 machines; delete one");
    const fs::path f = p.dir / (name + ".json"), tmp = p.dir / (name + ".json.tmp");
    {
      std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
      out << text;
      if (!out) return Error(StatusCode::kInternal, "can't write " + tmp.string());
    }
    fs::rename(tmp, f, ec);
    if (ec) return Error(StatusCode::kInternal, "can't save " + f.string() + ": " + ec.message());
    Fill(p, name, text, Modified(f), true, resp.mutable_info());
    return Status::Ok();
  }
  std::lock_guard lock(mu_);
  auto &m = memory_[p.program_id];
  if (!m.contains(name) && m.size() >= kMaxMachines)
    return Error(StatusCode::kResourceExhausted, "a program keeps at most 64 machines; delete one");
  m[name] = Saved{text, now};
  Fill(p, name, text, now, false, resp.mutable_info());
  return Status::Ok();
}

Status MachineStore::Delete(const MachineProgram &p, const std::string &name) {
  if (!ValidName(name)) return Error(StatusCode::kInvalidArgument, "bad machine name " + name);
  if (!p.dir.empty()) {
    std::error_code ec;
    if (!fs::remove(p.dir / (name + ".json"), ec))
      return Error(StatusCode::kNotFound, "no machine " + name + " for " + p.program_id);
    return Status::Ok();
  }
  std::lock_guard lock(mu_);
  if (memory_[p.program_id].erase(name) == 0) return Error(StatusCode::kNotFound, "no machine " + name + " for " + p.program_id);
  return Status::Ok();
}

}  // namespace revkit::backend
