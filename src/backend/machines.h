// Machine descriptions kept with a program (docs/firmware-emulation.md):
// in the project's directory (machines/<program>/<name>.json) when it has
// one, else in memory. A description is checked when saved.
#pragma once

#include "revkit/api/backend.h"

#include <cstdint>
#include <filesystem>
#include <map>
#include <mutex>
#include <optional>
#include <string>

namespace revkit::backend {

namespace pb = ::revkit::v1;

struct MachineProgram {
  std::string program_id;
  std::filesystem::path dir;  // empty: memory
};

class MachineStore {
 public:
  api::Status List(const MachineProgram &p, pb::ListMachinesResponse &resp);
  api::Status Get(const MachineProgram &p, const std::string &name, pb::GetMachineResponse &resp);
  api::Status Save(const MachineProgram &p, const std::string &name, const std::string &text, pb::SaveMachineResponse &resp);
  api::Status Delete(const MachineProgram &p, const std::string &name);
  std::optional<std::string> Load(const MachineProgram &p, const std::string &name);

  static constexpr std::size_t kMaxMachines = 64;
  static constexpr std::size_t kMaxBytes = 4u << 20;

 private:
  struct Saved {
    std::string text;
    std::int64_t modified = 0;
  };
  std::mutex mu_;
  std::map<std::string, std::map<std::string, Saved>> memory_;  // program -> name -> description
};

}  // namespace revkit::backend
