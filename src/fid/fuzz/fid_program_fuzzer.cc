// Function ID matching against a hostile database, and the relocations of
// a hostile PE as FID hashing reads them (image_relocations: the base
// relocation directory). Input: the database, then "RKFZ", then the PE.
// The program's functions take the database's own hashes (so lookups hit)
// with callers and callees drawn from the bytes, as a program whose
// functions are a library's would; search() then scores every candidate,
// its relations and its library, as ListFidMatches does.
#include "revkit/fid/match.h"
#include "revkit/fid/program.h"
#include "revkit/loader/load.hh"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  using namespace revkit;
  const std::string_view in(reinterpret_cast<const char *>(data), size);
  const std::size_t sep = in.find("RKFZ");
  const std::string_view db_bytes = in.substr(0, sep);
  if (sep != std::string_view::npos) {
    const std::string_view pe = in.substr(sep + 4);
    auto bytes = std::make_shared<loader::Bytes>(pe.size());
    std::memcpy(bytes->data(), pe.data(), pe.size());
    try {
      const loader::Image img = loader::parse_pe(std::move(bytes));
      fid::ProgramSource src;
      fid::image_relocations(img, src);
      if (!std::is_sorted(src.relocations.begin(), src.relocations.end())) __builtin_trap();
    } catch (const loader::LoadError &) {
    }
  }
  try {
    const fid::Database db = fid::Database::parse(std::as_bytes(std::span(db_bytes.data(), db_bytes.size())), "fuzz");
    fid::ProgramHashes program;
    program.language = db.libraries().empty() ? "x86:LE:64:default" : db.libraries().front().language;
    const std::size_t n = std::min<std::size_t>(db.functions().size(), 512);
    for (std::size_t i = 0; i < n; ++i) {
      fid::ProgramFunction f;
      f.entry = 0x1000 + 16 * i;
      f.hash = db.functions()[i].hash;
      program.functions.push_back(std::move(f));
    }
    for (std::size_t i = 0; i < n && n > 1; ++i) {
      const std::size_t callee = static_cast<unsigned char>(db_bytes[i % db_bytes.size()]) % n;
      if (callee == i) continue;
      program.functions[i].callees.push_back(callee);
      program.functions[callee].callers.push_back(i);
    }
    const std::vector<const fid::Database *> dbs = {&db};
    for (const fid::Match &m : fid::search(program, fid::for_language(dbs, program.language))) (void)m.comment();
  } catch (const fid::FidError &) {
  }
  return 0;
}
