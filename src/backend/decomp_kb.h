// The decomp knowledge base (docs/decomp-kb.md): finished matching
// decompilations as records of their functions (Function ID hashes,
// translation unit, verbatim source, compiler and flags), kept in a
// directory on the daemon's host, and matched against a new program.
//
//   <kb>/kb.json           format, name, language, the games ingested
//   <kb>/functions.jsonl   one revkit.v1.DecompKbFunction per line (protobuf JSON)
//   <kb>/sources/<game>/<unit path>   each unit's source file, verbatim
//
// This file holds what doesn't need the backend: reading and writing the
// KB, the manifest, and finding a function's own text in its unit.
#pragma once

#include "revkit/v1/project.pb.h"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::backend {

namespace pb = ::revkit::v1;

inline constexpr std::string_view kDecompKbFormat = "revkit-decomp-kb/1";

struct DecompKb {
  std::string name;
  std::string language;
  std::vector<std::string> games;
  std::vector<pb::DecompKbFunction> functions;
};

// Reads the KB at `dir`; an empty KB when it doesn't exist yet. nullopt
// with `error` for a KB that doesn't parse.
std::optional<DecompKb> ReadDecompKb(const std::string &dir, std::string *error);
// Writes kb.json and functions.jsonl (sources are written by the caller).
bool WriteDecompKb(const std::string &dir, const DecompKb &kb, std::string *error);

// One manifest line's fields (docs/decomp-kb.md, "The manifest"): a
// matching pipeline's names (name, isa, masked_sha256) or the older ones
// (symbol, mode, masked_hash).
struct ManifestEntry {
  std::string module;
  std::uint64_t address = 0;
  std::uint64_t size = 0;
  std::string mode, symbol, compiler, flags, status, source, masked_hash, library, object, variant;
  double fuzzy = 0;
  std::uint32_t relocations = 0;
};
// The manifest by (module, address); lines that don't parse are counted
// in `bad`.
std::map<std::pair<std::string, std::uint64_t>, ManifestEntry> ReadManifest(std::string_view text, std::size_t *bad);
// A manifest's status as the KB keeps it: "matching" for an exact match
// ("exact", "matching", "match", "ok"), "nonmatching" for fuzzy ones,
// "asm"; others as given, lowercased.
std::string NormalizeStatus(std::string_view status);

// A unified diff of two instruction listings, `a` (the KB function's)
// to `b`: lines " x" (both), "-x" (a's only), "+x" (b's only), from the
// longest common subsequence. Listings over `limit` lines each are cut.
std::string InstructionDiff(const std::vector<std::string> &a, const std::vector<std::string> &b,
                            std::size_t limit = 2000);

// The definition of the function `qualified` ("GameOverScene::Update",
// "Clamp", "GameOverScene::~GameOverScene") in C or C++ source: from its
// declaration's first line to its closing brace, comments and string
// literals respected; an in-class definition by its last component.
// nullopt when there is none (a declaration only, a macro, asm).
std::optional<std::string> ExtractFunctionText(std::string_view source, std::string_view qualified);

}  // namespace revkit::backend
