// PDB streams (info, DBI, TPI/IPI, symbols) into revkit's debug info model.

#include "revkit/debuginfo/pdb.h"

#include "codeview.h"
#include "cursor.h"
#include "msf.h"
#include "pdb_types.h"
#include "revkit/demangle/demangle.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace revkit::debuginfo {
namespace {

using pdb::Msf;
using types::TypeId;

constexpr std::uint16_t kNoStream = 0xffff;
constexpr std::size_t kMaxDiagnostics = 256;
constexpr std::size_t kMaxScopeDepth = 1024;
constexpr int kMaxSymbolErrors = 16;  // per symbol stream

// DBI stream header (DbiStreamHeader in LLVM's naming).
struct DbiHeader {
  std::uint32_t age = 0;
  std::uint16_t global_stream = kNoStream;
  std::uint16_t public_stream = kNoStream;
  std::uint16_t symbol_stream = kNoStream;
  std::uint32_t module_info_size = 0;
  std::uint32_t contribution_size = 0;
  std::uint32_t section_map_size = 0;
  std::uint32_t source_info_size = 0;
  std::uint32_t type_server_map_size = 0;
  std::uint32_t optional_header_size = 0;
  std::uint32_t ec_size = 0;
  std::uint16_t machine = 0;
};
constexpr std::size_t kDbiHeaderSize = 64;

DbiHeader parse_dbi_header(Cursor &c) {
  DbiHeader h;
  std::int32_t signature = std::int32_t(c.u32());
  if (signature != -1) throw FormatError("DBI stream has an old-format header");
  c.u32();  // version
  h.age = c.u32();
  h.global_stream = c.u16();
  c.u16();  // build number
  h.public_stream = c.u16();
  c.u16();  // PDB DLL version
  h.symbol_stream = c.u16();
  c.u16();  // PDB DLL rebuild
  h.module_info_size = c.u32();
  h.contribution_size = c.u32();
  h.section_map_size = c.u32();
  h.source_info_size = c.u32();
  h.type_server_map_size = c.u32();
  c.u32();  // MFC type server index
  h.optional_header_size = c.u32();
  h.ec_size = c.u32();
  c.u16();  // flags
  h.machine = c.u16();
  c.u32();
  return h;
}

std::string hex(std::uint64_t v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
  return buf;
}

// Name without its enclosing scopes: "ns::Foo<a::b>::bar" -> "bar".
std::string unqualified(std::string_view name) {
  int depth = 0;
  std::size_t start = 0;
  for (std::size_t i = 0; i < name.size(); ++i) {
    char ch = name[i];
    if (ch == '<' || ch == '(' || ch == '[') ++depth;
    else if ((ch == '>' || ch == ')' || ch == ']') && depth > 0) --depth;
    else if (ch == ':' && depth == 0 && i + 1 < name.size() && name[i + 1] == ':') {
      // "operator::" doesn't exist; anything after "operator" is the name.
      if (name.substr(start).starts_with("operator")) break;
      start = i + 2;
      ++i;
    }
  }
  return std::string(name.substr(start));
}

PdbIdentity parse_info_stream(const std::vector<std::uint8_t> &s) {
  PdbIdentity id;
  Cursor c(s, false);
  try {
    id.version = c.u32();
    id.signature = c.u32();
    id.age = c.u32();
    auto g = c.bytes(16);
    std::copy(g.begin(), g.end(), id.guid.begin());
  } catch (const FormatError &e) {
    throw PdbError(std::string("PDB info stream: ") + e.what());
  }
  if (id.version < cv::kPdbVersionVC70)
    throw PdbError("PDB info stream version " + std::to_string(id.version) + " is not supported");
  // Named stream map, then feature codes. Damage here loses the names but
  // not the identity.
  try {
    std::uint32_t strings = c.u32();
    auto buf = c.bytes(strings);
    std::uint32_t size = c.u32();
    std::uint32_t capacity = c.u32();
    std::uint32_t present_words = c.u32();
    if (present_words > c.remaining() / 4) throw FormatError("bad hash table");
    std::vector<std::uint32_t> present(present_words);
    for (auto &w : present) w = c.u32();
    std::uint32_t deleted_words = c.u32();
    c.skip(std::uint64_t(deleted_words) * 4);
    std::uint32_t found = 0;
    for (std::uint64_t bit = 0; bit < std::uint64_t(present_words) * 32 && bit < capacity; ++bit) {
      if (!(present[bit / 32] >> (bit % 32) & 1)) continue;
      std::uint32_t key = c.u32();
      std::uint32_t value = c.u32();
      if (key < buf.size()) {
        std::size_t end = key;
        while (end < buf.size() && buf[end]) ++end;
        id.named_streams.emplace(std::string(reinterpret_cast<const char *>(buf.data()) + key, end - key), value);
      }
      if (++found >= size) break;
    }
    while (c.remaining() >= 4)
      if (c.u32() == cv::kFeatureVC140) id.has_ipi = true;
  } catch (const FormatError &) {
  }
  return id;
}

class Reader {
 public:
  Reader(std::span<const std::uint8_t> file, types::TypeStore &store, const PdbOptions &opt,
         PdbDebugInfo &out)
      : msf_(file), store_(store), opt_(opt), out_(out) {}

  void identify() {
    if (!msf_.has_stream(1)) throw PdbError("PDB has no info stream");
    try {
      out_.identity = parse_info_stream(msf_.read(1));
    } catch (const FormatError &e) {
      throw PdbError(std::string("PDB info stream: ") + e.what());
    }
    if (msf_.has_stream(4) && !out_.identity.has_ipi && msf_.stream_size(4) >= 56)
      out_.identity.has_ipi = true;  // old writers omit the feature code
    if (!msf_.has_stream(3)) return;
    try {
      dbi_ = msf_.read(3);
      Cursor c(dbi_, false);
      dbi_header_ = parse_dbi_header(c);
      have_dbi_ = true;
      out_.identity.dbi_age = dbi_header_.age;
      out_.identity.machine = dbi_header_.machine;
    } catch (const FormatError &e) {
      diag(0, std::string("DBI stream: ") + e.what());
    }
  }

  void run() {
    identify();
    pointer_size_ = out_.identity.machine == 0x14c || out_.identity.machine == 0x1c4 ? 4 : 8;
    read_types();
    if (have_dbi_) {
      read_dbi();
      read_global_symbols();
      for (std::size_t i = 0; i < out_.modules.size(); ++i) read_module(i);
    }
    finish();
  }

 private:
  void diag(std::uint64_t offset, std::string msg) {
    if (out_.diagnostics.size() < kMaxDiagnostics) out_.diagnostics.push_back({offset, std::move(msg)});
  }

  // --- types --------------------------------------------------------------

  void read_types() {
    try {
      std::string warning;
      tpi_ = pdb::TypeStream::parse(msf_.read(2), &warning);
      if (!warning.empty()) diag(0, "TPI: " + warning);
    } catch (const FormatError &e) {
      diag(0, std::string("TPI stream: ") + e.what());
    }
    if (out_.identity.has_ipi && msf_.has_stream(4)) {
      try {
        std::string warning;
        ipi_ = pdb::TypeStream::parse(msf_.read(4), &warning);
        if (!warning.empty()) diag(0, "IPI: " + warning);
      } catch (const FormatError &e) {
        diag(0, std::string("IPI stream: ") + e.what());
      }
    }
    types_.emplace(tpi_, store_, pointer_size_, opt_.resolve_forward_refs, out_.diagnostics);
    types_->import_all();
  }

  // A string of the "/names" stream (the PDB's string table) by offset.
  std::string names_string(std::uint32_t offset) {
    if (!names_loaded_) {
      names_loaded_ = true;
      auto it = out_.identity.named_streams.find("/names");
      if (it != out_.identity.named_streams.end() && msf_.has_stream(it->second)) {
        try {
          std::vector<std::uint8_t> bytes = msf_.read(it->second);
          Cursor c(bytes, false);
          if (c.u32() == 0xEFFEEFFEu) {
            c.u32();  // version
            const std::uint32_t size = c.u32();
            auto buf = c.bytes(size);
            names_.assign(buf.begin(), buf.end());
          }
        } catch (const FormatError &) {
        }
      }
    }
    if (offset >= names_.size()) return {};
    const auto *p = reinterpret_cast<const char *>(names_.data()) + offset;
    return std::string(p, strnlen(p, names_.size() - offset));
  }

  // The TPI type of an S_*PROC32_ID symbol's LF_FUNC_ID / LF_MFUNC_ID.
  std::uint32_t function_id_type(std::uint32_t id) {
    pdb::TypeRecord r = ipi_.record(id);
    if (r.kind != cv::LF_FUNC_ID && r.kind != cv::LF_MFUNC_ID) return 0;
    Cursor c(r.data, false);
    c.u32();  // scope or parent class
    return c.u32();
  }

  // --- DBI ----------------------------------------------------------------

  void read_dbi() {
    const DbiHeader &h = dbi_header_;
    std::uint64_t pos = kDbiHeaderSize;
    auto sub = [&](std::uint32_t size, const char *what) -> std::span<const std::uint8_t> {
      if (pos > dbi_.size() || size > dbi_.size() - pos) {
        diag(0, std::string("DBI ") + what + " substream runs past the end of the stream");
        pos = dbi_.size();
        return {};
      }
      auto s = std::span<const std::uint8_t>(dbi_).subspan(std::size_t(pos), size);
      pos += size;
      return s;
    };
    auto modules = sub(h.module_info_size, "module info");
    auto contributions = sub(h.contribution_size, "section contribution");
    auto section_map = sub(h.section_map_size, "section map");
    sub(h.source_info_size, "source info");
    sub(h.type_server_map_size, "type server map");
    sub(h.ec_size, "EC");
    auto optional = sub(h.optional_header_size, "optional debug header");

    read_optional_header(optional);
    read_section_map(section_map);
    read_modules(modules);
    read_contributions(contributions);
  }

  std::vector<PdbSectionHeader> read_section_headers(std::uint16_t stream) {
    std::vector<PdbSectionHeader> out;
    if (stream == kNoStream || !msf_.has_stream(stream)) return out;
    try {
      std::vector<std::uint8_t> s = msf_.read(stream);
      Cursor c(s, false);
      while (c.remaining() >= 40) {
        PdbSectionHeader hdr;
        auto name = c.bytes(8);
        std::size_t n = 0;
        while (n < 8 && name[n]) ++n;
        hdr.name.assign(reinterpret_cast<const char *>(name.data()), n);
        hdr.virtual_size = c.u32();
        hdr.virtual_address = c.u32();
        hdr.raw_size = c.u32();
        c.skip(12);  // raw data, relocation and line number pointers
        c.skip(4);   // relocation and line number counts
        hdr.characteristics = c.u32();
        out.push_back(std::move(hdr));
      }
    } catch (const FormatError &e) {
      diag(0, std::string("section headers: ") + e.what());
    }
    return out;
  }

  void read_optional_header(std::span<const std::uint8_t> data) {
    std::vector<std::uint16_t> streams;
    for (std::size_t i = 0; i + 2 <= data.size(); i += 2) streams.push_back(std::uint16_t(data[i] | data[i + 1] << 8));
    auto slot = [&](unsigned i) { return i < streams.size() ? streams[i] : kNoStream; };
    out_.sections = read_section_headers(slot(cv::kDbgSectionHdr));
    std::uint16_t omap = slot(cv::kDbgOmapFromSrc);
    if (omap != kNoStream && msf_.has_stream(omap)) {
      try {
        std::vector<std::uint8_t> s = msf_.read(omap);
        Cursor c(s, false);
        while (c.remaining() >= 8) {
          std::uint32_t from = c.u32();
          omap_.push_back({from, c.u32()});
        }
        std::stable_sort(omap_.begin(), omap_.end(),
                         [](const auto &a, const auto &b) { return a.first < b.first; });
      } catch (const FormatError &e) {
        diag(0, std::string("OMAP: ") + e.what());
      }
      original_sections_ = read_section_headers(slot(cv::kDbgSectionHdrOrig));
      if (original_sections_.empty()) original_sections_ = out_.sections;
    }
  }

  void read_section_map(std::span<const std::uint8_t> data) {
    if (data.empty()) return;
    try {
      Cursor c(data, false);
      std::uint16_t count = c.u16();
      c.u16();  // logical segment count
      for (std::uint16_t i = 0; i < count; ++i) {
        SectionMapEntry e;
        e.flags = c.u16();
        c.u16();  // overlay
        c.u16();  // group
        e.frame = c.u16();
        c.u16();  // section name
        c.u16();  // class name
        e.offset = c.u32();
        c.u32();  // length
        section_map_.push_back(e);
      }
    } catch (const FormatError &e) {
      diag(0, std::string("section map: ") + e.what());
    }
  }

  void read_modules(std::span<const std::uint8_t> data) {
    Cursor c(data, false);
    try {
      while (c.remaining() >= 64) {
        PdbModule m;
        c.u32();
        c.skip(28);  // the module's first section contribution
        c.u16();     // flags
        m.stream = c.u16();
        m.symbol_bytes = c.u32();
        c.u32();  // C11 line bytes
        m.c13_line_bytes = c.u32();
        m.source_files = c.u16();
        c.u16();
        c.u32();
        c.u32();  // source file name index
        c.u32();  // PDB file path name index
        m.name = std::string(pdb::read_name(c));
        m.object = std::string(pdb::read_name(c));
        c.seek(std::min<std::size_t>((c.pos() + 3) & ~std::size_t(3), c.size()));
        out_.modules.push_back(std::move(m));
      }
    } catch (const FormatError &e) {
      diag(0, std::string("module info: ") + e.what());
    }
  }

  void read_contributions(std::span<const std::uint8_t> data) {
    if (data.size() < 4) return;
    Cursor c(data, false);
    try {
      std::uint32_t version = c.u32();
      std::size_t entry = version == 0xeffe0000u + 20140516u ? 32 : 28;
      if (version != 0xeffe0000u + 19970605u && entry == 28) {
        diag(0, "unknown section contribution version " + hex(version));
        return;
      }
      while (c.remaining() >= entry) {
        std::size_t start = c.pos();
        PdbContribution sc;
        sc.section = c.u16();
        c.u16();
        sc.offset = c.u32();
        sc.size = c.u32();
        sc.characteristics = c.u32();
        sc.module = c.u16();
        c.seek(start + entry);
        if (auto r = rva(sc.section, sc.offset)) sc.address = opt_.image_base + *r;
        out_.contributions.push_back(sc);
      }
    } catch (const FormatError &e) {
      diag(0, std::string("section contributions: ") + e.what());
    }
  }

  // section:offset -> RVA through the section map, section headers and
  // OMAP; nullopt if the address isn't in the image.
  std::optional<std::uint64_t> rva(std::uint16_t segment, std::uint32_t offset) const {
    if (segment == 0) return std::nullopt;
    const auto &headers = omap_.empty() ? out_.sections : original_sections_;
    std::uint32_t frame = segment;
    std::uint64_t base = 0;
    if (segment <= section_map_.size()) {
      const SectionMapEntry &e = section_map_[segment - 1];
      if (e.flags & 0x200) return std::nullopt;  // IsAbsoluteAddress: not in a section
      frame = e.frame;
      base = e.offset;
    }
    if (frame == 0 || frame > headers.size()) return std::nullopt;
    std::uint64_t r = std::uint64_t(headers[frame - 1].virtual_address) + base + offset;
    if (omap_.empty()) return r;
    if (r > 0xffffffffu) return std::nullopt;
    auto it = std::upper_bound(omap_.begin(), omap_.end(), std::uint32_t(r),
                               [](std::uint32_t v, const auto &e) { return v < e.first; });
    if (it == omap_.begin()) return std::nullopt;
    --it;
    if (it->second == 0) return std::nullopt;  // code the rewriter removed
    return std::uint64_t(it->second) + (r - it->first);
  }

  // --- symbols ------------------------------------------------------------

  struct Symbol {
    std::uint16_t kind;
    std::span<const std::uint8_t> data;
    std::size_t offset;
  };

  // Symbol records in [begin, end) of `bytes`; stops at the first record
  // whose length is bad, reporting it.
  template <class F>
  void for_each_symbol(std::span<const std::uint8_t> bytes, std::size_t begin, std::size_t end,
                       std::uint64_t diag_base, F &&f) {
    end = std::min(end, bytes.size());
    std::size_t pos = begin;
    int errors = 0;
    while (pos + 4 <= end) {
      std::uint16_t len = std::uint16_t(bytes[pos] | bytes[pos + 1] << 8);
      if (len < 2 || pos + 2 + len > end) {
        diag(diag_base + pos, "bad symbol record length " + std::to_string(len));
        return;
      }
      std::uint16_t kind = std::uint16_t(bytes[pos + 2] | bytes[pos + 3] << 8);
      Symbol s{kind, bytes.subspan(pos + 4, len - 2), pos};
      try {
        f(s);
      } catch (const FormatError &e) {
        diag(diag_base + pos, "symbol " + hex(kind) + ": " + e.what());
        if (++errors == kMaxSymbolErrors) {
          diag(diag_base + pos, "too many bad symbols; skipping the rest of the stream");
          return;
        }
      }
      pos += 2 + std::size_t(len);
    }
  }

  void read_global_symbols() {
    std::uint16_t stream = dbi_header_.symbol_stream;
    if (stream == kNoStream || !msf_.has_stream(stream)) return;
    std::vector<std::uint8_t> bytes;
    try {
      bytes = msf_.read(stream);
    } catch (const FormatError &e) {
      diag(0, std::string("global symbols: ") + e.what());
      return;
    }
    const std::uint64_t base = std::uint64_t(0xffff) << 32;
    for_each_symbol(bytes, 0, bytes.size(), base, [&](const Symbol &s) {
      Cursor c(s.data, false);
      switch (s.kind) {
        case cv::S_PUB32: {
          PdbPublic p;
          std::uint32_t flags = c.u32();
          p.offset = c.u32();
          p.segment = c.u16();
          p.name = std::string(pdb::read_name(c));
          p.code = flags & cv::kPubCode;
          p.function = flags & cv::kPubFunction;
          if (auto r = rva(p.segment, p.offset)) p.address = opt_.image_base + *r;
          p.demangled = demangle::demangle_or_self(p.name);
          out_.publics.push_back(std::move(p));
          break;
        }
        case cv::S_GDATA32:
        case cv::S_LDATA32: data_symbol(s, c, base, false); break;
        case cv::S_UDT: udt(c); break;
        default: break;
      }
    });
  }

  void data_symbol(const Symbol &s, Cursor &c, std::uint64_t base, bool in_function) {
    std::uint32_t ti = c.u32();
    std::uint32_t off = c.u32();
    std::uint16_t seg = c.u16();
    std::string name(pdb::read_name(c));
    auto r = rva(seg, off);
    if (!r) return;
    Variable v;
    v.qualified_name = name;
    v.name = unqualified(name);
    v.address = opt_.image_base + *r;
    if (!seen_vars_.insert({v.address, name}).second) return;
    v.type = types_->type(ti);
    v.external = s.kind == cv::S_GDATA32;
    v.function_local = in_function;
    v.die_offset = base + s.offset;
    vars_.push_back(std::move(v));
  }

  void udt(Cursor &c) {
    std::uint32_t ti = c.u32();
    std::string name(pdb::read_name(c));
    if (name.empty() || !seen_udts_.insert({name, ti}).second) return;
    udts_.push_back({std::move(name), ti});
  }

  struct Scope {
    enum Kind : std::uint8_t { Proc, Inline, Other } kind;
    std::size_t function;  // index into funcs_ for Proc
  };

  struct Pending {
    Function fn;
    std::optional<types::FunctionType> type;
    std::vector<std::string> param_names;  // S_LOCAL parameters
    std::vector<TypeId> param_types;       // and their types
    std::vector<std::string> frame_names;  // S_REGREL32 etc. directly in the procedure
    bool saw_local_param = false;
  };

  void read_module(std::size_t index) {
    PdbModule &m = out_.modules[index];
    if (m.stream == kNoStream || !msf_.has_stream(m.stream)) return;
    if (!read_streams_.insert(m.stream).second) {
      diag(std::uint64_t(index) << 32, "module " + std::to_string(index) + " shares stream " +
                                           std::to_string(m.stream) + " with another module");
      return;
    }
    std::vector<std::uint8_t> bytes;
    try {
      bytes = msf_.read(m.stream);
    } catch (const FormatError &e) {
      diag(std::uint64_t(index) << 32, "module " + m.name + ": " + e.what());
      return;
    }
    const std::uint64_t base = std::uint64_t(index) << 32;
    if (m.symbol_bytes < 4 || bytes.size() < 4) return;
    std::uint32_t sig = std::uint32_t(bytes[0] | bytes[1] << 8 | bytes[2] << 16 | std::uint32_t(bytes[3]) << 24);
    if (sig != cv::kSymbolSignatureC13) {
      diag(base, "module " + m.name + " has symbol signature " + std::to_string(sig) + ", not C13");
      return;
    }

    CompileUnit unit;
    unit.offset = index;
    unit.name = m.name;
    std::vector<Scope> scopes;
    LocalVariable *last_local = nullptr;

    auto current_proc = [&]() -> Pending * {
      for (auto it = scopes.rbegin(); it != scopes.rend(); ++it) {
        if (it->kind == Scope::Inline) return nullptr;  // an inlinee's variables
        if (it->kind == Scope::Proc) return &funcs_[it->function];
      }
      return nullptr;
    };
    auto push = [&](Scope s) {
      if (scopes.size() >= kMaxScopeDepth) throw FormatError("symbol scopes nest too deeply");
      scopes.push_back(s);
    };

    for_each_symbol(bytes, 4, m.symbol_bytes, base, [&](const Symbol &s) {
      Cursor c(s.data, false);
      // S_DEFRANGE_* records describe the S_LOCAL just before them.
      LocalVariable *const prev = last_local;
      last_local = nullptr;
      switch (s.kind) {
        case cv::S_COMPILE3:
        case cv::S_COMPILE2: {
          std::uint32_t flags = c.u32();
          c.u16();  // machine
          c.skip(s.kind == cv::S_COMPILE3 ? 16 : 12);  // front- and back-end versions
          m.language = std::uint8_t(flags & 0xff);
          m.compiler = std::string(pdb::read_name(c));
          unit.language = *m.language;
          unit.producer = m.compiler;
          break;
        }
        case cv::S_GPROC32:
        case cv::S_LPROC32:
        case cv::S_GPROC32_ID:
        case cv::S_LPROC32_ID:
        case cv::S_LPROC32_DPC:
        case cv::S_LPROC32_DPC_ID: {
          procedure(s, c, base);
          push({Scope::Proc, funcs_.size() - 1});
          break;
        }
        case cv::S_THUNK32: {
          c.u32();
          c.u32();
          c.u32();
          std::uint32_t off = c.u32();
          std::uint16_t seg = c.u16();
          std::uint16_t len = c.u16();
          c.u8();
          std::string name(pdb::read_name(c));
          push({Scope::Other, 0});
          auto r = rva(seg, off);
          if (!r) break;
          Pending p;
          p.fn.qualified_name = name;
          p.fn.name = unqualified(name);
          p.fn.entry = opt_.image_base + *r;
          p.fn.ranges = {{p.fn.entry, p.fn.entry + std::max<std::uint16_t>(len, 1)}};
          p.fn.die_offset = base + s.offset;
          funcs_.push_back(std::move(p));
          break;
        }
        case cv::S_BLOCK32:
        case cv::S_WITH32: push({Scope::Other, 0}); break;
        case cv::S_SEPCODE: {
          c.u32();
          c.u32();
          std::uint32_t len = c.u32();
          c.u32();  // flags
          std::uint32_t off = c.u32();
          c.u32();  // parent offset
          std::uint16_t seg = c.u16();
          push({Scope::Other, 0});
          if (Pending *p = current_proc(); p && len)
            if (auto r = rva(seg, off)) p->fn.ranges.push_back({opt_.image_base + *r, opt_.image_base + *r + len});
          break;
        }
        case cv::S_INLINESITE:
        case cv::S_INLINESITE2: push({Scope::Inline, 0}); break;
        case cv::S_END:
        case cv::S_PROC_ID_END:
        case cv::S_INLINESITE_END:
          if (scopes.empty()) throw FormatError("scope end without a scope");
          scopes.pop_back();
          break;
        case cv::S_LOCAL: {
          Pending *p = current_proc();
          if (!p) break;
          LocalVariable v;
          std::uint32_t ti = c.u32();
          std::uint16_t flags = c.u16();
          v.name = std::string(pdb::read_name(c));
          v.type = types_->type(ti);
          v.is_param = flags & cv::kLocalIsParam;
          if (v.is_param) {
            p->saw_local_param = true;
            p->param_names.push_back(v.name);
            p->param_types.push_back(v.type);
          }
          p->fn.locals.push_back(std::move(v));
          last_local = &p->fn.locals.back();
          break;
        }
        case cv::S_DEFRANGE_FRAMEPOINTER_REL:
        case cv::S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE:
          last_local = prev;
          if (prev && prev->location == LocalVariable::Location::Unknown) {
            prev->location = LocalVariable::Location::FrameRelative;
            prev->offset = std::int32_t(c.u32());
          }
          break;
        case cv::S_DEFRANGE_REGISTER:
        case cv::S_DEFRANGE_SUBFIELD_REGISTER:
          last_local = prev;
          if (prev && prev->location == LocalVariable::Location::Unknown) {
            prev->location = LocalVariable::Location::Register;
            prev->reg = c.u16();
          }
          break;
        case cv::S_DEFRANGE_REGISTER_REL:
          last_local = prev;
          if (prev && prev->location == LocalVariable::Location::Unknown) {
            prev->location = LocalVariable::Location::RegisterRelative;
            prev->reg = c.u16();
            c.u16();
            prev->offset = std::int32_t(c.u32());
          }
          break;
        case cv::S_REGREL32:
        case cv::S_BPREL32:
        case cv::S_REGISTER: {
          Pending *p = current_proc();
          if (!p) break;
          LocalVariable v;
          if (s.kind == cv::S_REGREL32) {
            v.location = LocalVariable::Location::RegisterRelative;
            v.offset = std::int32_t(c.u32());
            v.type = types_->type(c.u32());
            v.reg = c.u16();
          } else if (s.kind == cv::S_BPREL32) {
            v.location = LocalVariable::Location::FrameRelative;
            v.offset = std::int32_t(c.u32());
            v.type = types_->type(c.u32());
          } else {
            v.location = LocalVariable::Location::Register;
            v.type = types_->type(c.u32());
            v.reg = c.u16();
          }
          v.name = std::string(pdb::read_name(c));
          // Without S_LOCAL's flag, a procedure's parameters are its first
          // frame symbols (MSVC writes them first, in order).
          if (scopes.back().kind == Scope::Proc) p->frame_names.push_back(v.name);
          p->fn.locals.push_back(std::move(v));
          break;
        }
        case cv::S_GDATA32:
        case cv::S_LDATA32: data_symbol(s, c, base, current_proc() != nullptr); break;
        case cv::S_UDT: udt(c); break;
        default: break;
      }
    });
    if (!unit.producer.empty() || unit.language) out_.units.push_back(std::move(unit));
  }

  void procedure(const Symbol &s, Cursor &c, std::uint64_t base) {
    c.u32();  // parent
    c.u32();  // end
    c.u32();  // next
    std::uint32_t len = c.u32();
    c.u32();  // debug start
    c.u32();  // debug end
    std::uint32_t ti = c.u32();
    std::uint32_t off = c.u32();
    std::uint16_t seg = c.u16();
    std::uint8_t flags = c.u8();
    std::string name(pdb::read_name(c));

    Pending p;
    p.fn.qualified_name = name;
    p.fn.name = unqualified(name);
    p.fn.external = s.kind == cv::S_GPROC32 || s.kind == cv::S_GPROC32_ID;
    p.fn.noreturn = flags & cv::kProcNoReturn;
    p.fn.die_offset = base + s.offset;
    const bool id = s.kind == cv::S_GPROC32_ID || s.kind == cv::S_LPROC32_ID ||
                    s.kind == cv::S_LPROC32_DPC_ID;
    if (id) ti = function_id_type(ti);
    try {
      p.type = types_->function(ti);
    } catch (const FormatError &e) {
      diag(base + s.offset, "procedure " + name + ": " + e.what());
    }
    if (auto r = rva(seg, off)) {
      p.fn.entry = opt_.image_base + *r;
      p.fn.ranges = {{p.fn.entry, p.fn.entry + std::max<std::uint32_t>(len, 1)}};
    } else {
      diag(base + s.offset, "procedure " + name + " at " + std::to_string(seg) + ":" + hex(off) +
                                " is outside the image");
      p.fn.ranges.clear();
    }
    funcs_.push_back(std::move(p));
  }

  // --- results ------------------------------------------------------------

  // Positions of `part` in `whole` as a subsequence, if there is exactly
  // one way to place it.
  static std::optional<std::vector<std::size_t>> unique_embedding(const std::vector<TypeId> &part,
                                                                  const std::vector<TypeId> &whole) {
    const std::size_t m = part.size(), n = whole.size();
    if (m == 0 || m > n || n > 256) return std::nullopt;
    // ways[i][j]: placements of part[i..] in whole[j..], capped at 2.
    std::vector<std::vector<std::uint8_t>> ways(m + 1, std::vector<std::uint8_t>(n + 1, 0));
    for (std::size_t j = 0; j <= n; ++j) ways[m][j] = 1;
    for (std::size_t i = m; i-- > 0;)
      for (std::size_t j = n; j-- > 0;)
        ways[i][j] = std::uint8_t(std::min(2, ways[i][j + 1] + (part[i] == whole[j] ? ways[i + 1][j + 1] : 0)));
    if (ways[0][0] != 1) return std::nullopt;
    std::vector<std::size_t> at;
    for (std::size_t i = 0, j = 0; i < m; ++j)
      if (part[i] == whole[j] && ways[i + 1][j + 1] == 1 && ways[i][j + 1] == 0) {
        at.push_back(j);
        ++i;
      }
    return at;
  }

  void finish() {
    // Prototypes: the procedure's type with its own parameter names.
    for (Pending &p : funcs_) {
      if (!p.type) continue;
      types::FunctionType ft = std::move(*p.type);
      const std::vector<std::string> &names =
          p.saw_local_param ? p.param_names : p.frame_names;
      if (names.size() == ft.params.size() || (!p.saw_local_param && names.size() > ft.params.size())) {
        for (std::size_t i = 0; i < ft.params.size(); ++i) ft.params[i].name = names[i];
      } else if (p.saw_local_param && names.size() < ft.params.size()) {
        // Clang leaves out unused parameters. Name the others if their
        // types place them in the argument list in exactly one way.
        std::vector<TypeId> want;
        for (const auto &prm : ft.params) want.push_back(prm.type);
        if (auto at = unique_embedding(p.param_types, want))
          for (std::size_t i = 0; i < at->size(); ++i) ft.params[(*at)[i]].name = names[i];
      }
      for (const auto &prm : ft.params) p.fn.param_names.push_back(prm.name);
      p.fn.prototype = types_->add(std::move(ft));
    }
    // An S_UDT names a type: the tag of a struct, union or enum (C++ and
    // clang's C give `typedef struct {...} point;` the tag "point"), or
    // else a typedef, which CodeView has no type record for.
    // Where each struct, union and enum was declared (the IPI's
    // LF_UDT_SRC_LINE and LF_UDT_MOD_SRC_LINE records).
    std::vector<std::pair<TypeId, std::string>> files;
    std::unordered_map<std::uint32_t, std::string> file_of_ti;
    for (std::uint32_t id = ipi_.begin(); id < ipi_.end(); ++id) {
      pdb::TypeRecord r = ipi_.record(id);
      if (r.kind != cv::LF_UDT_SRC_LINE && r.kind != cv::LF_UDT_MOD_SRC_LINE) continue;
      try {
        Cursor c(r.data, false);
        const std::uint32_t udt = c.u32(), src = c.u32();
        std::string file;
        if (r.kind == cv::LF_UDT_SRC_LINE) {
          pdb::TypeRecord str = ipi_.record(src);
          if (str.kind != cv::LF_STRING_ID) continue;
          Cursor sc(str.data, false);
          sc.u32();  // substring list
          file = std::string(sc.cstr());
        } else {
          file = names_string(src);
        }
        if (!file.empty() && tpi_.contains(udt)) file_of_ti.emplace(udt, std::move(file));
      } catch (const FormatError &) {
      }
    }
    for (const auto &[ti, file] : file_of_ti) files.emplace_back(types_->type(ti), file);
    std::vector<std::pair<std::string, TypeId>> names;
    for (auto &[name, ti] : udts_) {
      TypeId t = types_->type(ti);
      if (types_->tag(ti) != name) {
        t = types_->add(types::TypedefType{name, t});
        // A typedef CodeView has no record for: its type's file.
        if (auto f = file_of_ti.find(ti); f != file_of_ti.end()) files.emplace_back(t, f->second);
      }
      names.push_back({name, t});
    }
    std::vector<TypeId> ids = types_->finish();
    auto map = [&](TypeId t) { return t.is_local() ? ids[t.index()] : t; };
    for (auto &[name, t] : names) out_.type_names.push_back({name, map(t)});
    for (const auto &[t, file] : files) out_.type_files.emplace(map(t), file);

    std::unordered_map<std::uint64_t, const PdbPublic *> public_at;
    for (const PdbPublic &p : out_.publics)
      if (p.address && (p.function || p.code)) public_at.emplace(p.address, &p);
    for (Pending &p : funcs_) {
      if (p.fn.ranges.empty()) continue;
      p.fn.prototype = p.fn.prototype.valid() ? map(p.fn.prototype) : p.fn.prototype;
      for (LocalVariable &v : p.fn.locals) v.type = map(v.type);
      if (auto it = public_at.find(p.fn.entry);
          it != public_at.end() && it->second->name != p.fn.qualified_name)
        p.fn.linkage_name = it->second->name;
      std::sort(p.fn.ranges.begin(), p.fn.ranges.end());
      out_.functions.push_back(std::move(p.fn));
    }
    for (Variable &v : vars_) {
      v.type = map(v.type);
      if (auto it = public_at.find(v.address); it != public_at.end() && it->second->name != v.qualified_name)
        v.linkage_name = it->second->name;
      out_.variables.push_back(std::move(v));
    }
    out_.types = ids;
    for (const PdbTypeName &n : out_.type_names) out_.types.push_back(n.type);
    std::sort(out_.types.begin(), out_.types.end());
    out_.types.erase(std::unique(out_.types.begin(), out_.types.end()), out_.types.end());
    std::sort(out_.functions.begin(), out_.functions.end(), [](const Function &a, const Function &b) {
      return std::tie(a.entry, a.die_offset) < std::tie(b.entry, b.die_offset);
    });
    std::sort(out_.variables.begin(), out_.variables.end(), [](const Variable &a, const Variable &b) {
      return std::tie(a.address, a.die_offset) < std::tie(b.address, b.die_offset);
    });
    std::sort(out_.publics.begin(), out_.publics.end(), [](const PdbPublic &a, const PdbPublic &b) {
      return std::tie(a.address, a.name) < std::tie(b.address, b.name);
    });
  }

  struct SectionMapEntry {
    std::uint16_t flags = 0;
    std::uint16_t frame = 0;
    std::uint32_t offset = 0;
  };

  Msf msf_;
  types::TypeStore &store_;
  const PdbOptions &opt_;
  PdbDebugInfo &out_;
  std::vector<std::uint8_t> dbi_;
  DbiHeader dbi_header_;
  bool have_dbi_ = false;
  unsigned pointer_size_ = 8;
  pdb::TypeStream tpi_, ipi_;
  std::vector<std::uint8_t> names_;  // "/names": the string table
  bool names_loaded_ = false;
  std::optional<pdb::TypeImporter> types_;
  std::vector<SectionMapEntry> section_map_;
  std::vector<PdbSectionHeader> original_sections_;
  std::vector<std::pair<std::uint32_t, std::uint32_t>> omap_;
  std::vector<Pending> funcs_;
  std::vector<Variable> vars_;
  std::set<std::pair<std::uint64_t, std::string>> seen_vars_;
  std::vector<std::pair<std::string, std::uint32_t>> udts_;
  std::set<std::pair<std::string, std::uint32_t>> seen_udts_;
  std::unordered_set<std::uint16_t> read_streams_;
};

}  // namespace

std::string guid_string(const PdbGuid &g) {
  char buf[40];
  std::snprintf(buf, sizeof buf, "{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6], g[8], g[9], g[10], g[11], g[12], g[13],
                g[14], g[15]);
  return buf;
}

PdbIdentity read_pdb_identity(std::span<const std::uint8_t> file) {
  types::TypeStore store;
  PdbDebugInfo out;
  PdbOptions opt;
  Reader r(file, store, opt, out);
  r.identify();
  return out.identity;
}

PdbDebugInfo read_pdb(std::span<const std::uint8_t> file, types::TypeStore &store,
                      const PdbOptions &options) {
  PdbDebugInfo out;
  Reader(file, store, options, out).run();
  return out;
}

}  // namespace revkit::debuginfo
