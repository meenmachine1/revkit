// Export: patches to file offsets, fixups, file names, verification.

#include "revkit/patch/export.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace revkit::patch {

namespace {

std::string hexs(std::uint64_t v) {
  char buf[32];
  std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
  return buf;
}

}  // namespace

MapResult map_to_file(const loader::Image &image, const std::vector<Patch> &patches) {
  MapResult out;
  for (const Patch &p : patches) {
    std::uint64_t done = 0;
    while (done < p.bytes.size()) {
      const std::uint64_t a = p.address + done;
      const loader::Region *r = image.memory.find(a);
      if (r == nullptr || a - r->start >= r->file_size) {
        out.error = "the patch at " + hexs(p.address) + " covers " + hexs(a) +
                    ", which the file doesn't back (unmapped, uninitialized or synthesized memory); revert it to export";
        out.mapped.clear();
        return out;
      }
      const std::uint64_t in_region = r->file_size - (a - r->start);
      const std::uint64_t n = std::min<std::uint64_t>(in_region, p.bytes.size() - done);
      out.mapped.push_back({r->file_offset + (a - r->start), p.bytes.substr(done, n), a});
      done += n;
    }
  }
  return out;
}

std::string render_name(const std::string &tpl, const std::string &original, std::optional<std::uint64_t> sum,
                        unsigned sum_bits) {
  if (tpl.empty()) return original;
  std::string stem = original, ext;
  if (auto slash = stem.find_last_of("/\\"); slash != std::string::npos) stem.erase(0, slash + 1);
  if (auto dot = stem.rfind('.'); dot != std::string::npos && dot > 0) {
    ext = stem.substr(dot);
    stem.erase(dot);
  }
  std::string out;
  for (std::size_t i = 0; i < tpl.size();) {
    if (tpl[i] != '{') {
      out += tpl[i++];
      continue;
    }
    const std::size_t close = tpl.find('}', i);
    if (close == std::string::npos) {
      out += tpl.substr(i);
      break;
    }
    const std::string field = tpl.substr(i + 1, close - i - 1);
    i = close + 1;
    if (field == "NAME") {
      out += stem;
    } else if (field == "EXT") {
      out += ext;
    } else if (field.rfind("SUM", 0) == 0) {
      if (!sum) {
        out += "{" + field + "}";
        continue;
      }
      // {SUM}, {SUM:08X}, {SUM:x}: printf-like width and case.
      std::string fmt = field.size() > 4 && field[3] == ':' ? field.substr(4) : "X";
      const bool lower = !fmt.empty() && fmt.back() == 'x';
      int width = 0;
      for (char c : fmt)
        if (std::isdigit(static_cast<unsigned char>(c))) width = width * 10 + (c - '0');
      const std::uint64_t mask = sum_bits >= 64 ? ~std::uint64_t{0} : (std::uint64_t{1} << sum_bits) - 1;
      char buf[40];
      std::snprintf(buf, sizeof buf, lower ? "%0*llx" : "%0*llX", width, static_cast<unsigned long long>(*sum & mask));
      out += buf;
    } else {
      out += "{" + field + "}";
    }
  }
  return out;
}

std::string template_for(const std::string &file_name, std::uint64_t value) {
  for (const unsigned digits : {8u, 4u}) {
    char upper[32], lower[32];
    std::snprintf(upper, sizeof upper, "%0*llX", digits, static_cast<unsigned long long>(value));
    std::snprintf(lower, sizeof lower, "%0*llx", digits, static_cast<unsigned long long>(value));
    for (const char *spelled : {upper, lower}) {
      const auto at = file_name.rfind(spelled);
      if (at == std::string::npos) continue;
      const bool is_lower = spelled == lower && std::string(upper) != lower;
      return file_name.substr(0, at) + "{SUM:0" + std::to_string(digits) + (is_lower ? "x" : "X") + "}" +
             file_name.substr(at + digits);
    }
  }
  return file_name;
}

ExportResult build_export(std::span<const std::uint8_t> file, const std::vector<FilePatch> &patches,
                          const ExportOptions &o) {
  ExportResult out;
  std::uint64_t base = 0, end = file.size();
  if (o.image_only) {
    base = o.image_offset;
    end = o.image_length ? std::min<std::uint64_t>(file.size(), base + o.image_length) : file.size();
    if (base > end) {
      out.error = "the image's slice is outside the file";
      return out;
    }
  }
  out.data.assign(file.begin() + static_cast<std::ptrdiff_t>(base), file.begin() + static_cast<std::ptrdiff_t>(end));
  for (const FilePatch &p : patches) {
    if (p.file_offset < base || p.file_offset + p.bytes.size() > end) {
      out.error = "the patch at " + hexs(p.address) + " is outside the exported bytes";
      return out;
    }
    std::copy(p.bytes.begin(), p.bytes.end(), out.data.begin() + static_cast<std::ptrdiff_t>(p.file_offset - base));
    out.changes.push_back({p.file_offset - base, static_cast<std::uint32_t>(p.bytes.size()), p.address, "patch"});
  }
  std::optional<std::uint64_t> name_sum;
  unsigned name_bits = 32;
  // Field checksums in order, then the PE CheckSum (it covers them), then
  // the name (over the final bytes).
  std::vector<const Fixup *> order;
  for (const Fixup &f : o.fixups)
    if (f.kind == Fixup::Kind::checksum && f.spec.field) order.push_back(&f);
  for (const Fixup &f : o.fixups)
    if (f.kind == Fixup::Kind::pe_checksum) order.push_back(&f);
  for (const Fixup &f : o.fixups)
    if (f.kind == Fixup::Kind::checksum && !f.spec.field) order.push_back(&f);
  for (const Fixup *f : order) {
    if (f->kind == Fixup::Kind::pe_checksum) {
      auto at = pe_checksum_offset(out.data);
      auto v = pe_checksum(out.data);
      if (!at || !v) {
        out.error = "PE CheckSum: the output is not a PE file";
        return out;
      }
      Spec s;
      s.field = true;
      s.field_offset = *at;
      s.field_width = 4;
      write_field(s, *v, out.data);
      out.changes.push_back({*at, 4, std::nullopt, "PE CheckSum"});
      out.fixed.emplace_back(*at, *at + 4);
      out.fixups.push_back("PE CheckSum = " + hexs(*v) + " at " + hexs(*at));
      continue;
    }
    const Spec &s = f->spec;
    auto v = evaluate(s, out.data);
    if (!v) {
      out.error = "checksum " + describe(s) + ": the range is outside the output";
      return out;
    }
    if (s.field) {
      if (!write_field(s, *v, out.data)) {
        out.error = "checksum " + describe(s) + ": the field is outside the output";
        return out;
      }
      out.changes.push_back({s.field_offset, s.field_width, std::nullopt, "checksum " + std::string(name(s.algorithm))});
      out.fixed.emplace_back(s.field_offset, s.field_offset + s.field_width);
      out.fixups.push_back(describe(s) + " = " + hexs(*v));
    } else {
      name_sum = v;
      name_bits = width_bits(s.algorithm);
      out.fixups.push_back(describe(s) + " = " + hexs(*v) + " (file name)");
    }
  }
  out.file_name = render_name(o.name_template, o.original_name, name_sum, name_bits);
  return out;
}

Verification verify_export(const loader::Image &original, const std::vector<Patch> &patches,
                           const loader::Image &reloaded,
                           const std::vector<std::pair<std::uint64_t, std::uint64_t>> &fixed, std::uint64_t file_delta) {
  Verification v;
  v.ok = true;
  auto excluded = [&](std::uint64_t file_offset) {
    if (file_offset < file_delta) return false;
    const std::uint64_t at = file_offset - file_delta;
    for (const auto &[a, b] : fixed)
      if (at >= a && at < b) return true;
    return false;
  };
  for (const loader::Region &r : original.memory.regions()) {
    if (r.file_size == 0) continue;
    std::vector<std::byte> want(static_cast<std::size_t>(r.file_size)), got(static_cast<std::size_t>(r.file_size));
    original.memory.read(r.start, want);
    for (const Patch &p : patches)
      for (std::size_t i = 0; i < p.bytes.size(); ++i) {
        const std::uint64_t a = p.address + i;
        if (a >= r.start && a - r.start < r.file_size) want[a - r.start] = static_cast<std::byte>(p.bytes[i]);
      }
    const std::size_t n = reloaded.memory.read(r.start, got);
    for (std::size_t i = 0; i < want.size(); ++i) {
      if (excluded(r.file_offset + i)) continue;
      ++v.compared;
      if (i >= n || got[i] != want[i]) {
        ++v.mismatches;
        if (!v.first_mismatch) v.first_mismatch = r.start + i;
      }
    }
  }
  v.ok = v.mismatches == 0;
  v.detail = v.ok ? "the output loads to the patched bytes (" + std::to_string(v.compared) + " bytes compared)"
                  : std::to_string(v.mismatches) + " of " + std::to_string(v.compared) +
                        " bytes differ from the patched program, the first at " + hexs(*v.first_mismatch);
  return v;
}

}  // namespace revkit::patch
