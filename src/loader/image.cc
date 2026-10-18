#include "revkit/loader/image.hh"
#include "revkit/loader/load.hh"

#include "reader.hh"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iterator>
#include <mutex>

namespace revkit::loader {

namespace detail {

std::string hex(std::uint64_t v) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string s;
  do {
    s.insert(s.begin(), digits[v & 0xf]);
    v >>= 4;
  } while (v != 0);
  return "0x" + s;
}

void fail(std::string_view what) { throw LoadError(std::string(what)); }

}  // namespace detail

std::string Perms::str() const {
  return {read ? 'r' : '-', write ? 'w' : '-', exec ? 'x' : '-'};
}

void Memory::add(const Region &r) { add(r, nullptr); }

void Memory::set_perms(std::uint64_t start, Perms perms) {
  auto it = std::lower_bound(regions_.begin(), regions_.end(), start,
                             [](const Region &a, std::uint64_t s) { return a.start < s; });
  if (it != regions_.end() && it->start == start) it->perms = perms;
}

void Memory::set_perms(std::uint64_t start, std::uint64_t size, Perms perms) {
  if (size == 0) return;
  const std::uint64_t last = size - 1 > UINT64_MAX - start ? UINT64_MAX : start + (size - 1);
  // The piece of `r` from `at` on, `n` bytes long.
  auto piece = [](const Region &r, std::uint64_t at, std::uint64_t n) {
    Region p = r;
    const std::uint64_t off = at - r.start;
    p.start = at;
    p.size = n;
    p.file_offset = r.file_offset + off;
    p.file_size = r.file_size > off ? std::min(r.file_size - off, n) : 0;
    if (p.file_size == 0) p.file_offset = r.file_offset;
    return p;
  };
  std::vector<Region> regions;
  std::vector<std::shared_ptr<const Bytes>> own;
  regions.reserve(regions_.size() + 2);
  for (std::size_t i = 0; i < regions_.size(); ++i) {
    const Region &r = regions_[i];
    auto keep = [&](const Region &p) {
      regions.push_back(p);
      if (!own_.empty()) own.push_back(own_[i]);
    };
    if (r.last() < start || r.start > last || r.perms == perms) {
      keep(r);
      continue;
    }
    const std::uint64_t first = std::max(r.start, start), end = std::min(r.last(), last);
    if (first > r.start) keep(piece(r, r.start, first - r.start));
    Region mid = piece(r, first, end - first + 1);
    mid.perms = perms;
    keep(mid);
    if (end < r.last()) keep(piece(r, end + 1, r.last() - end));
  }
  regions_ = std::move(regions);
  if (!own_.empty()) own_ = std::move(own);
}

void Memory::add(const Region &r, std::shared_ptr<const Bytes> bytes) {
  using detail::hex;
  if (r.size == 0) detail::fail("memory region at " + hex(r.start) + " is empty");
  if (r.size - 1 > UINT64_MAX - r.start)
    detail::fail("memory region at " + hex(r.start) + " wraps the address space");
  if (r.file_size > r.size) detail::fail("memory region at " + hex(r.start) + " has more file bytes than memory");
  if (r.file_size != 0) {
    const Bytes *from = bytes ? bytes.get() : file_.get();
    std::uint64_t fsize = from ? from->size() : 0;
    if (r.file_offset > fsize || r.file_size > fsize - r.file_offset)
      detail::fail("memory region at " + hex(r.start) + " extends past end of file");
  }

  auto it = std::lower_bound(regions_.begin(), regions_.end(), r.start,
                             [](const Region &a, std::uint64_t s) { return a.start < s; });
  // Both ranges, inclusive: "memory region 0x0–0xffff overlaps region
  // 0x0–0x1a49" (loaders that know the regions' names say them first).
  auto range = [](const Region &x) { return hex(x.start) + "–" + hex(x.last()); };
  if (it != regions_.end() && it->start <= r.last())
    detail::fail("memory region " + range(r) + " overlaps region " + range(*it));
  if (it != regions_.begin() && std::prev(it)->last() >= r.start)
    detail::fail("memory region " + range(r) + " overlaps region " + range(*std::prev(it)));
  if (bytes && own_.empty()) own_.resize(regions_.size());
  if (!own_.empty()) own_.insert(own_.begin() + (it - regions_.begin()), std::move(bytes));
  regions_.insert(it, r);
}

const Region *Memory::find(std::uint64_t addr) const {
  auto it = std::upper_bound(regions_.begin(), regions_.end(), addr,
                             [](std::uint64_t a, const Region &r) { return a < r.start; });
  if (it == regions_.begin()) return nullptr;
  --it;
  return it->contains(addr) ? &*it : nullptr;
}

std::size_t Memory::read(std::uint64_t addr, std::span<std::byte> out) const {
  std::size_t mapped = 0;
  std::size_t i = 0;
  while (i < out.size()) {
    std::uint64_t a = addr + i;  // wraps at 2^64 like the address space
    const Region *r = find(a);
    if (r == nullptr) {
      out[i++] = std::byte{0};
      continue;
    }
    // Copy as much of this region as the request covers.
    std::uint64_t off = a - r->start;
    std::uint64_t n = std::min<std::uint64_t>(out.size() - i, r->size - off);
    const Bytes *from = file_.get();
    if (!own_.empty())
      if (const auto &own = own_[static_cast<std::size_t>(r - regions_.data())]) from = own.get();
    for (std::uint64_t k = 0; k < n; ++k) {
      std::uint64_t o = off + k;
      out[i + k] = o < r->file_size ? (*from)[static_cast<std::size_t>(r->file_offset + o)] : std::byte{0};
    }
    i += static_cast<std::size_t>(n);
    mapped += static_cast<std::size_t>(n);
  }
  return mapped;
}

const AddressSpace *find_space(const Image &image, std::string_view name) {
  for (const AddressSpace &s : image.spaces)
    if (s.name == name) return &s;
  return nullptr;
}

const AddressSpace &add_space(Image &image, std::string_view name, bool alias_of_default,
                              std::optional<std::uint64_t> base) {
  if (name.empty()) detail::fail("a memory space needs a name");
  if (const AddressSpace *s = find_space(image, name)) return *s;
  if (image.bits > 32 && !alias_of_default)
    detail::fail("memory space " + std::string(name) + ": a " + std::to_string(image.bits) +
                 "-bit image has a single address space");
  constexpr std::uint64_t kLow = (std::uint64_t{1} << kSpaceKeyShift) - 1;
  std::uint64_t b = 0;
  if (!alias_of_default) {
    if (base) {
      if ((*base & kLow) != 0 || *base == 0) detail::fail("memory space " + std::string(name) + ": bad base");
      b = *base;
    } else {
      for (const AddressSpace &s : image.spaces) b = std::max(b, s.base);
      if (b >= ~kLow) detail::fail("too many memory spaces");
      b += std::uint64_t{1} << kSpaceKeyShift;
    }
    for (const AddressSpace &s : image.spaces)
      if (!s.alias_of_default && s.base == b) detail::fail("memory space " + std::string(name) + ": base in use");
  }
  image.spaces.push_back({std::string(name), b, alias_of_default});
  return image.spaces.back();
}

namespace {
std::mutex g_provider_mu;
LanguageMemoryProvider g_provider;
}  // namespace

void set_language_memory_provider(LanguageMemoryProvider provider) {
  std::lock_guard lock(g_provider_mu);
  g_provider = std::move(provider);
}

std::optional<LanguageMemory> language_memory(std::string_view language) {
  LanguageMemoryProvider p;
  {
    std::lock_guard lock(g_provider_mu);
    p = g_provider;
  }
  if (!p || language.empty()) return std::nullopt;
  return p(language);
}

void apply_language_memory(Image &image, const LanguageMemory &memory, bool blocks) {
  if (image.bits > 32 || memory.spaces.empty()) return;
  image.default_space = memory.code;
  for (const AddressSpace &s : memory.spaces) {
    add_space(image, s.name, s.alias_of_default, s.alias_of_default ? std::nullopt : std::optional(s.base));
    for (AddressSpace &a : image.spaces)
      if (a.name == s.name) {
        a.wordsize = s.wordsize;
        a.digits = s.digits;
      }
  }
  if (!blocks) return;
  for (const DefaultBlock &d : memory.blocks) {
    if (d.size == 0) continue;
    const std::optional<std::uint64_t> key = space_key(image, d.space, d.start);
    if (!key || d.size - 1 > ~std::uint64_t{0} - *key) continue;
    const std::uint64_t last = *key + (d.size - 1);
    if (!d.space.empty() && (last >> kSpaceKeyShift) != (*key >> kSpaceKeyShift)) continue;
    // Not over anything the file put there.
    bool clash = false;
    for (const Region &r : image.memory.regions()) clash = clash || (r.start <= last && *key <= r.last());
    if (clash) continue;
    image.memory.add({*key, d.size, 0, 0, d.perms});
    Block b{d.name, *key, d.size, d.perms, d.initialized, d.is_volatile};
    image.blocks.insert(std::upper_bound(image.blocks.begin(), image.blocks.end(), b,
                                         [](const Block &x, const Block &y) { return x.start < y.start; }),
                        std::move(b));
  }
  for (const DefaultLabel &l : memory.labels) {
    const std::optional<std::uint64_t> key = space_key(image, l.space, l.offset);
    if (!key || !image.memory.is_mapped(*key)) continue;
    Symbol sym;
    sym.name = l.name;
    sym.value = *key;
    sym.type = SymbolType::object;
    sym.bind = SymbolBind::weak;
    sym.defined = true;
    image.symbols.push_back(std::move(sym));
  }
}

std::optional<std::uint64_t> space_key(const Image &image, std::string_view name, std::uint64_t offset) {
  if (name.empty()) return offset;
  const AddressSpace *s = find_space(image, name);
  if (s == nullptr) return std::nullopt;
  if (s->alias_of_default) return offset;
  if (offset >= (std::uint64_t{1} << kSpaceKeyShift)) return std::nullopt;
  return s->base + offset;
}

SpaceOffset split_key(const Image &image, std::uint64_t key) {
  const std::uint64_t base = key & ~((std::uint64_t{1} << kSpaceKeyShift) - 1);
  if (base != 0 && image.bits <= 32)
    for (const AddressSpace &s : image.spaces)
      if (!s.alias_of_default && s.base == base) return {&s, key - base};
  return {nullptr, key};
}

std::string name_address(const Image &image, std::uint64_t key, std::string_view qualifier) {
  char buf[40];
  if (image.spaces.empty()) {
    std::snprintf(buf, sizeof buf, "%08llx", static_cast<unsigned long long>(key));
    return std::string(qualifier) + buf;
  }
  const SpaceOffset so = split_key(image, key);
  const AddressSpace &s = so.space != nullptr ? *so.space : image.default_space;
  const std::uint64_t units = s.wordsize > 1 ? so.offset / s.wordsize : so.offset;
  std::snprintf(buf, sizeof buf, "%0*llx", static_cast<int>(s.digits), static_cast<unsigned long long>(units));
  return (s.name.empty() ? std::string(qualifier) : s.name + "_") + buf;
}

Image parse(std::shared_ptr<const Bytes> file, const LoadOptions &options) {
  if (!file) detail::fail("no input");
  const Bytes &b = *file;
  if (b.size() >= 4 && b[0] == std::byte{0x7f} && b[1] == std::byte{'E'} && b[2] == std::byte{'L'} &&
      b[3] == std::byte{'F'})
    return parse_elf(std::move(file), options);
  if (b.size() >= 2 && b[0] == std::byte{'M'} && b[1] == std::byte{'Z'})
    return parse_pe(std::move(file), options);
  if (is_macho(b)) return parse_macho(std::move(file), options);
  detail::fail("unrecognised file format");
}

namespace {

std::shared_ptr<Bytes> read_file(const std::filesystem::path &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) throw LoadError("cannot open " + path.string());
  auto bytes = std::make_shared<Bytes>();
  in.seekg(0, std::ios::end);
  std::streamoff len = in.tellg();
  if (len < 0) throw LoadError("cannot size " + path.string());
  in.seekg(0, std::ios::beg);
  bytes->resize(static_cast<std::size_t>(len));
  if (len > 0 && !in.read(reinterpret_cast<char *>(bytes->data()), len))
    throw LoadError("cannot read " + path.string());
  return bytes;
}

}  // namespace

Image load_file(const std::filesystem::path &path, const LoadOptions &options) {
  return parse(read_file(path), options);
}

Image load_raw_file(const std::filesystem::path &path, const RawOptions &options) {
  return parse_raw(read_file(path), options);
}

}  // namespace revkit::loader
