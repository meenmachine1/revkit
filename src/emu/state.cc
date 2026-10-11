// Registers and memory: a flat register file, and the default space as the
// loaded image with written pages laid over it (copy on write).
#include "impl.hh"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace revkit::emu {

namespace detail {

const Page *PageStore::find(std::uint64_t index) const {
  if (index == last_index_ && last_ != nullptr) return last_;
  auto it = pages_.find(index);
  if (it == pages_.end()) return nullptr;
  last_index_ = index;
  last_ = it->second.get();
  return last_;
}

void PageStore::erase(std::uint64_t index) {
  pages_.erase(index);
  last_index_ = ~std::uint64_t{0};
  last_ = nullptr;
}

void PageStore::clear() {
  pages_.clear();
  last_index_ = ~std::uint64_t{0};
  last_ = nullptr;
}

}  // namespace detail

using detail::kPageSize;
using detail::Wide;

namespace {
std::string lower(std::string_view s) {
  std::string out(s);
  for (char &c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return out;
}
}  // namespace

std::optional<std::size_t> Emulator::Impl::find_reg(std::string_view name) const {
  auto it = register_by_name.find(lower(name));
  if (it == register_by_name.end()) return std::nullopt;
  return it->second;
}

const RegisterInfo &Emulator::Impl::reg(std::string_view name) const {
  auto i = find_reg(name);
  if (!i) throw EmuError("unknown register " + std::string(name));
  return registers[*i];
}

std::uint64_t Emulator::Impl::word(const std::uint8_t *bytes, std::uint32_t size) const {
  std::uint64_t v = 0;
  for (std::uint32_t i = 0; i < size && i < 8; ++i) {
    const std::uint32_t at = big_endian ? size - 1 - i : i;
    v |= std::uint64_t{bytes[at]} << (8 * i);
  }
  return v;
}

void Emulator::Impl::put_word(std::uint8_t *bytes, std::uint32_t size, std::uint64_t v) const {
  for (std::uint32_t i = 0; i < size; ++i) {
    const std::uint32_t at = big_endian ? size - 1 - i : i;
    bytes[at] = i < 8 ? static_cast<std::uint8_t>(v >> (8 * i)) : 0;
  }
}

Wide Emulator::Impl::get_reg(const RegisterInfo &r) const {
  std::uint8_t buf[detail::kMaxValueBytes] = {};
  const std::uint32_t n = std::min<std::uint32_t>(r.size, detail::kMaxValueBytes);
  for (std::uint32_t i = 0; i < n; ++i) {
    const std::uint64_t at = r.offset + i;
    buf[i] = at < regs.size() ? regs[at] : 0;
  }
  if (big_endian) std::reverse(buf, buf + n);
  return Wide::from_le(n, buf);
}

void Emulator::Impl::set_reg(const RegisterInfo &r, const Wide &v) {
  const std::uint32_t n = std::min<std::uint32_t>(r.size, detail::kMaxValueBytes);
  if (r.offset + n > regs.size()) {
    charge(r.offset + n - regs.size());
    regs.resize(r.offset + n, 0);
  }
  std::uint8_t buf[detail::kMaxValueBytes] = {};
  v.resized(n).to_le(buf);
  if (big_endian) std::reverse(buf, buf + n);
  std::memcpy(regs.data() + r.offset, buf, n);
}

std::uint64_t Emulator::Impl::get_reg_u64(std::string_view name) const { return get_reg(reg(name)).lo(); }

void Emulator::Impl::set_reg_u64(std::string_view name, std::uint64_t v) {
  const RegisterInfo &r = reg(name);
  set_reg(r, Wide::of(r.size, v));
}

void Emulator::Impl::charge(std::uint64_t bytes) {
  if (used + bytes > options.max_memory)
    throw detail::Fault{StopKind::memory_limit, 0,
                        "the session's memory bound (" + std::to_string(options.max_memory >> 20) + " MiB) is reached"};
  used += bytes;
}

const detail::Region *Emulator::Impl::region_at(std::uint64_t addr) const {
  auto it = regions.upper_bound(addr);
  if (it == regions.begin()) return nullptr;
  --it;
  return addr <= it->second.last() ? &it->second : nullptr;
}

bool Emulator::Impl::mapped(std::uint64_t addr, std::uint64_t size) const {
  std::uint64_t at = addr;
  std::uint64_t left = size;
  while (left > 0) {
    const detail::Region *r = region_at(at);
    if (r == nullptr) return false;
    const std::uint64_t in_region = r->last() - at + 1;  // may be 0 on wrap of a full space; regions never wrap
    if (in_region >= left) return true;
    left -= in_region;
    at += in_region;
  }
  return true;
}

void Emulator::Impl::overlay_patches(std::uint64_t at, std::span<std::byte> span) const {
  for (const auto &[p, bytes] : options.patches) {
    if (bytes.empty() || p + bytes.size() <= at || p >= at + span.size()) continue;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
      const std::uint64_t a = p + i;
      if (a >= at && a - at < span.size()) span[static_cast<std::size_t>(a - at)] = static_cast<std::byte>(bytes[i]);
    }
  }
}

void Emulator::Impl::base_read(std::uint64_t at, std::span<std::byte> out) const {
  if (!options.backing) {
    image->memory.read(at, out);  // zero where nothing is loaded
    overlay_patches(at, out);
    return;
  }
  std::size_t done = 0;
  while (done < out.size()) {
    const std::uint64_t a = at + done;
    const std::uint64_t index = a / kPageSize, off = a % kPageSize;
    const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(out.size() - done, kPageSize - off));
    const detail::Page *page = fetched.find(index);
    if (page == nullptr) {
      bool created = false;
      page = fetched.writable(
          index,
          [&](detail::Page &p) {
            const std::size_t got = options.backing->read ? options.backing->read(index * kPageSize, p.bytes) : 0;
            if (got < kPageSize) std::memset(p.bytes.data() + got, 0, kPageSize - got);
          },
          created);
      ++pages_fetched;
    }
    std::memcpy(out.data() + done, page->bytes.data() + off, n);
    done += n;
  }
}

void Emulator::Impl::ram_read(std::uint64_t addr, std::uint8_t *out, std::uint64_t size) const {
  std::uint64_t done = 0;
  while (done < size) {
    const std::uint64_t at = (addr + done) & code_mask;
    const std::uint64_t index = at / kPageSize, off = at % kPageSize;
    const std::uint64_t n = std::min<std::uint64_t>(size - done, kPageSize - off);
    if (const detail::Page *page = ram.find(index)) {
      std::memcpy(out + done, page->bytes.data() + off, n);
    } else {
      base_read(at, std::span<std::byte>(reinterpret_cast<std::byte *>(out + done), n));
    }
    done += n;
  }
}

void Emulator::Impl::ram_write(std::uint64_t addr, const std::uint8_t *in, std::uint64_t size) {
  std::uint64_t done = 0;
  while (done < size) {
    const std::uint64_t at = (addr + done) & code_mask;
    const std::uint64_t index = at / kPageSize, off = at % kPageSize;
    const std::uint64_t n = std::min<std::uint64_t>(size - done, kPageSize - off);
    bool created = false;
    // Charge before allocating: a page costs its size.
    if (ram.find(index) == nullptr) charge(kPageSize);
    detail::Page *page = ram.writable(
        index,
        [&](detail::Page &p) {
          base_read(index * kPageSize, std::span<std::byte>(reinterpret_cast<std::byte *>(p.bytes.data()), kPageSize));
        },
        created);
    std::memcpy(page->bytes.data() + off, in + done, n);
    if (!code_pages.empty() && code_pages.count(index) != 0) {
      // Code was written: decode again from the new bytes.
      decoded.clear();
      decoded_thumb.clear();
      code_pages.clear();
    }
    done += n;
  }
}

void Emulator::Impl::map_region(RegionInfo info) {
  if (info.size == 0) throw EmuError("empty region " + info.name);
  const std::uint64_t last = info.start + (info.size - 1);
  if (last < info.start) throw EmuError("region " + info.name + " wraps around the address space");
  auto it = regions.upper_bound(last);
  if (it != regions.begin()) {
    --it;
    if (it->second.last() >= info.start)
      throw EmuError("region " + info.name + " overlaps " + it->second.info.name);
  }
  detail::Region r;
  r.info = std::move(info);
  regions.emplace(r.info.start, std::move(r));
}

}  // namespace revkit::emu
