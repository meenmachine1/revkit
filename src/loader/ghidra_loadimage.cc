#include "revkit/loader/ghidra_loadimage.hh"

#include "translate.hh"

#include <algorithm>
#include <span>

namespace revkit::loader {

namespace {
constexpr std::uint32_t kElfMachineArm = 40;
}

GhidraLoadImage::GhidraLoadImage(std::shared_ptr<const Image> image, std::string arch_type)
    : ghidra::LoadImage("revkit"), image_(std::move(image)), arch_type_(std::move(arch_type)) {
  const bool thumb_bit = (image_->format == Format::elf || image_->format == Format::raw) && image_->machine == kElfMachineArm;
  for (const Symbol &s : image_->symbols) {
    if (!s.defined || s.type != SymbolType::func || s.name.empty()) continue;
    std::uint64_t addr = thumb_bit ? (s.value & ~std::uint64_t{1}) : s.value;
    if (!image_->memory.is_mapped(addr)) continue;
    functions_.push_back({addr, s.name});
  }
  std::sort(functions_.begin(), functions_.end(), [](const FuncSym &a, const FuncSym &b) {
    return a.addr != b.addr ? a.addr < b.addr : a.name < b.name;
  });
  functions_.erase(std::unique(functions_.begin(), functions_.end(),
                               [](const FuncSym &a, const FuncSym &b) { return a.addr == b.addr; }),
                   functions_.end());
}

std::optional<std::uint64_t> GhidraLoadImage::key_of(const ghidra::Address &addr) const {
  if (addr.isInvalid()) return std::nullopt;
  if (space_ == nullptr || addr.getSpace() == space_) return addr.getOffset();
  if (image_->spaces.empty()) return std::nullopt;
  return space_key(*image_, addr.getSpace()->getName(), addr.getOffset());
}

ghidra::Address GhidraLoadImage::address_of(std::uint64_t key) const {
  if (space_ == nullptr) return ghidra::Address();
  SpaceOffset so = split_key(*image_, key);
  ghidra::AddrSpace *spc = so.space == nullptr ? space_ : space_->getManager()->getSpaceByName(so.space->name);
  if (spc == nullptr || so.offset > spc->getHighest()) return ghidra::Address();
  return ghidra::Address(spc, so.offset);
}

void GhidraLoadImage::loadFill(ghidra::uint1 *ptr, ghidra::int4 size, const ghidra::Address &addr) {
  if (size <= 0) return;
  std::span<std::byte> out(reinterpret_cast<std::byte *>(ptr), static_cast<std::size_t>(size));
  const std::optional<std::uint64_t> key = key_of(addr);
  if (!key) {
    std::fill(out.begin(), out.end(), std::byte{0});
    throw ghidra::DataUnavailError("no data in space " + addr.getSpace()->getName());
  }
  if (image_->memory.read(*key, out) == 0) {
    std::ostringstream s;
    s << "unable to load " << size << " bytes at ";
    addr.printRaw(s);
    throw ghidra::DataUnavailError(s.str());
  }
}

void GhidraLoadImage::adjustVma(long) {
  throw ghidra::LowlevelError("revkit images are rebased at load time, not through adjustVma");
}

bool GhidraLoadImage::getNextSymbol(ghidra::LoadImageFunc &record) const {
  if (space_ == nullptr || next_symbol_ >= functions_.size()) return false;
  const FuncSym &f = functions_[next_symbol_++];
  record.address = ghidra::Address(space_, f.addr);
  record.name = f.name;
  return true;
}

bool GhidraLoadImage::getNextSection(ghidra::LoadImageSection &record) const {
  if (space_ == nullptr) return false;
  ghidra::Address at;
  const Block *block = nullptr;
  while (next_section_ < image_->blocks.size() && at.isInvalid()) {
    block = &image_->blocks[next_section_++];
    at = address_of(block->start);
  }
  if (at.isInvalid()) return false;
  const Block &b = *block;
  record.address = at;
  record.size = b.size;
  record.flags = 0;
  if (!b.initialized) record.flags |= ghidra::LoadImageSection::noload;
  if (b.perms.exec) record.flags |= ghidra::LoadImageSection::code;
  else record.flags |= ghidra::LoadImageSection::data;
  if (!b.perms.write) record.flags |= ghidra::LoadImageSection::readonly;
  return true;
}

void GhidraLoadImage::getReadonly(ghidra::RangeList &list) const {
  if (space_ == nullptr) return;
  for (const Block &b : image_->blocks) {
    if (b.perms.write || !b.initialized || b.size == 0) continue;
    const ghidra::Address at = address_of(b.start);
    if (at.isInvalid()) continue;
    const std::uint64_t last = at.getOffset() + (b.size - 1);
    if (last < at.getOffset() || last > at.getSpace()->getHighest()) continue;
    list.insertRange(at.getSpace(), at.getOffset(), last);
  }
}

}  // namespace revkit::loader
