// Adapter that lets Ghidra's SLEIGH engine and decompiler read bytes and
// symbols from a loaded Image.
#pragma once

#include "revkit/loader/image.hh"

#include "loadimage.hh"

#include <memory>
#include <optional>
#include <string>

namespace revkit::loader {

class GhidraLoadImage : public ghidra::LoadImage {
 public:
  // `arch_type` is what getArchType() reports, normally the language id.
  GhidraLoadImage(std::shared_ptr<const Image> image, std::string arch_type);

  // Bytes are served only for this space (the default code space). Must be
  // called before symbols or sections are enumerated.
  void attach(ghidra::AddrSpace *space) { space_ = space; }

  // Unmapped bytes inside a request read as zero (SLEIGH always asks for a
  // fixed-size window that can run past the end of a segment). Throws
  // DataUnavailError only when no byte of the request is mapped.
  void loadFill(ghidra::uint1 *ptr, ghidra::int4 size, const ghidra::Address &addr) override;

  std::string getArchType() const override { return arch_type_; }
  void adjustVma(long adjust) override;

  // Function symbols, in address order (ARM Thumb bit cleared).
  void openSymbols() const override { next_symbol_ = 0; }
  void closeSymbols() const override {}
  bool getNextSymbol(ghidra::LoadImageFunc &record) const override;

  void openSectionInfo() const override { next_section_ = 0; }
  void closeSectionInfo() const override {}
  bool getNextSection(ghidra::LoadImageSection &record) const override;

  // Blocks without write permission, so the decompiler can fold loads from
  // constant data.
  void getReadonly(ghidra::RangeList &list) const override;

  const Image &image() const { return *image_; }

  // The key (see AddressSpace) of a SLEIGH address: the offset in the
  // attached default space, the image's base for the space plus the
  // offset in another space the image has blocks in; nullopt otherwise.
  std::optional<std::uint64_t> key_of(const ghidra::Address &addr) const;
  // The SLEIGH address of a key; an invalid Address when the key is in a
  // space the language doesn't have (or nothing is attached).
  ghidra::Address address_of(std::uint64_t key) const;

 private:
  struct FuncSym {
    std::uint64_t addr;
    std::string name;
  };

  std::shared_ptr<const Image> image_;
  std::string arch_type_;
  ghidra::AddrSpace *space_ = nullptr;
  std::vector<FuncSym> functions_;
  mutable std::size_t next_symbol_ = 0;
  mutable std::size_t next_section_ = 0;
};

}  // namespace revkit::loader
