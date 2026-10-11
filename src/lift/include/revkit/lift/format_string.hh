// printf and scanf format strings: the arguments a constant format passes
// to a varargs function, for call-site prototype overrides (Ghidra's
// "Variadic Function Signature Override" analysis; docs/types.md#format-strings).
#pragma once

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace revkit::lift {

// The target's C sizes the conversions take.
struct FormatModel {
  int int_size = 4;
  int long_size = 8;
  int long_long_size = 8;
  int pointer_size = 8;
  int wchar_size = 4;
  int long_double_size = 16;
  bool windows = false;  // Microsoft's: %I64d, %S and %C are wide, %ls too
};

struct FormatArg {
  enum class Kind : std::uint8_t {
    integer,     // an integer of `size` bytes (char and short promote to int)
    floating,    // a double (or long double), `size` bytes
    string,      // a pointer to characters of `size` bytes (char or wchar_t)
    pointer,     // void *
    int_ptr,     // a pointer to an integer of `size` bytes (%n, scanf's %d)
    float_ptr,   // a pointer to a float of `size` bytes (scanf's %f, %lf)
  };
  Kind kind = Kind::integer;
  int size = 4;
  bool is_signed = true;
  friend bool operator==(const FormatArg &, const FormatArg &) = default;
};

// The arguments after the format, in order; nullopt for what isn't a
// format this can read (positional arguments "%1$d", an unknown
// conversion, no terminating conversion character).
std::optional<std::vector<FormatArg>> printf_arguments(std::string_view format, const FormatModel &model);
std::optional<std::vector<FormatArg>> scanf_arguments(std::string_view format, const FormatModel &model);

}  // namespace revkit::lift
