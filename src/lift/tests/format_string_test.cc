// printf and scanf formats as the arguments they pass (format_string.hh).
#include "revkit/lift/format_string.hh"

#include <gtest/gtest.h>

namespace revkit::lift {
namespace {

using K = FormatArg::Kind;

TEST(FormatString, PrintfConversions) {
  FormatModel lp64;
  auto args = printf_arguments("%-10s %08x %ld %lld %zu %p %.2f %c %% %Lf %hhd %n", lp64);
  ASSERT_TRUE(args);
  const std::vector<FormatArg> want = {
      {K::string, 1, true},  {K::integer, 4, false}, {K::integer, 8, true},  {K::integer, 8, true},
      {K::integer, 8, false}, {K::pointer, 8, false}, {K::floating, 8, true}, {K::integer, 4, true},
      {K::floating, 16, true}, {K::integer, 4, true}, {K::int_ptr, 4, true}};
  EXPECT_EQ(*args, want);
  // Width and precision from arguments.
  args = printf_arguments("%*.*s|%-*d", lp64);
  ASSERT_TRUE(args);
  EXPECT_EQ(args->size(), 5u);
  EXPECT_EQ((*args)[2].kind, K::string);
  // No conversion, glibc's %m, and what can't be read.
  EXPECT_EQ(printf_arguments("plain text\n", lp64)->size(), 0u);
  EXPECT_EQ(printf_arguments("error: %m", lp64)->size(), 0u);
  EXPECT_FALSE(printf_arguments("%1$d %2$d", lp64));
  EXPECT_FALSE(printf_arguments("%y", lp64));
  EXPECT_FALSE(printf_arguments("trailing %", lp64));
}

TEST(FormatString, WindowsLengths) {
  FormatModel llp64;
  llp64.long_size = 4;
  llp64.wchar_size = 2;
  llp64.windows = true;
  auto args = printf_arguments("%I64d %Iu %ld %S %ls", llp64);
  ASSERT_TRUE(args);
  ASSERT_EQ(args->size(), 5u);
  EXPECT_EQ((*args)[0].size, 8);
  EXPECT_EQ((*args)[1].size, 8);  // pointer-sized
  EXPECT_EQ((*args)[2].size, 4);  // long is 4 bytes
  EXPECT_EQ((*args)[3], (FormatArg{K::string, 2, true}));
  EXPECT_EQ((*args)[4], (FormatArg{K::string, 2, true}));
}

TEST(FormatString, ScanfConversions) {
  FormatModel lp64;
  auto args = scanf_arguments("%d %*d %lf %s %[^,] %hu %c", lp64);
  ASSERT_TRUE(args);
  const std::vector<FormatArg> want = {{K::int_ptr, 4, true}, {K::float_ptr, 8, true}, {K::string, 1, true},
                                       {K::string, 1, true},  {K::int_ptr, 2, false},  {K::string, 1, true}};
  EXPECT_EQ(*args, want);
  EXPECT_FALSE(scanf_arguments("%ms", lp64));
}

}  // namespace
}  // namespace revkit::lift
