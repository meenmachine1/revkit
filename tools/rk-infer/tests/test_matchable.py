import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import matchable as m  # noqa: E402


class Matchable(unittest.TestCase):
    def test_primitives_and_pointers(self):
        self.assertTrue(m.is_matchable("int main(int argc, char * * argv)", "elf"))
        self.assertTrue(m.is_matchable("ulonglong f(uchar * p, longdouble x, ...)", "elf"))
        self.assertTrue(m.is_matchable("void f(void)", "pe"))
        self.assertTrue(m.is_matchable("__int128 unsigned f(int[8] * a)", "elf"))

    def test_library_types(self):
        self.assertTrue(m.is_matchable("int f(_IO_FILE * fp, char * fmt, __va_list_tag * ap)", "elf"))
        self.assertTrue(m.is_matchable("int f(stat * st)", "elf"))
        self.assertTrue(m.is_matchable("void f(_RTL_CRITICAL_SECTION * cs)", "pe"))

    def test_platform_names(self):
        # mingw-w64's names don't make an ELF function matchable, nor glibc's a PE one.
        self.assertFalse(m.is_matchable("void f(_RTL_CRITICAL_SECTION * cs)", "elf"))
        self.assertFalse(m.is_matchable("int f(_IO_FILE * fp)", "pe"))

    def test_program_types(self):
        self.assertFalse(m.is_matchable("TValue * index2value(lua_State * L, int idx)", "elf"))
        self.assertFalse(m.is_matchable("int f(anon_struct_7257413e * s)", "elf"))
        self.assertFalse(m.is_matchable("undefined8 f(void)", "elf"))
        self.assertEqual(m.unmatchable_words("cJSON * f(cJSON * a, int b)", "elf"), ["cJSON", "cJSON"])

    def test_function_types(self):
        self.assertTrue(m.is_matchable("void f(_func_void_int_ptr_void_ptr * cb)", "elf"))
        self.assertTrue(m.is_matchable("void f(_func_int__IO_FILE_ptr * cb)", "elf"))
        self.assertTrue(m.is_matchable("void f(_func_void_ptr_void_ptr_ulong * cb)", "elf"))
        self.assertTrue(m.is_matchable("int f(_func_int_char_ptr_ptr_varargs * cb)", "elf"))
        self.assertFalse(m.is_matchable("void f(_func_int_lua_State_ptr * cb)", "elf"))
        self.assertFalse(m.is_matchable("void f(_func_void_ptr_cJSON_ptr * cb)", "elf"))

    def test_names_ignored(self):
        # Parameter names that look like program types don't count.
        self.assertTrue(m.is_matchable("int f(int lua_State)", "elf"))

    def test_platform_of(self):
        self.assertEqual(m.platform_of("pe-x86_64/clang-O2/stripped/sqlite.exe"), "pe")
        self.assertEqual(m.platform_of("elf-riscv64/gcc-O0/stripped/mujs"), "elf")


if __name__ == "__main__":
    unittest.main()
