import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import protonorm  # noqa: E402


class Normalize(unittest.TestCase):
    def test_spacing_and_spellings(self):
        self.assertEqual(protonorm.normalize("int main(int argc,char **argv)"),
                         "int main(int argc, char * * argv)")
        self.assertEqual(protonorm.normalize("unsigned long fib(unsigned int n)"),
                         "ulong fib(uint n)")
        self.assertEqual(protonorm.normalize("long double f(long long a, short unsigned int b)"),
                         "longdouble f(longlong a, ushort b)")
        self.assertEqual(protonorm.normalize("_Bool g(signed char c)"), "bool g(char c)")

    def test_pdb_spellings(self):
        self.assertEqual(protonorm.normalize("long64 f(ulong64 a, schar b, float16 c, float10 d)"),
                         "longlong f(ulonglong a, char b, longdouble c, longdouble d)")
        self.assertEqual(protonorm.normalize("int fold(_func___cdecl_int_int_int * f)"),
                         "int fold(_func_int_int_int * f)")

    def test_qualifiers_and_tags(self):
        self.assertEqual(protonorm.normalize("int f(const struct node *const n, volatile enum e x)"),
                         "int f(node * n, e x)")

    def test_void_and_varargs(self):
        self.assertEqual(protonorm.normalize("void f()"), "void f(void)")
        self.assertEqual(protonorm.normalize("long sum(int count,...)"), "long sum(int count, ...)")

    def test_hidden_return_pointer(self):
        truth = "rect make_rect(int x0, uchar color)"
        for ghidra in ("rect * make_rect(rect * __return_storage_ptr__, int x0, uchar color)",
                       "void make_rect(rect * __return_storage_ptr__, int x0, uchar color)"):
            self.assertEqual(protonorm.normalize(ghidra), protonorm.normalize(truth))

    def test_arrays_and_function_types(self):
        self.assertEqual(protonorm.normalize("void m(int[8] * a, _func_int_int * f)"),
                         "void m(int[8] * a, _func_int_int * f)")

    def test_signature_drops_names(self):
        self.assertEqual(protonorm.signature("uint popcount32(uint32_t x)"), "uint(uint32_t)")
        self.assertEqual(protonorm.signature("uint FUN_00101428(uint param_1)"), "uint(uint)")
        self.assertEqual(protonorm.signature("int f(char *s, ...)"), "int(char *, ...)")

    def test_arity(self):
        self.assertEqual(protonorm.arity("void f(int a, ...)"), (False, 1, True))
        self.assertEqual(protonorm.arity("undefined8 FUN_1(void)"), (True, 0, False))

    def test_decompiled_prototype(self):
        c = "\n/* WARNING: x */\nuint FUN_00101428(uint param_1)\n\n{\n  return 0;\n}\n"
        self.assertEqual(protonorm.decompiled_prototype(c), "uint FUN_00101428(uint param_1)")
        self.assertIsNone(protonorm.decompiled_prototype(None))


if __name__ == "__main__":
    unittest.main()
