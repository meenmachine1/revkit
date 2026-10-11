/* The shared library the program imports from (its PLT's targets). */
int ext1(int x) { return x + 1; }
int ext2(int x) { return x * 2; }
int ext3(const char *s) { return s[0]; }
