// Links libgreet.dylib by @rpath (build.sh).
int greet(const char *who);
extern int greet_count;

int main(void) { return greet("there") + greet_count; }
