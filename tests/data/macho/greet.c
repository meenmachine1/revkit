// libgreet.dylib for the library tests: an exported function and datum.
int printf(const char *, ...);

int greet_count;

int greet(const char *who) {
  ++greet_count;
  return printf("hi %s\n", who);
}
