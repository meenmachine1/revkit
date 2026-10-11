/* Runtime entry points a glibc program imports that no public header
   declares (revkit's own declarations, after the system headers). */
int __libc_start_main(int (*main)(int, char **, char **), int argc, char **argv, void (*init)(void),
                      void (*fini)(void), void (*rtld_fini)(void), void *stack_end);
_Noreturn void __stack_chk_fail(void);
void __cxa_finalize(void *d);
int __cxa_atexit(void (*func)(void *), void *arg, void *d);
void __gmon_start__(void);
void _ITM_deregisterTMCloneTable(void *table);
void _ITM_registerTMCloneTable(void *table, size_t size);
/* ISO C's scanf functions as glibc links them when the program asks for
   strict ISO C or POSIX (no _GNU_SOURCE): asm labels the headers above
   don't take with _GNU_SOURCE. */
int __isoc99_scanf(const char *__format, ...);
int __isoc99_fscanf(FILE *__stream, const char *__format, ...);
int __isoc99_sscanf(const char *__s, const char *__format, ...);
int __isoc99_vscanf(const char *__format, __gnuc_va_list __arg);
int __isoc99_vfscanf(FILE *__s, const char *__format, __gnuc_va_list __arg);
int __isoc99_vsscanf(const char *__s, const char *__format, __gnuc_va_list __arg);
int __isoc99_wscanf(const wchar_t *__format, ...);
int __isoc99_fwscanf(FILE *__stream, const wchar_t *__format, ...);
int __isoc99_swscanf(const wchar_t *__s, const wchar_t *__format, ...);
