/* C runtime start-up functions a mingw or MSVC program imports that the
   public headers don't declare (revkit's own declarations). */
int __getmainargs(int *argc, char ***argv, char ***envp, int expand, void *startinfo);
int __wgetmainargs(int *argc, wchar_t ***argv, wchar_t ***envp, int expand, void *startinfo);
void __set_app_type(int type);
void __setusermatherr(int (*handler)(struct _exception *));
void _initterm(void (**first)(void), void (**last)(void));
int _initterm_e(int (**first)(void), int (**last)(void));
_Noreturn void _amsg_exit(int code);
int ___mb_cur_max_func(void);
unsigned int ___lc_codepage_func(void);
