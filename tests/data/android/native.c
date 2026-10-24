/* The JNI library of the generated test APK (make_apk.py): exports bound
   to com.example.droid.NativeLib's native methods by their JNI names, one
   overloaded pair by the long names, JNI_OnLoad (where registered() would
   be bound by RegisterNatives), and a call into libhelper.so. */
int helper_scale(int x);

void *Java_com_example_droid_NativeLib_hello(void *env, void *cls, void *s) { (void)env; (void)cls; return s; }
int Java_com_example_droid_NativeLib_add__II(void *env, void *self, int a, int b) { (void)env; (void)self; return a + b; }
long long Java_com_example_droid_NativeLib_add__JJ(void *env, void *self, long long a, long long b) { (void)env; (void)self; return a + b; }
void Java_com_example_droid_NativeLib_do_1it(void *env, void *cls) { (void)env; (void)cls; }
int Java_com_example_droid_NativeLib_00024Inner_ping(void *env, void *cls) { (void)env; (void)cls; return helper_scale(7); }
int JNI_OnLoad(void *vm, void *reserved) { (void)vm; (void)reserved; return 0x10006; }
static int hidden_twice(int x) { return 2 * x; }
int exported_helper(int x) { return hidden_twice(x) + 1; }
