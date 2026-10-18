public class Tiny {
    static int add(int a, int b) { int c = a + b; if (c > 10) c -= 3; return c * 2; }
    static int sum(int[] xs) { int s = 0; for (int i = 0; i < xs.length; i++) s += xs[i]; return s; }
    int f;
    int getF() { return f; }
    static String hello(String n) { return "hi " + n.length(); }
}
