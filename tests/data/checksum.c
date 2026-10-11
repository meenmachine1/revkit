/* FNV-1a over a buffer. No calls or data references, so the
 * function decompiles cleanly from a raw .text dump. */
unsigned int checksum(const unsigned char *p, unsigned long n)
{
    unsigned int h = 2166136261u;
    for (unsigned long i = 0; i < n; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}
