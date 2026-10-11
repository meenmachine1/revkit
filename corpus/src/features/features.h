/* Shared declarations for the "features" corpus program. Each module
 * exercises one group of C features and returns a checksum so the
 * optimizer can't drop the work. */
#ifndef FEATURES_H
#define FEATURES_H

#include <stddef.h>
#include <stdint.h>

uint32_t run_loops(int n);
uint32_t run_switches(int n);
uint32_t run_structs(int n);
uint32_t run_funcptr(int n);
uint32_t run_recursion(int n);
uint32_t run_varargs(int n);
uint32_t run_floats(int n);
uint32_t run_strings(int n);
uint32_t run_bits(int n);
uint32_t run_hashtable(int n);
uint32_t run_vm(int n);

uint32_t fnv1a(const void *data, size_t len);

#endif
