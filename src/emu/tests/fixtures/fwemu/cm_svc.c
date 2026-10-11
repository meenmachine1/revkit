/* SVC on a Cortex-M3: services read their arguments from the exception
 * frame and return in it, on whichever stack the caller used; the handler
 * sees its exception number in IPSR. */
#include "cm_common.h"

extern unsigned __psp_top[];

__attribute__((naked)) void svc_handler(void) {
  asm volatile(
      "tst lr, #4\n\t"
      "ite eq\n\t"
      "mrseq r0, msp\n\t"
      "mrsne r0, psp\n\t"
      "b svc_dispatch\n\t");
}

void svc_dispatch(unsigned *frame) {
  const unsigned char number = ((const unsigned char *)frame[6])[-2];
  unsigned ipsr;
  asm volatile("mrs %0, ipsr" : "=r"(ipsr));
  switch (number) {
    case 1: frame[0] = frame[0] + frame[1]; break;
    case 2: frame[0] = frame[0] * frame[1]; break;
    case 3: frame[0] = ipsr; break;
    case 4: frame[0] = (unsigned)frame; break;
    default: frame[0] = 0xffffffffu; break;
  }
}

#define SVC(num, a, b)                                                            \
  ({                                                                              \
    register unsigned r0_ asm("r0") = (a);                                        \
    register unsigned r1_ asm("r1") = (b);                                        \
    asm volatile("svc %2" : "+r"(r0_) : "r"(r1_), "i"(num) : "memory");           \
    r0_;                                                                          \
  })

static unsigned max3(unsigned a, unsigned b, unsigned c) {
  unsigned m = a > b ? a : b; /* IT blocks */
  return m > c ? m : c;
}

int main(void) {
  puts_("svc test\n");
  puts_("add ");
  putu(SVC(1, 2, 40));
  puts_("\nmul ");
  putu(SVC(2, 6, 7));
  puts_("\nipsr ");
  putu(SVC(3, 0, 0));
  const unsigned msp_frame = SVC(4, 0, 0);
  asm volatile("msr psp, %0\n\tmovs r0, #2\n\tmsr control, r0\n\tisb" : : "r"(__psp_top) : "r0", "memory");
  const unsigned psp_frame = SVC(4, 0, 0);
  puts_(psp_frame < (unsigned)__psp_top && psp_frame + 0x40 >= (unsigned)__psp_top && msp_frame > psp_frame
            ? "\nframes on msp then psp\n"
            : "\nframes misplaced\n");
  volatile unsigned a = 3, b = 9, c = 5;
  puts_("max ");
  putu(max3(a, b, c));
  puts_("\ndone\n");
  semihosting_exit(0); /* main's frame is on the main stack: it can't return */
}
