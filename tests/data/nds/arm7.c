// The ARM7's side: ARMv4T code.
int arm7_counter;

int Arm7Poll(int port) {
  arm7_counter += port & 0xff;
  return arm7_counter;
}

void Arm7Main(void) {
  for (int i = 0; i < 4; ++i) Arm7Poll(i * 0x41);
}
