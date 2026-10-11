/* mcukit's application: see mcukit.h. */
#include "mcukit.h"

ring_t uart_rx, uart_tx;
volatile uint16_t ticks;

/* ---- ring buffers (the UART interrupts fill and drain them) ---- */

uint8_t ring_put(ring_t *r, uint8_t c) {
  uint8_t next = (uint8_t)((r->head + 1) & (MCU_RING_SIZE - 1));
  if (next == r->tail) return 0;
  r->buf[r->head] = c;
  r->head = next;
  return 1;
}

int16_t ring_get(ring_t *r) {
  uint8_t c;
  if (r->head == r->tail) return -1;
  c = r->buf[r->tail];
  r->tail = (uint8_t)((r->tail + 1) & (MCU_RING_SIZE - 1));
  return c;
}

static uint8_t ring_count(const ring_t *r) { return (uint8_t)((r->head - r->tail) & (MCU_RING_SIZE - 1)); }

/* ---- output ---- */

static void out_char(char c) {
  while (!ring_put(&uart_tx, (uint8_t)c)) board_uart_kick();
  board_uart_kick();
}

static void out_str(const char *s) {
  while (*s) out_char(*s++);
}

static void out_line(const char *s) {
  out_str(s);
  out_char('\r');
  out_char('\n');
}

static void out_hex(uint16_t v, uint8_t digits) {
  static const char MCU_CODE hexdigits[] = "0123456789abcdef";
  while (digits--) out_char((char)MCU_READ8(&hexdigits[(v >> (4 * digits)) & 0xf]));
}

static void out_udec(uint32_t v) {
  char buf[11];
  uint8_t n = 0;
  do {
    buf[n++] = (char)('0' + (uint8_t)(v % 10));
    v /= 10;
  } while (v != 0);
  while (n) out_char(buf[--n]);
}

static void out_dec(int32_t v) {
  if (v < 0) {
    out_char('-');
    out_udec((uint32_t)-v);
  } else {
    out_udec((uint32_t)v);
  }
}

/* ---- checksums ---- */

/* CRC-16/CCITT-FALSE, a nibble table in code memory. */
static const uint16_t MCU_CODE crc16_table[16] = {
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
    0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
};

uint16_t crc16_update(uint16_t crc, uint8_t b) {
  crc = (uint16_t)((crc << 4) ^ MCU_READ16(&crc16_table[((crc >> 12) ^ (b >> 4)) & 0xf]));
  crc = (uint16_t)((crc << 4) ^ MCU_READ16(&crc16_table[((crc >> 12) ^ b) & 0xf]));
  return crc;
}

uint16_t crc16(const uint8_t *p, uint8_t n) {
  uint16_t crc = 0xffff;
  while (n--) crc = crc16_update(crc, *p++);
  return crc;
}

uint32_t crc32_bitwise(const uint8_t *p, uint16_t n) {
  uint32_t crc = 0xffffffffUL;
  uint8_t k;
  while (n--) {
    crc ^= *p++;
    for (k = 0; k < 8; k++) crc = (crc >> 1) ^ (0xedb88320UL & (uint32_t)-(int32_t)(crc & 1));
  }
  return ~crc;
}

/* ---- settings in non-volatile memory ---- */

typedef struct {
  uint8_t magic;
  uint8_t mode;
  int16_t kp, ki, kd; /* PID gains, Q8.8 */
  uint16_t setpoint;
  uint16_t period; /* control period in ticks */
  uint8_t echo;
  uint16_t crc;
} settings_t;

static settings_t settings;

#define SETTINGS_MAGIC 0xa5

static void settings_defaults(void) {
  settings.magic = SETTINGS_MAGIC;
  settings.mode = 0;
  settings.kp = 0x0180;
  settings.ki = 0x0020;
  settings.kd = 0x0040;
  settings.setpoint = 512;
  settings.period = 10;
  settings.echo = 1;
}

static uint8_t settings_load(void) {
  uint8_t *p = (uint8_t *)&settings;
  uint8_t i;
  for (i = 0; i < sizeof settings; i++) p[i] = board_nvm_read(i);
  if (settings.magic != SETTINGS_MAGIC ||
      settings.crc != crc16((const uint8_t *)&settings, (uint8_t)(sizeof settings - sizeof settings.crc))) {
    settings_defaults();
    return 0;
  }
  return 1;
}

static void settings_save(void) {
  const uint8_t *p = (const uint8_t *)&settings;
  uint8_t i;
  settings.crc = crc16(p, (uint8_t)(sizeof settings - sizeof settings.crc));
  for (i = 0; i < sizeof settings; i++)
    if (board_nvm_read(i) != p[i]) board_nvm_write(i, p[i]);
}

/* ---- control: a fixed-point PID loop on an ADC channel ---- */

typedef struct {
  int32_t integral;
  int16_t last_error;
  int16_t out_min, out_max;
} pid_t_;

static pid_t_ pid;

static int16_t clamp16(int32_t v, int16_t lo, int16_t hi) {
  if (v < lo) return lo;
  if (v > hi) return hi;
  return (int16_t)v;
}

int16_t pid_step(pid_t_ *c, int16_t error) {
  int32_t p, i, d, out;
  c->integral += error;
  c->integral = clamp16(c->integral, -4096, 4096);
  p = (int32_t)settings.kp * error;
  i = (int32_t)settings.ki * c->integral;
  d = (int32_t)settings.kd * (error - c->last_error);
  c->last_error = error;
  out = (p + i + d) >> 8;
  return clamp16(out, c->out_min, c->out_max);
}

/* Integer square root (for an RMS of the samples). */
uint16_t isqrt32(uint32_t v) {
  uint32_t bit = 1UL << 30, res = 0;
  while (bit > v) bit >>= 2;
  while (bit != 0) {
    if (v >= res + bit) {
      v -= res + bit;
      res = (res >> 1) + bit;
    } else {
      res >>= 1;
    }
    bit >>= 2;
  }
  return (uint16_t)res;
}

static uint16_t samples[8];
static uint8_t sample_at;

static void control_task(void) {
  uint16_t v = board_adc(0);
  int16_t duty;
  samples[sample_at++ & 7] = v;
  duty = pid_step(&pid, (int16_t)(settings.setpoint - v));
  if (settings.mode == 1) board_pwm((uint16_t)duty);
}

static uint16_t rms(void) {
  uint32_t sum = 0;
  uint8_t i;
  for (i = 0; i < 8; i++) sum += (uint32_t)samples[i] * samples[i];
  return isqrt32(sum / 8);
}

/* ---- the framed protocol: SOF, length, command, payload, CRC-16 ---- */

enum { RX_SOF, RX_LEN, RX_CMD, RX_DATA, RX_CRC_HI, RX_CRC_LO };
#define FRAME_SOF 0x7e
#define FRAME_MAX 16

static uint8_t rx_state, rx_len, rx_cmd, rx_at;
static uint8_t rx_data[FRAME_MAX];
static uint16_t rx_crc, rx_got;
static uint16_t frames_ok, frames_bad;

static void frame_reply(uint8_t cmd, const uint8_t *p, uint8_t n) {
  uint16_t crc = 0xffff;
  uint8_t i;
  out_char((char)FRAME_SOF);
  out_char((char)n);
  out_char((char)cmd);
  crc = crc16_update(crc, n);
  crc = crc16_update(crc, cmd);
  for (i = 0; i < n; i++) {
    out_char((char)p[i]);
    crc = crc16_update(crc, p[i]);
  }
  out_char((char)(crc >> 8));
  out_char((char)crc);
}

static void frame_dispatch(void) {
  uint8_t reply[4];
  switch (rx_cmd) {
    case 0x01: /* ping */
      frame_reply(0x81, rx_data, rx_len);
      break;
    case 0x02: /* read the setpoint */
      reply[0] = (uint8_t)(settings.setpoint >> 8);
      reply[1] = (uint8_t)settings.setpoint;
      frame_reply(0x82, reply, 2);
      break;
    case 0x03: /* write the setpoint */
      if (rx_len == 2) settings.setpoint = (uint16_t)(rx_data[0] << 8 | rx_data[1]);
      frame_reply(0x83, 0, 0);
      break;
    case 0x04: /* mode */
      if (rx_len == 1) settings.mode = rx_data[0];
      frame_reply(0x84, &settings.mode, 1);
      break;
    case 0x05: /* status */
      reply[0] = (uint8_t)(ticks >> 8);
      reply[1] = (uint8_t)ticks;
      reply[2] = (uint8_t)frames_ok;
      reply[3] = (uint8_t)frames_bad;
      frame_reply(0x85, reply, 4);
      break;
    case 0x06: /* save */
      settings_save();
      frame_reply(0x86, 0, 0);
      break;
    case 0x07: /* reset */
      board_reset();
      break;
    default:
      reply[0] = rx_cmd;
      frame_reply(0xff, reply, 1);
      break;
  }
}

/* Feeds one received byte to the frame parser; 1 when a frame completed. */
uint8_t frame_feed(uint8_t c) {
  switch (rx_state) {
    case RX_SOF:
      if (c == FRAME_SOF) rx_state = RX_LEN;
      break;
    case RX_LEN:
      if (c > FRAME_MAX) {
        frames_bad++;
        rx_state = RX_SOF;
        break;
      }
      rx_len = c;
      rx_crc = crc16_update(0xffff, c);
      rx_state = RX_CMD;
      break;
    case RX_CMD:
      rx_cmd = c;
      rx_crc = crc16_update(rx_crc, c);
      rx_at = 0;
      rx_state = rx_len ? RX_DATA : RX_CRC_HI;
      break;
    case RX_DATA:
      rx_data[rx_at++] = c;
      rx_crc = crc16_update(rx_crc, c);
      if (rx_at == rx_len) rx_state = RX_CRC_HI;
      break;
    case RX_CRC_HI:
      rx_got = (uint16_t)c << 8;
      rx_state = RX_CRC_LO;
      break;
    case RX_CRC_LO:
      rx_got |= c;
      rx_state = RX_SOF;
      if (rx_got != rx_crc) {
        frames_bad++;
        return 0;
      }
      frames_ok++;
      frame_dispatch();
      return 1;
  }
  return 0;
}

/* ---- the shell ---- */

static char line[MCU_LINE_MAX];
static uint8_t line_len;

static uint8_t str_eq(const char *a, const char *b) {
  while (*a && *a == *b) {
    a++;
    b++;
  }
  return *a == *b;
}

static uint8_t parse_u16(const char *s, uint16_t *out) {
  uint16_t v = 0;
  uint8_t base = 10, digit;
  if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
    base = 16;
    s += 2;
  }
  if (!*s) return 0;
  for (; *s; s++) {
    if (*s >= '0' && *s <= '9') digit = (uint8_t)(*s - '0');
    else if (base == 16 && *s >= 'a' && *s <= 'f') digit = (uint8_t)(*s - 'a' + 10);
    else if (base == 16 && *s >= 'A' && *s <= 'F') digit = (uint8_t)(*s - 'A' + 10);
    else return 0;
    v = (uint16_t)(v * base + digit);
  }
  *out = v;
  return 1;
}

static void cmd_help(uint8_t argc, char **argv) MCU_REENTRANT;

static void cmd_peek(uint8_t argc, char **argv) MCU_REENTRANT {
  uint16_t at, n = 16, i;
  if (argc < 2 || !parse_u16(argv[1], &at)) {
    out_line("usage: peek <addr> [n]");
    return;
  }
  if (argc > 2) parse_u16(argv[2], &n);
  for (i = 0; i < n; i++) {
    if ((i & 7) == 0) {
      out_str("\r\n");
      out_hex((uint16_t)(at + i), 4);
      out_char(':');
    }
    out_char(' ');
    out_hex(board_nvm_read((uint16_t)(at + i)), 2);
  }
  out_str("\r\n");
}

static void cmd_poke(uint8_t argc, char **argv) MCU_REENTRANT {
  uint16_t at, v;
  if (argc != 3 || !parse_u16(argv[1], &at) || !parse_u16(argv[2], &v)) {
    out_line("usage: poke <addr> <byte>");
    return;
  }
  board_nvm_write(at, (uint8_t)v);
}

static void cmd_crc(uint8_t argc, char **argv) MCU_REENTRANT {
  uint8_t i;
  for (i = 1; i < argc; i++) {
    const char *s = argv[i];
    uint8_t n = 0;
    while (s[n]) n++;
    out_hex(crc16((const uint8_t *)s, n), 4);
    out_char(' ');
    out_udec(crc32_bitwise((const uint8_t *)s, n));
    out_str("\r\n");
  }
}

static void cmd_led(uint8_t argc, char **argv) MCU_REENTRANT {
  if (argc == 2 && str_eq(argv[1], "on")) board_led(1);
  else if (argc == 2 && str_eq(argv[1], "off")) board_led(0);
  else out_line("usage: led on|off");
}

static void cmd_pid(uint8_t argc, char **argv) MCU_REENTRANT {
  uint16_t v;
  if (argc == 3 && parse_u16(argv[2], &v)) {
    if (str_eq(argv[1], "kp")) settings.kp = (int16_t)v;
    else if (str_eq(argv[1], "ki")) settings.ki = (int16_t)v;
    else if (str_eq(argv[1], "kd")) settings.kd = (int16_t)v;
    else if (str_eq(argv[1], "sp")) settings.setpoint = v;
    else out_line("unknown gain");
    return;
  }
  out_str("kp ");
  out_dec(settings.kp);
  out_str(" ki ");
  out_dec(settings.ki);
  out_str(" kd ");
  out_dec(settings.kd);
  out_str(" sp ");
  out_udec(settings.setpoint);
  out_str(" rms ");
  out_udec(rms());
  out_str("\r\n");
}

static void cmd_stats(uint8_t argc, char **argv) MCU_REENTRANT {
  (void)argc;
  (void)argv;
  out_str("ticks ");
  out_udec(ticks);
  out_str(" frames ");
  out_udec(frames_ok);
  out_char('/');
  out_udec(frames_bad);
  out_str(" rx ");
  out_udec(ring_count(&uart_rx));
  out_str("\r\n");
}

static void cmd_save(uint8_t argc, char **argv) MCU_REENTRANT {
  (void)argc;
  (void)argv;
  settings_save();
  out_line("saved");
}

static void cmd_reset(uint8_t argc, char **argv) MCU_REENTRANT {
  (void)argc;
  (void)argv;
  out_line("resetting");
  board_reset();
}

typedef void (*command_fn)(uint8_t argc, char **argv) MCU_REENTRANT;
typedef struct {
  const char *name;
  command_fn fn;
  const char *help;
} command_t;

static const command_t commands[] = {
    {"help", cmd_help, "this list"},
    {"peek", cmd_peek, "dump settings memory"},
    {"poke", cmd_poke, "write settings memory"},
    {"crc", cmd_crc, "checksums of words"},
    {"led", cmd_led, "the status LED"},
    {"pid", cmd_pid, "control gains"},
    {"stats", cmd_stats, "counters"},
    {"save", cmd_save, "store the settings"},
    {"reset", cmd_reset, "restart"},
};
#define N_COMMANDS (sizeof commands / sizeof commands[0])

static void cmd_help(uint8_t argc, char **argv) MCU_REENTRANT {
  uint8_t i;
  (void)argc;
  (void)argv;
  for (i = 0; i < N_COMMANDS; i++) {
    out_str(commands[i].name);
    out_str(" - ");
    out_line(commands[i].help);
  }
}

static void shell_run(void) {
  char *argv[MCU_ARGS_MAX];
  uint8_t argc = 0, i;
  char *p = line;
  line[line_len] = 0;
  while (*p && argc < MCU_ARGS_MAX) {
    while (*p == ' ') *p++ = 0;
    if (!*p) break;
    argv[argc++] = p;
    while (*p && *p != ' ') p++;
  }
  if (argc == 0) return;
  for (i = 0; i < N_COMMANDS; i++)
    if (str_eq(argv[0], commands[i].name)) {
      commands[i].fn(argc, argv);
      return;
    }
  out_str("unknown: ");
  out_line(argv[0]);
}

static void shell_input(uint8_t c) {
  if (c == '\r' || c == '\n') {
    if (settings.echo) out_str("\r\n");
    shell_run();
    line_len = 0;
    out_str("> ");
  } else if (c == 0x08 || c == 0x7f) {
    if (line_len) {
      line_len--;
      if (settings.echo) out_str("\b \b");
    }
  } else if (line_len < MCU_LINE_MAX - 1) {
    line[line_len++] = (char)c;
    if (settings.echo) out_char((char)c);
  }
}

/* ---- the scheduler ---- */

typedef struct {
  void (*fn)(void);
  uint16_t period;
  uint16_t next;
} task_t;

static void blink_task(void) {
  static uint8_t on;
  on = !on;
  board_led(on);
}

static void input_task(void) {
  int16_t c;
  while ((c = ring_get(&uart_rx)) >= 0) {
    if (settings.mode == 2) frame_feed((uint8_t)c);
    else shell_input((uint8_t)c);
  }
}

static void watchdog_task(void) {
  if (ring_count(&uart_tx) == MCU_RING_SIZE - 1) mcu_fault(2);
}

static task_t tasks[] = {
    {input_task, 1, 0},
    {control_task, 10, 0},
    {blink_task, 500, 0},
    {watchdog_task, 100, 0},
};
#define N_TASKS (sizeof tasks / sizeof tasks[0])

void mcu_tick(void) { ticks++; }

void mcu_fault(uint8_t code) {
  board_irq_off();
  board_led(1);
  out_str("fault ");
  out_hex(code, 2);
  out_str("\r\n");
  for (;;) board_idle();
}

void main(void) {
  uint8_t i;
  uint16_t now;
  board_init();
  if (!settings_load()) out_line("settings: defaults");
  tasks[1].period = settings.period;
  pid.out_min = 0;
  pid.out_max = 1023;
  board_irq_on();
  out_line("mcukit ready");
  out_str("> ");
  for (;;) {
    board_irq_off();
    now = ticks;
    board_irq_on();
    for (i = 0; i < N_TASKS; i++) {
      if ((int16_t)(now - tasks[i].next) >= 0) {
        tasks[i].next = (uint16_t)(now + tasks[i].period);
        tasks[i].fn();
      }
    }
    board_idle();
  }
}
