/* fwkit: a small RTOS firmware for the revkit firmware corpus. FreeRTOS
 * runs a shell on the UART, a littlefs filesystem on a RAM disk, an lwIP
 * network stack (DHCP, DNS, SNTP, MQTT, a UDP echo and a TCP service) on a
 * memory-mapped Ethernet MAC, Monocypher for signing and encryption, and
 * heatshrink compression. It is built, never run: what matters is that it
 * is the shape of real firmware (corpus/firmware/README in corpus/README.md). */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "FreeRTOS.h"
#include "event_groups.h"
#include "queue.h"
#include "semphr.h"
#include "stream_buffer.h"
#include "task.h"
#include "timers.h"

#include "heatshrink_decoder.h"
#include "heatshrink_encoder.h"
#include "lfs.h"
#include "monocypher.h"

#include "lwip/apps/mqtt.h"
#include "lwip/apps/sntp.h"
#include "lwip/dhcp.h"
#include "lwip/dns.h"
#include "lwip/etharp.h"
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/stats.h"
#include "lwip/tcp.h"
#include "lwip/timeouts.h"
#include "lwip/udp.h"
#include "netif/ethernet.h"

#include "board.h"

/* ---- console ---- */

static SemaphoreHandle_t console_lock;
static StreamBufferHandle_t uart_rx;

void _putchar(char c) { board_putc(c); }

int putchar(int c) {
  board_putc((char)c);
  return c;
}

int puts(const char *s) {
  while (*s) board_putc(*s++);
  board_putc('\n');
  return 0;
}

static void log_line(const char *tag, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void log_line(const char *tag, const char *fmt, ...) {
  char buf[128];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof buf, fmt, ap);
  va_end(ap);
  if (console_lock) xSemaphoreTake(console_lock, portMAX_DELAY);
  printf("[%8lu] %-6s %s\n", (unsigned long)xTaskGetTickCount(), tag, buf);
  if (console_lock) xSemaphoreGive(console_lock);
}

void uart_rx_isr(void) {
  BaseType_t woken = pdFALSE;
  int c;
  while ((c = board_getc()) >= 0) {
    char ch = (char)c;
    xStreamBufferSendFromISR(uart_rx, &ch, 1, &woken);
  }
  portYIELD_FROM_ISR(woken);
}

void fw_assert_failed(const char *expr, const char *file, int line) {
  board_irq_save();
  printf("assertion failed: %s (%s:%d)\n", expr, file, line);
  board_reset();
}

void fw_panic(const char *why) {
  board_irq_save();
  printf("panic: %s\n", why);
  board_reset();
}

void abort(void) { fw_panic("abort"); }

/* ---- events between tasks ---- */

enum {
  EV_NET_UP = 1 << 0,
  EV_FS_READY = 1 << 1,
  EV_TIME_SET = 1 << 2,
  EV_MAC_RX = 1 << 3,
  EV_SHUTDOWN = 1 << 4,
};
static EventGroupHandle_t events;

struct job {
  enum { JOB_HASH, JOB_SIGN, JOB_COMPRESS, JOB_STORE } kind;
  char path[24];
  uint16_t length;
  uint8_t data[48];
};
static QueueHandle_t jobs;
static unsigned long wall_clock;

void fw_set_time(unsigned long sec) {
  wall_clock = sec;
  xEventGroupSetBits(events, EV_TIME_SET);
}

/* ---- filesystem: littlefs on a RAM disk ---- */

#define FS_BLOCK_SIZE 256
#ifdef __AVR__
#define FS_BLOCK_COUNT 8
#else
#define FS_BLOCK_COUNT 64
#endif
static uint8_t ramdisk[FS_BLOCK_SIZE * FS_BLOCK_COUNT];
static uint8_t fs_read_buf[32], fs_prog_buf[32], fs_lookahead[16], fs_file_buf[32];
static lfs_t lfs;
static SemaphoreHandle_t fs_lock;

static int ramdisk_read(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, void *buffer, lfs_size_t size) {
  memcpy(buffer, ramdisk + block * c->block_size + off, size);
  return 0;
}

static int ramdisk_prog(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, const void *buffer,
                        lfs_size_t size) {
  uint8_t *p = ramdisk + block * c->block_size + off;
  const uint8_t *b = buffer;
  lfs_size_t i;
  for (i = 0; i < size; i++) {
    if ((p[i] & b[i]) != b[i]) return LFS_ERR_CORRUPT;  /* flash only clears bits */
    p[i] = b[i];
  }
  return 0;
}

static int ramdisk_erase(const struct lfs_config *c, lfs_block_t block) {
  memset(ramdisk + block * c->block_size, 0xff, c->block_size);
  return 0;
}

static int ramdisk_sync(const struct lfs_config *c) {
  (void)c;
  return 0;
}

static const struct lfs_config fs_config = {
    .read = ramdisk_read,
    .prog = ramdisk_prog,
    .erase = ramdisk_erase,
    .sync = ramdisk_sync,
    .read_size = 16,
    .prog_size = 16,
    .block_size = FS_BLOCK_SIZE,
    .block_count = FS_BLOCK_COUNT,
    .block_cycles = 100,
    .cache_size = 32,
    .lookahead_size = 16,
    .read_buffer = fs_read_buf,
    .prog_buffer = fs_prog_buf,
    .lookahead_buffer = fs_lookahead,
};

static int fs_write_file(const char *path, const void *data, size_t len) {
  lfs_file_t file;
  struct lfs_file_config fcfg = {.buffer = fs_file_buf};
  int err;
  xSemaphoreTake(fs_lock, portMAX_DELAY);
  err = lfs_file_opencfg(&lfs, &file, path, LFS_O_WRONLY | LFS_O_CREAT | LFS_O_TRUNC, &fcfg);
  if (err >= 0) {
    lfs_ssize_t n = lfs_file_write(&lfs, &file, data, (lfs_size_t)len);
    err = lfs_file_close(&lfs, &file);
    if (n < 0) err = (int)n;
  }
  xSemaphoreGive(fs_lock);
  return err;
}

static int fs_read_file(const char *path, void *data, size_t max) {
  lfs_file_t file;
  struct lfs_file_config fcfg = {.buffer = fs_file_buf};
  lfs_ssize_t n;
  int err;
  xSemaphoreTake(fs_lock, portMAX_DELAY);
  err = lfs_file_opencfg(&lfs, &file, path, LFS_O_RDONLY, &fcfg);
  if (err < 0) {
    xSemaphoreGive(fs_lock);
    return err;
  }
  n = lfs_file_read(&lfs, &file, data, (lfs_size_t)max);
  lfs_file_close(&lfs, &file);
  xSemaphoreGive(fs_lock);
  return (int)n;
}

static int fs_list(const char *path, void (*each)(const struct lfs_info *, void *), void *arg) {
  lfs_dir_t dir;
  struct lfs_info info;
  int err, count = 0;
  xSemaphoreTake(fs_lock, portMAX_DELAY);
  err = lfs_dir_open(&lfs, &dir, path);
  if (err >= 0) {
    while (lfs_dir_read(&lfs, &dir, &info) > 0) {
      each(&info, arg);
      count++;
    }
    lfs_dir_close(&lfs, &dir);
  }
  xSemaphoreGive(fs_lock);
  return err < 0 ? err : count;
}

static void fs_task(void *arg) {
  uint32_t boots = 0;
  int err;
  (void)arg;
  err = lfs_mount(&lfs, &fs_config);
  if (err) {
    log_line("fs", "formatting (%d)", err);
    lfs_format(&lfs, &fs_config);
    err = lfs_mount(&lfs, &fs_config);
    if (err) fw_panic("mount");
  }
  lfs_mkdir(&lfs, "/log");
  lfs_mkdir(&lfs, "/keys");
  if (fs_read_file("/boot_count", &boots, sizeof boots) != sizeof boots) boots = 0;
  boots++;
  fs_write_file("/boot_count", &boots, sizeof boots);
  log_line("fs", "boot %lu, %ld blocks used", (unsigned long)boots, (long)lfs_fs_size(&lfs));
  xEventGroupSetBits(events, EV_FS_READY);
  for (;;) {
    EventBits_t bits = xEventGroupWaitBits(events, EV_SHUTDOWN, pdFALSE, pdFALSE, pdMS_TO_TICKS(5000));
    if (bits & EV_SHUTDOWN) break;
    xSemaphoreTake(fs_lock, portMAX_DELAY);
    lfs_fs_gc(&lfs);
    xSemaphoreGive(fs_lock);
  }
  lfs_unmount(&lfs);
  vTaskDelete(NULL);
}

/* ---- crypto: Monocypher ---- */

static uint8_t device_secret[64], device_public[32];

static void hex_string(char *out, const uint8_t *data, size_t n) {
  static const char digits[] = "0123456789abcdef";
  size_t i;
  for (i = 0; i < n; i++) {
    out[2 * i] = digits[data[i] >> 4];
    out[2 * i + 1] = digits[data[i] & 15];
  }
  out[2 * n] = 0;
}

static void crypto_setup(void) {
  uint8_t seed[32];
  int i;
  if (fs_read_file("/keys/device", device_secret, sizeof device_secret) == sizeof device_secret) {
    memcpy(device_public, device_secret + 32, 32);
    return;
  }
  for (i = 0; i < 32; i++) seed[i] = (uint8_t)(rand() ^ board_ticks() ^ (i * 73));
  crypto_eddsa_key_pair(device_secret, device_public, seed);
  fs_write_file("/keys/device", device_secret, sizeof device_secret);
}

static void crypto_job(const struct job *j) {
  uint8_t hash[32], sig[64];
  char text[65];
  switch (j->kind) {
    case JOB_HASH:
      crypto_blake2b(hash, sizeof hash, j->data, j->length);
      hex_string(text, hash, sizeof hash);
      log_line("hash", "%s", text);
      break;
    case JOB_SIGN:
      crypto_eddsa_sign(sig, device_secret, j->data, j->length);
      if (crypto_eddsa_check(sig, device_public, j->data, j->length)) fw_panic("signature");
      hex_string(text, sig, 32);
      log_line("sign", "%s...", text);
      break;
    default:
      break;
  }
}

/* An authenticated, encrypted message for the network: X25519 with the
 * peer's key, then XChaCha20-Poly1305. */
static size_t seal_message(uint8_t *out, size_t max, const uint8_t peer[32], const void *msg, size_t len) {
  uint8_t eph_secret[32], eph_public[32], shared[32], key[32], nonce[24];
  size_t i;
  if (max < len + 32 + 24 + 16) return 0;
  for (i = 0; i < 32; i++) eph_secret[i] = (uint8_t)rand();
  for (i = 0; i < 24; i++) nonce[i] = (uint8_t)(rand() >> 3);
  crypto_x25519_public_key(eph_public, eph_secret);
  crypto_x25519(shared, eph_secret, peer);
  crypto_blake2b(key, sizeof key, shared, sizeof shared);
  memcpy(out, eph_public, 32);
  memcpy(out + 32, nonce, 24);
  crypto_aead_lock(out + 72, out + 56, key, nonce, NULL, 0, msg, len);
  crypto_wipe(eph_secret, sizeof eph_secret);
  crypto_wipe(shared, sizeof shared);
  crypto_wipe(key, sizeof key);
  return len + 72;
}

static int open_message(void *out, const uint8_t *in, size_t len) {
  uint8_t shared[32], key[32];
  int r;
  if (len < 72) return -1;
  crypto_x25519(shared, device_secret, in);
  crypto_blake2b(key, sizeof key, shared, sizeof shared);
  r = crypto_aead_unlock(out, in + 56, key, in + 32, NULL, 0, in + 72, len - 72);
  crypto_wipe(key, sizeof key);
  return r ? -1 : (int)(len - 72);
}

/* ---- compression: heatshrink ---- */

static heatshrink_encoder hse;
static heatshrink_decoder hsd;

static size_t compress(const uint8_t *in, size_t len, uint8_t *out, size_t max) {
  size_t sunk = 0, done = 0, n;
  heatshrink_encoder_reset(&hse);
  while (sunk < len) {
    heatshrink_encoder_sink(&hse, (uint8_t *)in + sunk, len - sunk, &n);
    sunk += n;
    if (sunk == len) heatshrink_encoder_finish(&hse);
    HSE_poll_res pres;
    do {
      pres = heatshrink_encoder_poll(&hse, out + done, max - done, &n);
      done += n;
    } while (pres == HSER_POLL_MORE && done < max);
  }
  while (heatshrink_encoder_finish(&hse) == HSER_FINISH_MORE && done < max) {
    heatshrink_encoder_poll(&hse, out + done, max - done, &n);
    done += n;
  }
  return done;
}

static size_t decompress(const uint8_t *in, size_t len, uint8_t *out, size_t max) {
  size_t sunk = 0, done = 0, n;
  heatshrink_decoder_reset(&hsd);
  while (sunk < len) {
    heatshrink_decoder_sink(&hsd, (uint8_t *)in + sunk, len - sunk, &n);
    sunk += n;
    HSD_poll_res pres;
    do {
      pres = heatshrink_decoder_poll(&hsd, out + done, max - done, &n);
      done += n;
    } while (pres == HSDR_POLL_MORE && done < max);
  }
  while (heatshrink_decoder_finish(&hsd) == HSDR_FINISH_MORE && done < max) {
    heatshrink_decoder_poll(&hsd, out + done, max - done, &n);
    done += n;
  }
  return done;
}

static void worker_task(void *arg) {
  struct job j;
  static uint8_t packed[96], unpacked[96];
  (void)arg;
  xEventGroupWaitBits(events, EV_FS_READY, pdFALSE, pdTRUE, portMAX_DELAY);
  crypto_setup();
  for (;;) {
    if (xQueueReceive(jobs, &j, portMAX_DELAY) != pdTRUE) continue;
    switch (j.kind) {
      case JOB_HASH:
      case JOB_SIGN:
        crypto_job(&j);
        break;
      case JOB_COMPRESS: {
        size_t c = compress(j.data, j.length, packed, sizeof packed);
        size_t d = decompress(packed, c, unpacked, sizeof unpacked);
        log_line("lz", "%u -> %u -> %u%s", (unsigned)j.length, (unsigned)c, (unsigned)d,
                 d == j.length && !memcmp(unpacked, j.data, d) ? "" : " MISMATCH");
        break;
      }
      case JOB_STORE:
        if (fs_write_file(j.path, j.data, j.length) < 0) log_line("fs", "write %s failed", j.path);
        break;
    }
  }
}

/* ---- network: lwIP ---- */

static struct netif eth;
static struct udp_pcb *echo_pcb;
static struct tcp_pcb *service_pcb;
static mqtt_client_t *mqtt;
static uint8_t peer_key[32];

static err_t eth_output(struct netif *netif, struct pbuf *p) {
  static uint8_t frame[1536];
  size_t len = pbuf_copy_partial(p, frame, sizeof frame, 0);
  (void)netif;
  LINK_STATS_INC(link.xmit);
  return board_mac_send(frame, len) ? ERR_IF : ERR_OK;
}

static err_t eth_init(struct netif *netif) {
  netif->name[0] = 'e';
  netif->name[1] = '0';
  netif->hostname = "fwkit";
  netif->mtu = 1500;
  netif->hwaddr_len = ETH_HWADDR_LEN;
  board_mac_address(netif->hwaddr);
  netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP | NETIF_FLAG_IGMP;
  netif->output = etharp_output;
  netif->linkoutput = eth_output;
  return ERR_OK;
}

void mac_rx_isr(void) {
  BaseType_t woken = pdFALSE;
  xEventGroupSetBitsFromISR(events, EV_MAC_RX, &woken);
  portYIELD_FROM_ISR(woken);
}

static void eth_poll(void) {
  static uint8_t frame[1536];
  size_t len;
  while ((len = board_mac_receive(frame, sizeof frame)) != 0) {
    struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_POOL);
    if (!p) {
      LINK_STATS_INC(link.memerr);
      break;
    }
    pbuf_take(p, frame, (u16_t)len);
    if (eth.input(p, &eth) != ERR_OK) pbuf_free(p);
  }
}

static void echo_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port) {
  (void)arg;
  if (p->tot_len >= 72) {
    static uint8_t in[256], plain[256];
    u16_t n = pbuf_copy_partial(p, in, sizeof in, 0);
    int len = open_message(plain, in, n);
    if (len > 0) {
      struct job j = {.kind = JOB_STORE};
      strncpy(j.path, "/log/udp", sizeof j.path);
      j.length = (uint16_t)(len > (int)sizeof j.data ? sizeof j.data : (size_t)len);
      memcpy(j.data, plain, j.length);
      xQueueSend(jobs, &j, 0);
    }
  }
  udp_sendto(pcb, p, addr, port);
  pbuf_free(p);
}

struct session {
  uint16_t received;
  uint8_t state;
  char line[64];
};

static err_t service_sent(void *arg, struct tcp_pcb *pcb, u16_t len) {
  (void)arg;
  (void)pcb;
  (void)len;
  return ERR_OK;
}

static void service_reply(struct tcp_pcb *pcb, const char *text) {
  tcp_write(pcb, text, (u16_t)strlen(text), TCP_WRITE_FLAG_COPY);
  tcp_output(pcb);
}

static err_t service_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
  struct session *s = arg;
  struct pbuf *q;
  if (!p || err != ERR_OK) {
    if (p) pbuf_free(p);
    mem_free(s);
    tcp_arg(pcb, NULL);
    tcp_close(pcb);
    return ERR_OK;
  }
  for (q = p; q; q = q->next) {
    const char *c = q->payload;
    u16_t i;
    for (i = 0; i < q->len; i++) {
      if (c[i] == '\n' || s->received + 1 >= sizeof s->line) {
        s->line[s->received] = 0;
        if (!strcmp(s->line, "status")) service_reply(pcb, "ok\n");
        else if (!strncmp(s->line, "get ", 4)) {
          char buf[48];
          int n = fs_read_file(s->line + 4, buf, sizeof buf - 1);
          buf[n < 0 ? 0 : n] = 0;
          service_reply(pcb, n < 0 ? "error\n" : buf);
        } else service_reply(pcb, "?\n");
        s->received = 0;
      } else {
        s->line[s->received++] = c[i];
      }
    }
  }
  tcp_recved(pcb, p->tot_len);
  pbuf_free(p);
  return ERR_OK;
}

static void service_error(void *arg, err_t err) {
  (void)err;
  if (arg) mem_free(arg);
}

static err_t service_accept(void *arg, struct tcp_pcb *pcb, err_t err) {
  struct session *s;
  (void)arg;
  if (err != ERR_OK) return err;
  s = mem_malloc(sizeof *s);
  if (!s) return ERR_MEM;
  memset(s, 0, sizeof *s);
  tcp_arg(pcb, s);
  tcp_recv(pcb, service_recv);
  tcp_sent(pcb, service_sent);
  tcp_err(pcb, service_error);
  service_reply(pcb, "fwkit ready\n");
  return ERR_OK;
}

static void mqtt_connected(mqtt_client_t *client, void *arg, mqtt_connection_status_t status) {
  (void)arg;
  if (status == MQTT_CONNECT_ACCEPTED) {
    mqtt_subscribe(client, "fwkit/cmd", 1, NULL, NULL);
    mqtt_publish(client, "fwkit/status", "online", 6, 1, 1, NULL, NULL);
  } else {
    log_line("mqtt", "refused (%d)", (int)status);
  }
}

static void mqtt_topic(void *arg, const char *topic, u32_t total) {
  (void)arg;
  log_line("mqtt", "%s (%lu bytes)", topic, (unsigned long)total);
}

static void mqtt_data(void *arg, const u8_t *data, u16_t len, u8_t flags) {
  struct job j = {.kind = JOB_HASH};
  (void)arg;
  (void)flags;
  j.length = len > sizeof j.data ? sizeof j.data : len;
  memcpy(j.data, data, j.length);
  xQueueSend(jobs, &j, 0);
}

static void broker_found(const char *name, const ip_addr_t *addr, void *arg) {
  struct mqtt_connect_client_info_t ci = {.client_id = "fwkit", .keep_alive = 60, .will_topic = "fwkit/status",
                                          .will_msg = "offline", .will_qos = 1, .will_retain = 1};
  (void)arg;
  if (!addr) {
    log_line("dns", "%s not found", name);
    return;
  }
  mqtt_set_inpub_callback(mqtt, mqtt_topic, mqtt_data, NULL);
  mqtt_client_connect(mqtt, addr, MQTT_PORT, mqtt_connected, NULL, &ci);
}

static void link_changed(struct netif *netif) {
  if (netif_is_up(netif) && !ip4_addr_isany_val(*netif_ip4_addr(netif))) {
    log_line("net", "address %s", ip4addr_ntoa(netif_ip4_addr(netif)));
    xEventGroupSetBits(events, EV_NET_UP);
  }
}

u32_t sys_now(void) { return (u32_t)xTaskGetTickCount() * portTICK_PERIOD_MS; }

static void net_task(void *arg) {
  ip_addr_t broker;
  (void)arg;
  lwip_init();
  netif_add(&eth, IP4_ADDR_ANY4, IP4_ADDR_ANY4, IP4_ADDR_ANY4, NULL, eth_init, ethernet_input);
  netif_set_default(&eth);
  netif_set_status_callback(&eth, link_changed);
  netif_set_up(&eth);
  dhcp_start(&eth);
  echo_pcb = udp_new();
  udp_bind(echo_pcb, IP4_ADDR_ANY, 7);
  udp_recv(echo_pcb, echo_recv, NULL);
  service_pcb = tcp_new();
  tcp_bind(service_pcb, IP4_ADDR_ANY, 23);
  service_pcb = tcp_listen(service_pcb);
  tcp_accept(service_pcb, service_accept);
  sntp_setoperatingmode(SNTP_OPMODE_POLL);
  sntp_setservername(0, "pool.ntp.org");
  mqtt = mqtt_client_new();
  for (;;) {
    EventBits_t bits = xEventGroupWaitBits(events, EV_MAC_RX | EV_SHUTDOWN, pdTRUE, pdFALSE, pdMS_TO_TICKS(50));
    if (bits & EV_SHUTDOWN) break;
    if (bits & EV_MAC_RX) eth_poll();
    if ((xEventGroupGetBits(events) & EV_NET_UP) && !sntp_enabled()) {
      sntp_init();
      if (dns_gethostbyname("broker.local", &broker, broker_found, NULL) == ERR_OK)
        broker_found("broker.local", &broker, NULL);
    }
    netif_poll_all();
    sys_check_timeouts();
  }
  dhcp_release_and_stop(&eth);
  netif_set_down(&eth);
  vTaskDelete(NULL);
}

/* ---- shell ---- */

struct command {
  const char *name;
  const char *help;
  int (*run)(int argc, char **argv);
};
static int cmd_help(int argc, char **argv);

static void print_entry(const struct lfs_info *info, void *arg) {
  (void)arg;
  printf("%c %6lu %s\n", info->type == LFS_TYPE_DIR ? 'd' : '-', (unsigned long)info->size, info->name);
}

static int cmd_ls(int argc, char **argv) { return fs_list(argc > 1 ? argv[1] : "/", print_entry, NULL) < 0; }

static int cmd_cat(int argc, char **argv) {
  char buf[64];
  int n, i;
  if (argc < 2) return 1;
  n = fs_read_file(argv[1], buf, sizeof buf);
  for (i = 0; i < n; i++) putchar(isprint((unsigned char)buf[i]) ? buf[i] : '.');
  putchar('\n');
  return n < 0;
}

static int cmd_rm(int argc, char **argv) {
  int err;
  if (argc < 2) return 1;
  xSemaphoreTake(fs_lock, portMAX_DELAY);
  err = lfs_remove(&lfs, argv[1]);
  xSemaphoreGive(fs_lock);
  return err < 0;
}

static int queue_job(int kind, int argc, char **argv) {
  struct job j;
  size_t len;
  if (argc < 2) return 1;
  memset(&j, 0, sizeof j);
  j.kind = kind;
  len = strlen(argv[1]);
  j.length = (uint16_t)(len > sizeof j.data ? sizeof j.data : len);
  memcpy(j.data, argv[1], j.length);
  if (argc > 2) strncpy(j.path, argv[2], sizeof j.path - 1);
  return xQueueSend(jobs, &j, pdMS_TO_TICKS(100)) != pdTRUE;
}

static int cmd_hash(int argc, char **argv) { return queue_job(JOB_HASH, argc, argv); }
static int cmd_sign(int argc, char **argv) { return queue_job(JOB_SIGN, argc, argv); }
static int cmd_lz(int argc, char **argv) { return queue_job(JOB_COMPRESS, argc, argv); }
static int cmd_write(int argc, char **argv) {
  if (argc < 3) return 1;
  return queue_job(JOB_STORE, argc, argv);
}

static int cmd_seal(int argc, char **argv) {
  uint8_t out[128];
  char text[33];
  size_t n;
  if (argc < 2) return 1;
  n = seal_message(out, sizeof out, peer_key, argv[1], strlen(argv[1]));
  hex_string(text, out + 56, 16);
  printf("%u bytes, tag %s\n", (unsigned)n, text);
  return n == 0;
}

static int cmd_ps(int argc, char **argv) {
  static char buf[512];
  (void)argc;
  (void)argv;
  vTaskList(buf);
  puts(buf);
  printf("heap: %u free, %u minimum\n", (unsigned)xPortGetFreeHeapSize(), (unsigned)xPortGetMinimumEverFreeHeapSize());
  return 0;
}

static int cmd_net(int argc, char **argv) {
  (void)argc;
  (void)argv;
  printf("%s %s\n", netif_is_up(&eth) ? "up" : "down", ip4addr_ntoa(netif_ip4_addr(&eth)));
  stats_display();
  return 0;
}

static int cmd_time(int argc, char **argv) {
  unsigned long t = wall_clock + xTaskGetTickCount() / configTICK_RATE_HZ;
  (void)argc;
  (void)argv;
  printf("%lu.%02lu:%02lu:%02lu\n", t / 86400, t / 3600 % 24, t / 60 % 60, t % 60);
  return 0;
}

static int cmd_reboot(int argc, char **argv) {
  (void)argc;
  (void)argv;
  xEventGroupSetBits(events, EV_SHUTDOWN);
  vTaskDelay(pdMS_TO_TICKS(200));
  board_reset();
}

static const struct command commands[] = {
    {"help", "list commands", cmd_help},
    {"ls", "ls [dir]", cmd_ls},
    {"cat", "cat <file>", cmd_cat},
    {"rm", "rm <file>", cmd_rm},
    {"write", "write <text> <file>", cmd_write},
    {"hash", "hash <text>", cmd_hash},
    {"sign", "sign <text>", cmd_sign},
    {"lz", "lz <text>", cmd_lz},
    {"seal", "seal <text>", cmd_seal},
    {"ps", "tasks and heap", cmd_ps},
    {"net", "network status", cmd_net},
    {"time", "uptime and clock", cmd_time},
    {"reboot", "restart", cmd_reboot},
};

static int cmd_help(int argc, char **argv) {
  size_t i;
  (void)argc;
  (void)argv;
  for (i = 0; i < sizeof commands / sizeof commands[0]; i++) printf("  %-8s %s\n", commands[i].name, commands[i].help);
  return 0;
}

static int split_args(char *line, char **argv, int max) {
  int argc = 0;
  while (*line && argc < max) {
    while (isspace((unsigned char)*line)) *line++ = 0;
    if (!*line) break;
    argv[argc++] = line;
    while (*line && !isspace((unsigned char)*line)) line++;
  }
  return argc;
}

static int command_compare(const void *key, const void *entry) {
  return strcmp(key, ((const struct command *)entry)->name);
}

static void shell_execute(char *line) {
  char *argv[6];
  int argc = split_args(line, argv, 6);
  const struct command *c;
  size_t i;
  if (argc == 0) return;
  c = NULL;
  for (i = 0; i < sizeof commands / sizeof commands[0]; i++)
    if (!strcmp(commands[i].name, argv[0])) c = &commands[i];
  if (!c) c = bsearch(argv[0], commands + 1, 0, sizeof *c, command_compare);
  if (!c) {
    printf("unknown command: %s\n", argv[0]);
    return;
  }
  if (c->run(argc, argv)) printf("%s: failed\n", argv[0]);
}

static void shell_task(void *arg) {
  static char line[80];
  size_t len = 0;
  (void)arg;
  xEventGroupWaitBits(events, EV_FS_READY, pdFALSE, pdTRUE, portMAX_DELAY);
  puts("fwkit shell; 'help' lists commands");
  for (;;) {
    char c;
    if (xStreamBufferReceive(uart_rx, &c, 1, portMAX_DELAY) != 1) continue;
    if (c == '\r' || c == '\n') {
      putchar('\n');
      line[len] = 0;
      shell_execute(line);
      len = 0;
      printf("> ");
    } else if ((c == 8 || c == 127) && len) {
      len--;
      printf("\b \b");
    } else if (isprint((unsigned char)c) && len + 1 < sizeof line) {
      line[len++] = c;
      putchar(c);
    }
  }
}

/* ---- housekeeping ---- */

static TimerHandle_t watchdog_timer, stats_timer;

static void watchdog_kick(TimerHandle_t t) {
  (void)t;
  WDT_KICK = 0x5a5a;
}

static void stats_report(TimerHandle_t t) {
  (void)t;
  log_line("stats", "heap %u, tasks %u, events %lx", (unsigned)xPortGetFreeHeapSize(),
           (unsigned)uxTaskGetNumberOfTasks(), (unsigned long)xEventGroupGetBits(events));
}

void vApplicationIdleHook(void) { WDT_KICK = 0x1d1e; }
void vApplicationTickHook(void) {}
void vApplicationMallocFailedHook(void) { fw_panic("out of memory"); }
void vApplicationStackOverflowHook(TaskHandle_t task, char *name) {
  (void)task;
  printf("stack overflow in %s\n", name);
  fw_panic("stack");
}

int main(void) {
  printf("fwkit %s (%s)\n", "1.0", BOARD_NAME);
  console_lock = xSemaphoreCreateMutex();
  fs_lock = xSemaphoreCreateRecursiveMutex() ? xSemaphoreCreateMutex() : NULL;
  events = xEventGroupCreate();
  jobs = xQueueCreate(4, sizeof(struct job));
  uart_rx = xStreamBufferCreate(64, 1);
  if (!console_lock || !fs_lock || !events || !jobs || !uart_rx) fw_panic("init");
  xTaskCreate(fs_task, "fs", configMINIMAL_STACK_SIZE * 4, NULL, 3, NULL);
  xTaskCreate(worker_task, "work", configMINIMAL_STACK_SIZE * 6, NULL, 2, NULL);
  xTaskCreate(net_task, "net", configMINIMAL_STACK_SIZE * 4, NULL, 2, NULL);
  xTaskCreate(shell_task, "shell", configMINIMAL_STACK_SIZE * 3, NULL, 1, NULL);
  watchdog_timer = xTimerCreate("wdt", pdMS_TO_TICKS(500), pdTRUE, NULL, watchdog_kick);
  stats_timer = xTimerCreate("stats", pdMS_TO_TICKS(60000), pdTRUE, NULL, stats_report);
  xTimerStart(watchdog_timer, 0);
  xTimerStart(stats_timer, 0);
  vTaskStartScheduler();
  fw_panic("scheduler returned");
}
