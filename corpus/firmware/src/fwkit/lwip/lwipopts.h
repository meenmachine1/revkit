/* lwIP options for fwkit: raw API, no OS (the network task polls). */
#ifndef LWIPOPTS_H
#define LWIPOPTS_H

#define NO_SYS                  1
#define SYS_LIGHTWEIGHT_PROT    0
#define LWIP_SOCKET             0
#define LWIP_NETCONN            0
#define LWIP_IPV4               1
#define LWIP_IPV6               0
#define LWIP_ARP                1
#define LWIP_ETHERNET           1
#define LWIP_ICMP               1
#define LWIP_RAW                1
#define LWIP_UDP                1
#define LWIP_TCP                1
#define LWIP_DHCP               1
#define LWIP_AUTOIP             0
#define LWIP_ACD                1
#define LWIP_DNS                1
#define LWIP_IGMP               1
#define LWIP_HAVE_LOOPIF        1
#define LWIP_NETIF_LOOPBACK     1
#define LWIP_NETIF_STATUS_CALLBACK 1
#define LWIP_NETIF_LINK_CALLBACK   1
#define LWIP_NETIF_HOSTNAME     1
#define LWIP_ALTCP              1
#define LWIP_STATS              1
#define LWIP_STATS_DISPLAY      1
#define IP_REASSEMBLY           1
#define IP_FRAG                 1

#define MEM_ALIGNMENT           4
#ifdef __AVR__
#define MEM_SIZE                2048
#define PBUF_POOL_SIZE          4
#define TCP_MSS                 256
#else
#define MEM_SIZE                (16 * 1024)
#define PBUF_POOL_SIZE          16
#define TCP_MSS                 1460
#endif
#define MEMP_NUM_TCP_PCB        4
#define MEMP_NUM_UDP_PCB        6
#define MEMP_NUM_SYS_TIMEOUT    (LWIP_NUM_SYS_TIMEOUT_INTERNAL + 4)
#define TCP_WND                 (4 * TCP_MSS)
#define TCP_SND_BUF             (4 * TCP_MSS)

#define SNTP_SERVER_DNS         1
#define SNTP_SET_SYSTEM_TIME(sec) fw_set_time(sec)
void fw_set_time(unsigned long sec);
#define MQTT_OUTPUT_RINGBUF_SIZE 256

#define LWIP_RAND()             ((u32_t)rand())
int rand(void);

#endif
