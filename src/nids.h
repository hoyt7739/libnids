/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
  See the file COPYING for license details.
*/

#ifndef _NIDS_NIDS_H
#define _NIDS_NIDS_H

#ifdef _WINDOWS
#include <sys/timeb.h>
#include <time.h>
#include <winsock2.h>
#define SYSLOG(l, ...) printf(__VA_ARGS__)
#else
#include <sys/types.h>
#define SYSLOG syslog
#endif
#include <pcap.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define NIDS_MAJOR 1
#define NIDS_MINOR 26

#ifdef _WINDOWS
#ifdef NIDS_EXPORTS
#define NIDS_API __declspec(dllexport)
#else
#define NIDS_API __declspec(dllimport)
#endif
#else
#define NIDS_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum
{
  NIDS_WARN_IP = 1,
  NIDS_WARN_TCP,
  NIDS_WARN_UDP,
  NIDS_WARN_SCAN
};

enum
{
  NIDS_WARN_UNDEFINED = 0,
  NIDS_WARN_IP_OVERSIZED,
  NIDS_WARN_IP_INVLIST,
  NIDS_WARN_IP_OVERLAP,
  NIDS_WARN_IP_HDR,
  NIDS_WARN_IP_SRR,
  NIDS_WARN_TCP_TOOMUCH,
  NIDS_WARN_TCP_HDR,
  NIDS_WARN_TCP_BIGQUEUE,
  NIDS_WARN_TCP_BADFLAGS
};

#define NIDS_JUST_EST 1
#define NIDS_DATA 2
#define NIDS_CLOSE 3
#define NIDS_RESET 4
#define NIDS_TIMED_OUT 5
#define NIDS_EXITING   6	/* nids is exiting; last chance to get data */
#ifdef ENABLE_TCPREASM
#define NIDS_RESUME 7
#endif

#define NIDS_DO_CHKSUM  0
#define NIDS_DONT_CHKSUM 1

#ifdef ENABLE_TCPREASM
#define NIDS_TCP_RESUME_NONE   0
#define NIDS_TCP_RESUME_CLIENT 1
#define NIDS_TCP_RESUME_SERVER 2
#endif

struct tuple4
{
  u_short source;
  u_short dest;
  u_int saddr;
  u_int daddr;
};

struct half_stream
{
  char state;
#ifdef ENABLE_TCPREASM
  char resume_second_half;
#endif
  
  char collect;
  char collect_urg;

  char *data;
  int offset;
  int count;
  int count_new;
  int bufsize;
  int rmem_alloc;

  int urg_count;
  u_int acked;
  u_int seq;
  u_int ack_seq;
  u_int first_data_seq;
  u_char urgdata;
  u_char count_new_urg;
  u_char urg_seen;
  u_int urg_ptr;
  u_short window;
  u_char ts_on;
  u_char wscale_on;
  u_int curr_ts; 
  u_int wscale;
  struct skbuff *list;
  struct skbuff *listtail;
};

struct tcp_stream
{
  struct tuple4 addr;
  char nids_state;
  struct lurker_node *listeners;
  struct half_stream client;
  struct half_stream server;
  struct tcp_stream *next_node;
  struct tcp_stream *prev_node;
  int hash_index;
  struct tcp_stream *next_time;
  struct tcp_stream *prev_time;
  int read;
  struct tcp_stream *next_free;
  void *user;
  long ts;
};

struct nids_prm
{
  int n_tcp_streams;
  int n_hosts;
  char *device;
  char *filename;
  int sk_buff_size;
  int dev_addon;
  void (*syslog) ();
  int syslog_level;
  int scan_num_hosts;
  int scan_delay;
  int scan_num_ports;
  void (*no_mem) (char *);
  int (*ip_filter) ();
  char *pcap_filter;
  int promisc;
  int one_loop_less;
  int pcap_timeout;
  int multiproc;
  int queue_limit;
  int tcp_workarounds;
  pcap_t *pcap_desc;
#ifdef ENABLE_TCPREASM
  int tcp_resume_wscale;
#endif
  int tcp_flow_timeout;
};

struct tcp_timeout
{
  struct tcp_stream *a_tcp;
  struct timeval timeout;
  struct tcp_timeout *next;
  struct tcp_timeout *prev;
};

struct nids_chksum_ctl
{
  u_int netaddr;
  u_int mask;
  u_int action;
  u_int reserved;
};

NIDS_API int nids_init (void);
NIDS_API void nids_register_ip_frag (void (*));
NIDS_API void nids_unregister_ip_frag (void (*));
NIDS_API void nids_register_ip (void (*));
NIDS_API void nids_unregister_ip (void (*));
NIDS_API void nids_register_tcp (void (*));
NIDS_API void nids_unregister_tcp (void (*x));
#ifdef ENABLE_TCPREASM
NIDS_API void nids_register_tcp_resume (void (*));
NIDS_API void nids_unregister_tcp_resume (void (*x));
#endif
NIDS_API void nids_register_udp (void (*));
NIDS_API void nids_unregister_udp (void (*));
NIDS_API void nids_killtcp (struct tcp_stream *);
NIDS_API void nids_discard (struct tcp_stream *, int);
NIDS_API int nids_run (void);
NIDS_API void nids_exit(void);
NIDS_API int nids_getfd (void);
NIDS_API int nids_dispatch (int);
NIDS_API int nids_next (void);
NIDS_API void nids_pcap_handler(u_char *, struct pcap_pkthdr *, u_char *);
NIDS_API struct tcp_stream *nids_find_tcp_stream(struct tuple4 *);
NIDS_API void nids_free_tcp_stream(struct tcp_stream *);
NIDS_API void nids_register_chksum_ctl(struct nids_chksum_ctl *, int);

NIDS_API extern struct nids_prm nids_params;
NIDS_API extern char *nids_warnings[];
NIDS_API extern char nids_errbuf[];
NIDS_API extern struct pcap_pkthdr *nids_last_pcap_header;
NIDS_API extern u_char *nids_last_pcap_data;
NIDS_API extern u_int nids_linkoffset;
NIDS_API extern struct tcp_timeout *nids_tcp_timeouts;

#ifdef __cplusplus
}
#endif

#endif /* _NIDS_NIDS_H */
