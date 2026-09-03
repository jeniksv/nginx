
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_H_INCLUDED_
#define _NGX_EVENT_QUIC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#if (NGX_QUICHE)
#include "quiche.h"
#endif

#define NGX_QUIC_MODULE                      0x43495551   /* "QUIC" */

#if (OPENSSL_VERSION_NUMBER >= 0x30500010L)
#define NGX_QUIC_OPENSSL_API                 1

#elif (defined SSL_R_MISSING_QUIC_TRANSPORT_PARAMETERS_EXTENSION)
#define NGX_QUIC_QUICTLS_API                 1

#elif (defined OPENSSL_IS_BORINGSSL || defined OPENSSL_IS_AWSLC               \
       || defined LIBRESSL_VERSION_NUMBER)
#define NGX_QUIC_BORINGSSL_API               1

#else
#define NGX_QUIC_BORINGSSL_API               1
#define NGX_QUIC_OPENSSL_COMPAT              1
#endif


#define NGX_QUIC_MAX_UDP_PAYLOAD_SIZE        65527

#define NGX_QUIC_DEFAULT_ACK_DELAY_EXPONENT  3
#define NGX_QUIC_DEFAULT_MAX_ACK_DELAY       25
#define NGX_QUIC_DEFAULT_HOST_KEY_LEN        32
#define NGX_QUIC_SR_KEY_LEN                  32
#define NGX_QUIC_AV_KEY_LEN                  32

#define NGX_QUIC_CID_LEN_MIN                 8
#define NGX_QUIC_CID_LEN_MAX                 20

#define NGX_QUIC_SR_TOKEN_LEN                16

#define NGX_QUIC_MIN_INITIAL_SIZE            1200

#define NGX_QUIC_STREAM_SERVER_INITIATED     0x01
#define NGX_QUIC_STREAM_UNIDIRECTIONAL       0x02


typedef ngx_int_t (*ngx_quic_init_pt)(ngx_connection_t *c);
typedef void (*ngx_quic_shutdown_pt)(ngx_connection_t *c);

typedef ngx_int_t (*ngx_quic_stream_reset_pt)(ngx_quic_stream_t *qs,
    ngx_uint_t err);
typedef ngx_int_t (*ngx_quic_stream_close_pt)(ngx_quic_stream_t *qs);
typedef ngx_int_t (*ngx_quic_stream_shutdown_pt)(ngx_connection_t *c);


typedef enum {
    NGX_QUIC_STREAM_SEND_READY = 0,
    NGX_QUIC_STREAM_SEND_SEND,
    NGX_QUIC_STREAM_SEND_DATA_SENT,
    NGX_QUIC_STREAM_SEND_DATA_RECVD,
    NGX_QUIC_STREAM_SEND_RESET_SENT,
    NGX_QUIC_STREAM_SEND_RESET_RECVD
} ngx_quic_stream_send_state_e;


typedef enum {
    NGX_QUIC_STREAM_RECV_RECV = 0,
    NGX_QUIC_STREAM_RECV_SIZE_KNOWN,
    NGX_QUIC_STREAM_RECV_DATA_RECVD,
    NGX_QUIC_STREAM_RECV_DATA_READ,
    NGX_QUIC_STREAM_RECV_RESET_RECVD,
    NGX_QUIC_STREAM_RECV_RESET_READ
} ngx_quic_stream_recv_state_e;


typedef struct {
    uint64_t                       size;
    uint64_t                       offset;
    uint64_t                       last_offset;
    ngx_chain_t                   *chain;
    ngx_chain_t                   *last_chain;
} ngx_quic_buffer_t;


typedef struct {
    ngx_ssl_t                     *ssl;

    ngx_flag_t                     retry;
    ngx_flag_t                     gso_enabled;
    ngx_flag_t                     disable_active_migration;
    ngx_msec_t                     handshake_timeout;
    ngx_msec_t                     idle_timeout;
    ngx_str_t                      host_key;
    size_t                         stream_buffer_size;
    ngx_uint_t                     max_concurrent_streams_bidi;
    ngx_uint_t                     max_concurrent_streams_uni;
    ngx_uint_t                     active_connection_id_limit;
    ngx_int_t                      stream_close_code;
    ngx_int_t                      stream_reject_code_uni;
    ngx_int_t                      stream_reject_code_bidi;

    ngx_quic_init_pt               init;
    ngx_quic_shutdown_pt           shutdown;

    u_char                         av_token_key[NGX_QUIC_AV_KEY_LEN];
    u_char                         sr_token_key[NGX_QUIC_SR_KEY_LEN];

#if (NGX_QUICHE)
    quiche_config                 *config;

    ngx_flag_t                     discover_pmtu;

    ngx_str_t                      keylog_path;

    size_t                         max_recv_udp_payload_size;
    size_t                         max_send_udp_payload_size;

    ngx_uint_t                     send_capacity_factor;

    ngx_uint_t                     congestion_control;
    ngx_flag_t                     congestion_control_pacing;
#endif
} ngx_quic_conf_t;


struct ngx_quic_stream_s {
    ngx_rbtree_node_t              node;
    ngx_queue_t                    queue;
    ngx_connection_t              *parent;
    ngx_connection_t              *connection;
    ngx_quic_stream_close_pt       close;
    ngx_quic_stream_reset_pt       reset;
    ngx_quic_stream_shutdown_pt    shutdown_send;
    ngx_quic_stream_shutdown_pt    shutdown_recv;
    uint64_t                       id;
    uint64_t                       sent;
    uint64_t                       acked;
    uint64_t                       send_max_data;
    uint64_t                       send_offset;
    uint64_t                       send_final_size;
    uint64_t                       recv_max_data;
    uint64_t                       recv_offset;
    uint64_t                       recv_window;
    uint64_t                       recv_last;
    uint64_t                       recv_final_size;
    ngx_quic_buffer_t              send;
    ngx_quic_buffer_t              recv;
    ngx_quic_stream_send_state_e   send_state;
    ngx_quic_stream_recv_state_e   recv_state;
    unsigned                       cancelable:1;
    unsigned                       fin_acked:1;
};


typedef struct {
    ngx_str_t                  name;
    const ngx_quic_backend_t  *backend;
} ngx_quic_module_t;


const ngx_quic_backend_t *ngx_quic_find_backend(ngx_cycle_t *cycle,
    ngx_str_t *name);

void ngx_quic_recvmsg(ngx_event_t *ev);
void ngx_quic_run(ngx_connection_t *c, ngx_quic_conf_t *conf);
void ngx_quic_stream_init(ngx_quic_stream_t *qs);
ngx_connection_t *ngx_quic_open_stream(ngx_connection_t *c, ngx_uint_t bidi);
void ngx_quic_finalize_connection(ngx_connection_t *c, ngx_uint_t err,
    const char *reason);
void ngx_quic_shutdown_connection(ngx_connection_t *c, ngx_uint_t err,
    const char *reason);
ngx_int_t ngx_quic_reset_stream(ngx_connection_t *c, ngx_uint_t err);
ngx_int_t ngx_quic_shutdown_stream(ngx_connection_t *c, int how);
void ngx_quic_cancelable_stream(ngx_connection_t *c);
ngx_int_t ngx_quic_get_packet_dcid(ngx_log_t *log, u_char *data, size_t len,
    ngx_str_t *dcid);
ngx_int_t ngx_quic_derive_key(ngx_log_t *log, const char *label,
    ngx_str_t *secret, ngx_str_t *salt, u_char *out, size_t len);

#if (NGX_QUICHE)
void ngx_quiche_stream_init(ngx_quic_stream_t *qs);
ngx_int_t ngx_quiche_process_control_events(ngx_connection_t *pc);
ngx_int_t ngx_quiche_process_writable_streams(ngx_connection_t *c);
ngx_int_t ngx_quiche_process_readable_streams(ngx_connection_t *c);

#if (NGX_DEBUG)
void ngx_quiche_log(const char *line, void *argp);
#endif

void ngx_quiche_config_cleanup_handler(void *data);
ngx_int_t ngx_quiche_config_new(ngx_quic_conf_t *conf);
#endif

#endif /* _NGX_EVENT_QUIC_H_INCLUDED_ */
