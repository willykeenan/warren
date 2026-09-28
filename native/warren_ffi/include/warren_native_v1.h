/* Warren native C ABI v1. Mobile packaging and application integration are separate.
 * All blocking calls run on dedicated background Dispatch queues, never main.
 * See README.md for ownership, buffers, cancellation and effect semantics. */
#ifndef WARREN_NATIVE_V1_H
#define WARREN_NATIVE_V1_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define WR_ABI_V1 1u
#define WR_MAX_IO_V1 65536u
#define WR_MAX_STREAMS_V1 32u
#define WR_MAX_OPERATIONS_V1 64u

typedef uint64_t wr_context_t;
typedef uint64_t wr_stream_t;
typedef uint64_t wr_operation_t;
typedef int32_t wr_status_t;
#define WR_OK                 ((wr_status_t)0)
#define WR_EOF                ((wr_status_t)1)
#define WR_INVALID_ARGUMENT   ((wr_status_t)-1)
#define WR_INVALID_HANDLE     ((wr_status_t)-2)
#define WR_BAD_STATE          ((wr_status_t)-3)
#define WR_BUSY               ((wr_status_t)-4)
#define WR_LIMIT              ((wr_status_t)-5)
#define WR_CANCELLED          ((wr_status_t)-6)
#define WR_DEADLINE            ((wr_status_t)-7)
#define WR_NOT_CONNECTED      ((wr_status_t)-8)
#define WR_PIN_REJECTED        ((wr_status_t)-9)
#define WR_PEER_REFUSED        ((wr_status_t)-10)
#define WR_AUTH_FAILED        ((wr_status_t)-11)
#define WR_STORAGE_UNAVAILABLE ((wr_status_t)-12)
#define WR_ALREADY_ENROLLED   ((wr_status_t)-13)
#define WR_TRANSPORT          ((wr_status_t)-14)
#define WR_INTERNAL           ((wr_status_t)-15)

/* Borrowed for the duration of a call; no NUL terminator, embedded NUL rejected. */
typedef struct { const uint8_t *ptr; uint32_t len; } wr_bytes_v1;
/* Native owner must prepare a protected, backup-excluded private app directory. */
typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    wr_bytes_v1 storage_root; /* absolute UTF-8 path, 1..1024 bytes */
    uint32_t reserved[4];    /* zero */
} wr_config_v1;
typedef struct {
    uint32_t struct_size;
    uint32_t has_relay_certificate_pin; /* exactly 0 or 1; otherwise reject */
    wr_bytes_v1 relay_https; /* 1..2048 bytes; no userinfo/fragment/query */
    wr_bytes_v1 invite;      /* 1..128 bytes; secret; never logged */
    wr_bytes_v1 node_name;   /* REQUIRED [a-z0-9-]{1,32}; no OS default name */
    uint8_t relay_certificate_sha256[32];
} wr_join_v1;
typedef struct {
    uint32_t struct_size;
    uint32_t name_len;
    uint8_t name[32];
    uint8_t noise_static_public_key[32];
    uint8_t signing_public_key[32];
    uint32_t relay_len;
    uint8_t relay_https[2048]; /* canonical configured relay; never userinfo */
} wr_public_identity_v1;
#define WR_MAY_HAVE_EFFECT_V1 1u
/* Initialize struct_size; callee initializes all remaining bytes on every path.
 * count: plaintext bytes delivered locally/read or fully enqueued write prefix.
 * value: new stream handle only for successful open, otherwise zero.
 * flags: MAY_HAVE_EFFECT means do not replay a mutation after failure/cancel.
 * Even successful writes prove local enqueue, never remote application commit. */
typedef struct {
    uint32_t struct_size;
    uint32_t flags;
    uint32_t count;
    uint32_t reserved;
    uint64_t value;
} wr_result_v1;
#define WR_STATE_STOPPED_V1  0u
#define WR_STATE_STARTING_V1 1u
#define WR_STATE_RUNNING_V1 2u
#define WR_STATE_STOPPING_V1 3u
#define WR_STATE_FAULTED_V1  4u

uint32_t wr_v1_abi_version(void);
wr_status_t wr_v1_context_create(const wr_config_v1 *config, wr_context_t *out_context);
wr_status_t wr_v1_context_state(wr_context_t context, uint32_t *out_state,
                                uint32_t *out_relay_connected);
/* No I/O: succeeds only after stop drain and release of all operations/streams. */
wr_status_t wr_v1_context_destroy(wr_context_t context);
/* Allocate before scheduling a blocking call; cancellation may win before it starts.
 * Each operation permits exactly one blocking call and belongs to one context. */
wr_status_t wr_v1_operation_create(wr_context_t context, wr_operation_t *out_operation);
wr_status_t wr_v1_operation_cancel(wr_operation_t operation); /* nonblocking */
wr_status_t wr_v1_operation_release(wr_operation_t operation); /* BUSY through the call output/cleanup epilogue */
/* Blocking calls: timeout 1..45000 ms for join; 1..30000 ms for other operations. */
wr_status_t wr_v1_join(wr_context_t context, wr_operation_t operation,
                     const wr_join_v1 *join, uint32_t timeout_ms, wr_result_v1 *out);
/* Start succeeds only after relay connection. Failed startup drains for up to
 * two additional seconds; unfinished cleanup retains STOPPING and its owner. */
wr_status_t wr_v1_start(wr_context_t context, wr_operation_t operation,
                      uint32_t timeout_ms, wr_result_v1 *out);
/* Cached public metadata after successful join/start; no secret/file serialization. */
wr_status_t wr_v1_identity_public(wr_context_t context, wr_public_identity_v1 *out);
/* Native owner verified the FULL new key out of band. No relay lookup.
 * Absent => approved; same key => explicit TOFU upgrade or approved no-op.
 * Different existing key => PIN_REJECTED; never silently replace. */
wr_status_t wr_v1_pin_approve(wr_context_t context, wr_operation_t operation,
                            wr_bytes_v1 peer, const uint8_t new_key[32],
                            uint32_t timeout_ms, wr_result_v1 *out);
/* Separate explicit local forget: exact current key required; drains matching
 * bridge streams first. Does not revoke a gateway credential or remote grant. */
wr_status_t wr_v1_pin_forget(wr_context_t context, wr_operation_t operation,
                           wr_bytes_v1 peer, const uint8_t expected_current_key[32],
                           uint32_t timeout_ms, wr_result_v1 *out);
wr_status_t wr_v1_open_private_pinned(wr_context_t context, wr_operation_t operation,
                                    wr_bytes_v1 peer, uint16_t nonzero_port,
                                    const uint8_t expected_key[32], uint32_t timeout_ms,
                                    wr_result_v1 *out);
wr_status_t wr_v1_open_gateway_pinned(wr_context_t context, wr_operation_t operation,
                                    wr_bytes_v1 peer, wr_bytes_v1 share,
                                    const uint8_t expected_key[32], uint32_t timeout_ms,
                                    wr_result_v1 *out);
/* capacity/length 1..WR_MAX_IO_V1; one read + one write/finish may run concurrently.
 * Pointers remain owned by Swift and valid until the blocking call returns. */
wr_status_t wr_v1_read(wr_stream_t stream, wr_operation_t operation,
                     uint8_t *buffer, uint32_t capacity, uint32_t timeout_ms,
                     wr_result_v1 *out);
wr_status_t wr_v1_write(wr_stream_t stream, wr_operation_t operation,
                      const uint8_t *buffer, uint32_t length, uint32_t timeout_ms,
                      wr_result_v1 *out);
wr_status_t wr_v1_finish_write(wr_stream_t stream, wr_operation_t operation,
                             uint32_t timeout_ms, wr_result_v1 *out);
/* Terminal cleanup cannot be canceled. Reset, cancel both directions, await drain.
 * On DEADLINE handle remains closing; call again only to finish cleanup. */
wr_status_t wr_v1_stream_close(wr_stream_t stream, uint32_t timeout_ms);
/* Stop invalidates/reset streams and cancels operations, then awaits core shutdown.
 * On DEADLINE context stays STOPPING; no new work or storage replacement allowed. */
wr_status_t wr_v1_stop(wr_context_t context, uint32_t timeout_ms);
#ifdef __cplusplus
}
#endif
#endif
