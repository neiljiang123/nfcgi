/* ********************************************************** */
/* -*- nfcgi-protocol.h -*- FastCGI Protocol Definitions  -*- */
/* ********************************************************** */
/* Tyler Besselman (C) September 2023, licensed under GPLv2   */
/* ********************************************************** */

#ifndef __NFCGI_PROTOCOL__
#define __NFCGI_PROTOCOL__ 1

#include <string.h>
#include <stdint.h>
#include <stdlib.h>

// There is currently only 1 FCGI version. Given that it's from the 90s, this will probably remain true.
#define FCGI_VERSION_CURRENT    FCGI_VERSION_1
#define FCGI_VERSION_1          1

// Initialize a new fcgi_record_t struct with the passed values.
#define FCGI_RECORD_INIT(type, request_id, content_length, padding_length)      \
    ((fcgi_record_t){                                                           \
        .version = FCGI_VERSION_CURRENT,                                        \
        .type = (type),                                                         \
        .requestId = (request_id),                                              \
        .contentLength = (content_length),                                      \
        .paddingLength = (padding_length)                                       \
    })

// FCGI suggests we pad to 8 bytes, pass a content length to get how much padding to include.
#define FCGI_PAD_FOR(content_length) (((content_length) + 7) & (~7))

// These come off the wire in big endian.
typedef struct fcgi_record {
    uint8_t  version;       /* FCGI protocol version */
    uint8_t  type;          /* Record type */
    uint16_t requestId;     /* Request Id (0 --> management request) */
    uint16_t contentLength; /* Record content size */
    uint8_t  paddingLength; /* Record padding size */
    uint8_t  _reserved;
} fcgi_record_t;

// All the currently known record types.
typedef enum fcgi_record_type {
    FCGI_RECORD_BEGIN_REQUEST   = 1,  /* (ws --> app) [app] Start a new request */
    FCGI_RECORD_ABORT_REQUEST   = 2,  /* (ws --> app) [app] Abort a currently processing request */
    FCGI_RECORD_END_REQUEST     = 3,  /* (app --> ws) [app] End a currently processing request */
    FCGI_RECORD_PARAMS          = 4,  /* (ws --> app) [app] Send request parameters */
    FCGI_RECORD_STDIN           = 5,  /* (ws --> app) [app] Send request data */
    FCGI_RECORD_STDOUT          = 6,  /* (app --> ws) [app] Send response data */
    FCGI_RECORD_STDERR          = 7,  /* (app --> ws) [app] Send any error data */
    FCGI_RECORD_DATA            = 8,  /* (ws --> app) [app] Send file data (filter role) */
    FCGI_RECORD_GET_VALUES      = 9,  /* (ws --> app) [mng] Request FCGI parameters */
    FCGI_RECORD_VALUES          = 10, /* (app --> ws) [mng] Return FCGI parameters */
    FCGI_RECORD_UNKNOWN_TYPE    = 11  /* (app --> ws) [mng] Received unknown record */
} fcgi_record_type_t;

/* Begin Request Body */

typedef struct fcgi_body_begin_request {
    uint16_t role; /* Which role is this request for? */
    uint8_t flags; /* Request flags; currently only one exists. */
    uint8_t _reserved[5];
} fcgi_body_begin_request_t;

// We only support the responder role here; I think nginx also only supports responder.
typedef enum fcgi_role {
    FCGI_ROLE_RESPONDER     = 1, /* Get full HTTP request, send response */
    FCGI_ROLE_AUTHORIZER    = 2, /* Get full HTTP request, decide if "authorized" or not */
    FCGI_ROLE_FILTER        = 3  /* Get full HTTP request + data from a file, sends HTTP response by "filtering" file data */
} fcgi_role_t;

// Should we reuse our connection (socket)?
#define FCGI_FLAG_KEEP_ALIVE    (1 << 0)

/* End Request Body */

typedef struct fcgi_body_end_request {
    uint32_t appStatus;     // What would this program exit with?
    uint8_t protocolStatus; // Protocol status code
    uint8_t _reserved[3];
} fcgi_body_end_request_t;

typedef enum fcgi_status {
    FCGI_STATUS_REQUEST_COMPLETE = 0, /* Request completed successfully */
    FCGI_STATUS_CANT_MPX         = 1, /* Can't multiplex multiple requests over single connection */
    FCGI_STATUS_OVERLOADED       = 2, /* Out of resources */
    FCGI_STATUS_UNKNOWN_ROLE     = 3  /* Request for unsupported role */
} fcgi_status_t;

/* Unknown Type Body */

typedef struct fcgi_body_unknown_type {
    uint8_t type; // What type of record is unknown?
    uint8_t _reserved[7];
} fcgi_body_unknown_type_t;

/* Core protocol functions */

// This function assumes at least 4 bytes left in buffer.
extern uint32_t fcgi_length_decode(const void *buffer, size_t *consumed);
extern size_t fcgi_length_encode(uint32_t length, void *buffer);

// Record header send/receive functions.
extern ssize_t fcgi_receive_next_record(const int socket, fcgi_record_t *record);
extern int fcgi_send_next_record(const int socket, const uint8_t type, const uint16_t request_id, const uint16_t content_length, const uint8_t padding_length);

// Receiving full records
extern ssize_t fcgi_receive_full_record_buffered(const int socket, fcgi_record_t *record, void *buffer, const size_t buffer_length);
extern int fcgi_receive_full_record(const int socket, fcgi_record_t *record, const void **data);

// Sending full records
extern int fcgi_send_full_record(const int socket, const uint8_t type, const uint16_t request_id, const void *buffer, const uint16_t content_length);

/* Record helper functions */

// Sending stdout records
extern int fcgi_send_stdout_record(const int socket, const uint16_t request_id, const void *data, size_t length);
#define fcgi_send_stdout_string(sock, req_id, str) fcgi_send_stdout_record((sock), (req_id), (str), strlen(str))
#define fcgi_send_close_stdout(sock, req_id) fcgi_send_stdout_record((sock), (req_id), NULL, 0)

// Sending stderr records
extern int fcgi_send_stderr_record(const int socket, const uint16_t request_id, const void *data, size_t length);
#define fcgi_send_stderr_string(sock, req_id, str) fcgi_send_stderr_record((sock), (req_id), (str), strlen(str))
#define fcgi_send_close_stderr(sock, req_id) fcgi_send_stderr_record((sock), (req_id), NULL, 0)

// Send request end record
extern int fcgi_send_end_record(const int socket, const uint32_t status, const fcgi_status_t fcgi_status, const uint16_t request_id);

// Respond to unknown record type
extern int fcgi_send_unknown_record(const int socket, const uint8_t type, const uint16_t request_id);

#endif /* !defined(__NFCGI_PROTOCOL__) */
