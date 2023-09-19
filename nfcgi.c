/* ********************************************************** */
/* -*- nfcgi.c -*- FastCGI Protocol Implementation        -*- */
/* ********************************************************** */
/* Tyler Besselman (C) September 2023, licensed under GPLv2   */
/* ********************************************************** */

#include <sys/socket.h>
#include <sys/param.h>
#include <arpa/inet.h>
#include <strings.h>
#include <limits.h>
#include <stdio.h>
#include <netdb.h>

#include "nfcgi_protocol.h"
#include "nfcgi.h"

// How much data should we read at once when skipping data from a socket?
#define SKIP_BUFFER_SIZE            4096

// How much data we allocate for request_state_t (including record data buffer)
#define REQUEST_BUFFER_SIZE         4096

// The receive buffer is placed at the end of the request struct
#define REQUEST_BUFFER(req)         (((void *)req) + sizeof(fcgi_request_t))

// We can use everything we allocate - the actual state tracking bits
#define REQUEST_BUFFER_LEN(req)     (REQUEST_BUFFER_SIZE - sizeof(fcgi_request_t))

// Make a new request struct (with receive buffer)
#define REQUEST_ALLOC()             malloc(REQUEST_BUFFER_SIZE)

static int fcgi_bind_socket(const struct addrinfo *bind_info);
static struct addrinfo *fcgi_get_host_info(const char *host, const uint16_t port);
static int fcgi_open_listening_socket(const char *host, const uint16_t port, const int backlog);

static int do_shutdown(const int socket, const int how);
static int do_recv(const int socket, void *buffer, const size_t buffer_length);
static int do_send(const int socket, const void *buffer, const size_t buffer_length);

static int fcgi_handle_get_values(const int socket, const fcgi_record_t *record, const void *buffer, const size_t buffer_length);
static int fcgi_skip_content(const int socket, const fcgi_record_t *record, const size_t already_received_length);

// 255 bytes of 0s. For record content padding.
const static uint8_t fcgi_empty_buffer[0xFF] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

// Buffer for data we don't care about.
static uint8_t fcgi_skip_buffer[SKIP_BUFFER_SIZE];

// Single library state (this library isn't thread safe)
static fcgi_lib_state_t __fcgi_lib_state = {};

// I want a pointer to this.
static fcgi_lib_state_t *const fcgi_lib_state = &__fcgi_lib_state;

/* Functions for finding a socket address, opening a socket, and binding + listening on a socket. */

// Bind a socket with the given socket info.
// Return a socket fd on success, -1 on failure.
static int fcgi_bind_socket(const struct addrinfo *bind_info)
{
    // Open a new socket.
    int _socket = socket(bind_info->ai_family, bind_info->ai_socktype, bind_info->ai_protocol);
    uint32_t enabled = 1; // For setsockopt

    if (_socket == -1)
    {
        perror("socket");
        return -1;
    }

    // Allow address reuse
    if (setsockopt(_socket, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(uint32_t)))
    {
        perror("setsockopt");
        return -1;
    }

    // Allow port reuse
    if (setsockopt(_socket, SOL_SOCKET, SO_REUSEPORT, &enabled, sizeof(uint32_t)))
    {
        perror("setsockopt");
        return -1;
    }

    // Bind the socket to the passed address
    if (bind(_socket, bind_info->ai_addr, bind_info->ai_addrlen))
    {
        perror("bind");
        return -1;
    }

    return _socket;
}

// Get the addressing info for a given (host, port) combo. Passing a NULL host will assume localhost.
// This function specifically gets info for a bind socket. The return value is allocated on the heap.
// Return NULL on failure.
static struct addrinfo *fcgi_get_host_info(const char *host, const uint16_t port)
{
    struct addrinfo *info = malloc(sizeof(struct addrinfo));
    if (!info) return NULL;

    struct addrinfo hint;
    char *port_str;

    bzero(&hint, sizeof(struct addrinfo));
    asprintf(&port_str, "%u", port);

    if (!port_str)
    {
        free(info);
        return NULL;
    }

    // I want a stream socket of whatever family matches the host address.
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_flags = AI_PASSIVE;

    int status = getaddrinfo(host, port_str, &hint, &info);
    free(port_str); // We're done with this now.

    if (status)
    {
        free(info);

        fprintf(stderr, "getaddrinfo: %s", gai_strerror(status));
        return NULL;
    }

    return info;
}

// Open a new socket listening on the passed (host, port) combo.
// Return -1 on failure, a socket fd on success.
static int fcgi_open_listening_socket(const char *host, const uint16_t port, const int backlog)
{
    struct addrinfo *bind_info = fcgi_get_host_info(host, port);

    if (!bind_info)
    {
        fprintf(stderr, "[FCGI] Failed to get host info.\n");
        return -1;
    }

    int socket = fcgi_bind_socket(bind_info);
    freeaddrinfo(bind_info);

    if (socket == -1)
    {
        fprintf(stderr, "[FCGI] Failed to bind listening socket.\n");
        return -1;
    }

    if (listen(socket, backlog))
    {
        perror("listen");
        return -1;
    }

    // I like to have this log message so I know what's going on.
    fprintf(stdout, "[FCGI] Bound socket (port: %hu)\n", port);
    return socket;
}

/* Wrappers for standard unix send, recv */

// Wrapper on recv() to ensure all bytes received.
// Return nonzero on failure.
static int do_recv(const int socket, void *buffer, const size_t buffer_length)
{
    const ssize_t bytes_received = recv(socket, buffer, buffer_length, MSG_WAITALL);

    if (bytes_received == -1) {
        perror("recv");
        return 1;
    } else if (!bytes_received && buffer_length) {
        fprintf(stderr, "[FCGI] Connection closed by remote.\n");
        return 1;
    } else if (bytes_received < buffer_length) {
        fprintf(stderr, "[FCGI] recv(): Received data length smaller than expected\n");
        return 1;
    } else {
        // Everything is ok.
        return 0;
    }
}

// Wrapper on send() to ensure all bytes sent.
// Return nonzero on failure.
static int do_send(const int socket, const void *buffer, const size_t buffer_length)
{
    const ssize_t bytes_sent = send(socket, buffer, buffer_length, 0);

    if (bytes_sent == -1) {
        perror("send");
        return 1;
    } else if (!bytes_sent && buffer_length) {
        fprintf(stderr, "[FCGI] Connection closed by remote.\n");
        return 1;
    } else if (bytes_sent < buffer_length) {
        fprintf(stderr, "[FCGI] send(): Received data length smaller than expected\n");
        return 1;
    } else {
        // Everything is ok
        return 0;
    }
}

// Wrapper on shutdown() to log errors
static int do_shutdown(const int socket, const int how)
{
    if (shutdown(socket, how))
    {
        perror("shutdown");
        return 1;
    }

    return 0;
}

/* Core protocol send/receive records and data functions. */

uint32_t fcgi_length_decode(const void *b, size_t *consumed)
{
    uint8_t *buffer = (uint8_t *)b;

    if ((*buffer) & 0x80) {
        uint32_t res  = (*buffer++) & 0x7F; res <<= 8;
                 res += (*buffer++);        res <<= 8;
                 res += (*buffer++);        res <<= 8;
                 res += (*buffer);

        (*consumed) = 4;
        return res;
    } else {
        (*consumed) = 1;
        return (*buffer);
    }
}

size_t fcgi_length_encode(uint32_t length, void *b)
{
    uint8_t *buffer = (uint8_t *)b;

    if (length > 0x7F) {
        buffer[3] = (length & 0xFF); length >>= 8;
        buffer[2] = (length & 0xFF); length >>= 8;
        buffer[1] = (length & 0xFF); length >>= 8;
        buffer[0] = (length & 0x7F) | 0x80; // Set 7th bit.

        return 4;
    } else {
        (*buffer) = length;

        return 1;
    }
}

// Note that we could batch receive a lot of these into a buffer and decode slower, but the kernel should store
//   a lot of this data cached in its TCP buffer, so it's probably fine to just issue a recv() call for each
//   record and then recv() the correct number of content bytes.
// Similarly, we let the kernel buffer send() calls for us as well.
// Basically, any further optimization here is probably not actually necessary.

// Receive an FCGI record (header only) into the provided buffer.
// This function will return the data size (content + padding) of the record, or -1 on failure.
ssize_t fcgi_receive_next_record(const int socket, fcgi_record_t *record)
{
    if (do_recv(socket, record, sizeof(fcgi_record_t))) {
        return -1; // Failed :(
    }

    if (record->version > FCGI_VERSION_CURRENT)
    {
        fprintf(stderr, "[FCGI] Received record with invalid version \"%u\"\n", record->version);
        return -1; // We can't process this version
    }

    // Byte swap these fields to host byte order.
    record->contentLength = ntohs(record->contentLength);
    record->requestId = ntohs(record->requestId);

    // Return record data length
    return (record->contentLength + record->paddingLength);
}

// Just write a record (header only) to the passed socket. We build the record for the caller
int fcgi_send_next_record(const int socket, const uint8_t type, const uint16_t request_id, const uint16_t content_length, const uint8_t padding_length)
{
    fcgi_record_t record = FCGI_RECORD_INIT(type, request_id, content_length, padding_length);

    // Byte swap these to network byte order.
    record.contentLength = htons(record.contentLength);
    record.requestId = htons(record.requestId);

    if (do_send(socket, &record, sizeof(fcgi_record_t))) {
        return 1; // Failed :(
    }

    return 0;
}

// Receive an FCGI record with data. A dynamically allocated data buffer will be returned in (*data), or NULL if this record has no data.
int fcgi_receive_full_record(const int socket, fcgi_record_t *record, const void **data)
{
    const ssize_t buffer_length = fcgi_receive_next_record(socket, record);
    if (buffer_length == -1) { return 1; }

    // We don't need to get any data.
    if (!buffer_length)
    {
        if (data) {
            (*data) = NULL;
        }

        return 0;
    }

    // Get a nice heap buffer.
    void *buffer = malloc(buffer_length);
    if (!buffer) { return 1; }

    // Actually get the data from the socket.
    if (do_recv(socket, buffer, (record->contentLength + record->paddingLength)))
    {
        free(buffer);
        return 1;
    }

    // In this one case, there is one body variable that needs to be byte-swapped.
    // Just do that here, even if it may not be the most efficient thing (this adds ~2 instructions).
    if (record->type == FCGI_RECORD_BEGIN_REQUEST)
    {
        fcgi_body_begin_request_t *body = (fcgi_body_begin_request_t *)buffer;
        body->role = ntohs(body->role);
    }

    return 0;
}

// Receive an FCGI record with content. Receive at most (*buffer_length) bytes of content.
// Return # of content bytes read, -1 on failure.
ssize_t fcgi_receive_full_record_buffered(const int socket, fcgi_record_t *record, void *buffer, const size_t buffer_length)
{
    const ssize_t data_size = fcgi_receive_next_record(socket, record);
    if (data_size == -1) { return -1; }

    // We want to receive the full request, but we may not be able to. Get as much as we can.
    ssize_t recv_count = (data_size > buffer_length) ? buffer_length : data_size;

    // Now get it.
    if (do_recv(socket, buffer, recv_count)) {
        return -1;
    }

    // In this one case, there is one body variable that needs to be byte-swapped.
    // Just do that here, even if it may not be the most efficient thing.
    if (record->type == FCGI_RECORD_BEGIN_REQUEST)
    {
        fcgi_body_begin_request_t *request_body = (fcgi_body_begin_request_t *)buffer;
        request_body->role = ntohs(request_body->role);
    }

    return recv_count;
}

// Send a record with associated content. We build the record struct for the caller.
int fcgi_send_full_record(const int socket, const uint8_t type, const uint16_t request_id, const void *buffer, const uint16_t content_length)
{
    // Figure out how many padding bytes to send.
    const uint8_t padding_length = FCGI_PAD_FOR(content_length);

    // Send record header
    if (fcgi_send_next_record(socket, type, request_id, content_length, padding_length)) {
        return 1;
    }

    // Send record content
    if (do_send(socket, buffer, content_length)) {
        return 1;
    }

    // Send record padding (we have a buffer of 0s builtin to this lib)
    if (do_send(socket, fcgi_empty_buffer, padding_length)) {
        return 1;
    }

    // Yay, it worked!
    return 0;
}

/* Helpers to send records of specific type */

int fcgi_send_stdout_record(const int socket, const uint16_t request_id, const void *data, size_t length)
{ return fcgi_send_full_record(socket, FCGI_RECORD_STDOUT, request_id, data, length); }

int fcgi_send_stderr_record(const int socket, const uint16_t request_id, const void *data, size_t length)
{ return fcgi_send_full_record(socket, FCGI_RECORD_STDERR, request_id, data, length); }

int fcgi_send_end_record(const int socket, const uint32_t status, const fcgi_status_t fcgi_status, const uint16_t request_id)
{
    fcgi_body_end_request_t body = {
        .protocolStatus = htons(fcgi_status),
        .appStatus = htons(status)
    };

    return fcgi_send_full_record(socket, FCGI_RECORD_END_REQUEST, request_id, &body, sizeof(fcgi_body_end_request_t));
}

int fcgi_send_unknown_record(const int socket, const uint8_t type, const uint16_t request_id)
{
    fcgi_body_unknown_type_t body = {
        .type = type
    };

   return fcgi_send_full_record(socket, FCGI_RECORD_UNKNOWN_TYPE, request_id, &body, sizeof(fcgi_body_unknown_type_t));
}

/* Utility to handle get values record */

static int fcgi_handle_get_values(const int socket, const fcgi_record_t *record, const void *buffer, const size_t buffer_length)
{
    // TODO: Handle this properly.

    if (fcgi_skip_content(socket, record, buffer_length)) {
        return 1;
    }

    return 1;
}

/* Utility to skip data we don't need */

// Read bytes from the socket until there is no more data.
static int fcgi_skip_content(const int socket, const fcgi_record_t *record, const size_t already_received_length)
{
    ssize_t remaining_length = (record->contentLength + record->paddingLength) - already_received_length;

    while (remaining_length)
    {
        size_t read_length = MIN(remaining_length, SKIP_BUFFER_SIZE);

        if (do_recv(socket, fcgi_skip_buffer, read_length)) {
            return 1;
        }

        remaining_length -= read_length;
    }

    return 0;
}

/* Library initialization function */

fcgi_lib_state_t *fcgi_lib_init(const fcgi_lib_config_t *config)
{
    // We can't do this right now.
    if (config->can_multiplex)
    {
        fprintf(stderr, "[FCGI] Connection multiplexing is not currently supported.\n");
        return NULL;
    }

    int listen_socket = fcgi_open_listening_socket(config->host, config->port, config->listen_backlog);
    if (listen_socket == -1) { return NULL; }

    // Populate library state object.
    memcpy(&fcgi_lib_state->config, config, sizeof(fcgi_lib_config_t));
    fcgi_lib_state->listen_socket = listen_socket;

    if (config->host)
    {
        // Duplicate this just in case the caller deallocates it.
        fcgi_lib_state->config.host = strdup(config->host);
    }

    return fcgi_lib_state;
}

void fcgi_lib_deinit(fcgi_lib_state_t *state)
{
    // Close listening socket now.
    do_shutdown(state->listen_socket, SHUT_RDWR);

    if (state->config.host)
    {
        // This was duplicated at init
        free(state->config.host);
    }
}

/* Request lifecycle functions */

// Allocate a new request struct. We can reuse these.
fcgi_request_t *fcgi_request_alloc(void)
{
    // This macro allocates enough data for a request structure + a content data buffer.
    fcgi_request_t *request = REQUEST_ALLOC();
    bzero(request, sizeof(fcgi_request_t));

    request->socket = -1;
    return request;
}

void fcgi_request_destroy(fcgi_request_t *request)
{
    // :)
    free(request);
}

// Many of these functions receive a record. Here's a macro to do that.
#define RECEIVE_RECORD(request, record, buf, buflen, recv_len, fail)                                                        \
    do {                                                                                                                    \
        (recv_len) = fcgi_receive_full_record_buffered((request)->socket, (record), (buf), (buflen));                       \
        if ((recv_len) == -1) { fail }                                                                                      \
                                                                                                                            \
        fprintf(stdout, "[FCGI] Got record from remote. Request: %hu, type: %hu\n", (record)->requestId, (record)->type);   \
        fprintf(stdout, "[FCGI] Record content length: %u (pad: %u)\n", (record)->contentLength, (record)->paddingLength);  \
    } while (0)

// Many of the below functions need to handle these requests in the same way. I add these switch cases by macro.
#define HANDLE_MANAGEMENT_RECORD(request, record, buffer, length)                                                           \
    case FCGI_RECORD_GET_VALUES: {                                                                                          \
        /* TODO: Technically, we should respond to this. */                                                                 \
        if (fcgi_handle_get_values((request)->socket, (record), (buffer), (length))) {                                      \
            fprintf(stderr, "[FCGI] Failed to handle get values record!\n");                                                \
        }                                                                                                                   \
                                                                                                                            \
        /* This function handles any excess data */                                                                         \
        continue;                                                                                                           \
    } break;                                                                                                                \
    default: {                                                                                                              \
        fprintf(stderr, "[FCGI] Got record of unknown type \"%u\"\n", (record)->type);                                      \
                                                                                                                            \
        if (fcgi_send_unknown_record((request)->socket, (record)->type, (record)->requestId))                               \
        {                                                                                                                   \
            fprintf(stderr, "[FCGI] Failed to notify server of unknown record type! (type: %u)\n", (record)->type);         \
            continue;                                                                                                       \
        }                                                                                                                   \
    } break

// This is needed in some of these functions but not all of them.
#define HANDLE_ABORT_RECORD(request, record, buffer, recv_length)                                                           \
    do {                                                                                                                    \
        /* Cancel this request and get out */                                                                               \
                                                                                                                            \
        /* If we need to keep this socket, make sure we read this record in full. */                                        \
        if ((request)->keep_alive && fcgi_skip_content((request)->socket, (record), (recv_length)))                         \
        {                                                                                                                   \
            /* If this fails, we likely can't keep anything since we don't know where the next record starts. */            \
            (request)->keep_alive = false;                                                                                  \
        }                                                                                                                   \
                                                                                                                            \
        if (fcgi_request_finalize(request, FCGI_STATUS_REQUEST_COMPLETE)) {                                                 \
            fprintf(stderr, "[FCGI] Failed to finalize aborted request!\n");                                                \
        }                                                                                                                   \
                                                                                                                            \
        /* This is considered a failure when it occurs */                                                                   \
        return 1;                                                                                                           \
    } while (0)

// Macro to skip over the content of a record which has been received partially
#define SKIP_CONTENT(request, record, received)                                                                             \
    do {                                                                                                                    \
        if (fcgi_skip_content((request)->socket, (record), (received)))                                                     \
        {                                                                                                                   \
            /* If this fails, we likely can't keep anything since we don't know where the next record starts. */            \
            (request)->keep_alive = false;                                                                                  \
                                                                                                                            \
            /* This is a failure condition. Attempt to notify the server. */                                                \
            if (fcgi_request_finalize((request), FCGI_STATUS_OVERLOADED)) {                                                 \
                fprintf(stderr, "[FCGI] Failed to finalize request!\n");                                                    \
            }                                                                                                               \
                                                                                                                            \
            return 1;                                                                                                       \
        }                                                                                                                   \
    } while (0)

// This function will block until we get a new request.
// We only get the first BEGIN record before returning.
// The request object should be gotten from the fcgi_request_alloc() function, and can be reused.
int fcgi_request_accept(fcgi_request_t *request)
{
    if (request->state != FCGI_REQUEST_STATE_INACTIVE)
    {
        fprintf(stderr, "[FCGI] Found request in wrong state when attempting to accept connection!\n");
        return 1;
    }

    // Reset this request object state.
    request->state = FCGI_REQUEST_STATE_INACTIVE;
    request->id = 0; // Invalid id
    request->_record_remaining = 0;
    request->_pad_remaining = 0;
    request->_output_finished = false;
    request->input_received = 0;

    // We don't reset param_count or params in case the client caches which parameters it would like to save.
    // This way, they don't have to reload these values on new request.

    // We may need to get a new socket.
    if (!request->keep_alive || request->socket == -1)
    {
        // These are used as arguments to accept().
        // Technically, we should add some safety here.
        struct sockaddr peer_addr;
        socklen_t peer_addrlen;

        // This line will block until a new connection is established.
        request->socket = accept(fcgi_lib_state->listen_socket, &peer_addr, &peer_addrlen);
    }

    if (request->socket == -1)
    {
        perror("socket");
        return 1;
    }

    size_t buffer_length = REQUEST_BUFFER_LEN(request);
    void *data_buffer = REQUEST_BUFFER(request);

    ssize_t received_length;
    fcgi_record_t record;

    do {
        RECEIVE_RECORD(request, &record, data_buffer, buffer_length, received_length, { goto shutdown_request; });

        switch (record.type)
        {
            case FCGI_RECORD_BEGIN_REQUEST: {
                fprintf(stdout, "[FCGI] Server sent begin request record.\n");

                if (record.contentLength < sizeof(fcgi_body_begin_request_t))
                {
                    fprintf(stderr, "[FCGI] Begin record body too small!\n");
                    goto shutdown_request;
                }

                fcgi_body_begin_request_t *body = (fcgi_body_begin_request_t *)data_buffer;

                // Take this setting even if we don't support this role.
                request->keep_alive = !!(body->flags & FCGI_FLAG_KEEP_ALIVE);

                // We only support responder role
                if (body->role != FCGI_ROLE_RESPONDER)
                {
                    fprintf(stderr, "[FCGI] Got request for unsupported role \"%u\"\n", body->role);

                    if (request->keep_alive) {
                        // Keep trying for a valid request on this connection.
                        break;
                    } else {
                        // Give up and return to the caller.
                        goto shutdown_request;
                    }
                }

                request->state = FCGI_REQUEST_STATE_STARTED;
                request->id = record.requestId;

                fprintf(stdout, "[FCGI] Began serving new request \"%hu\"\n", request->id);
            } break;
            case FCGI_RECORD_ABORT_REQUEST:
            case FCGI_RECORD_PARAMS:
            case FCGI_RECORD_STDIN:
            case FCGI_RECORD_DATA: {
                // We can't handle these yet since we haven't actually started the request.
                fprintf(stderr, "[FCGI] Ignoring misordered record of type \"%u\"", record.type);
            } break;
            HANDLE_MANAGEMENT_RECORD(request, &record, data_buffer, received_length);
        }

        if (fcgi_skip_content(request->socket, &record, received_length))
        {
            // If this fails, we likely can't keep anything since we don't know where the next record starts.
            request->keep_alive = false;

            goto shutdown_request;
        }
    } while (!request->id);

    return 0;

shutdown_request:
    if (!request->keep_alive) {
        do_shutdown(request->socket, SHUT_RDWR);
    }

    return 1;
}

// This function operates on the request->params and request->param_count variables.
// Receive request parameters. Here, we only store paramaters matching requested names.
// If a parameter is not matched, we set value_len to -1 to indicate missing.
int fcgi_request_read_params(fcgi_request_t *request)
{
    if (request->state != FCGI_REQUEST_STATE_STARTED)
    {
        fprintf(stderr, "[FCGI] Found request in wrong state when attempting to read params!\n");
        return 1;
    }

    // Reset the value length fields first. Any that remain at the end are not found.
    for (size_t i = 0; i < request->param_count; i++) {
        request->params[i].value_len = -1;
    }

    // We decrease this for each parameter we match.
    size_t unmatched_count = request->param_count;

    size_t buffer_length = REQUEST_BUFFER_LEN(request);
    void *data_buffer = REQUEST_BUFFER(request);
    ssize_t received_length;
    fcgi_record_t record;
    bool done = false;

    do {
        RECEIVE_RECORD(request, &record, data_buffer, buffer_length, received_length, { return 1; });

        if (record.requestId && record.requestId != request->id)
        {
            fprintf(stderr, "[FCGI] Got record for mismatched request id! (%hu vs %hu)\n", record.requestId, request->id);
            continue;
        }

        switch (record.type)
        {
            case FCGI_RECORD_PARAMS: {
                if (!record.contentLength)
                {
                    // This signifies that the params stream has ended, so we can skip this record and finish up.
                    done = true;
                    break;
                }

                // Hi, we read parameters here.
                size_t bytes_left = received_length;
                uint8_t *body = data_buffer;

                while (bytes_left && unmatched_count)
                {
                    if (bytes_left < 8 && ((body[0] & 0x80) | (body[1] & 0x80)))
                    {
                        if (received_length < record.contentLength) {
                            // We can keep reading. Move whatever we have left to the start of this buffer.
                            memmove(data_buffer, body, bytes_left);

                            // Get more record data
                            if (do_recv(request->socket, &data_buffer[bytes_left], buffer_length - bytes_left))
                            {
                                fprintf(stderr, "[FCGI] Failed to receive request parameters.\n");
                                return 1;
                            }

                            received_length += (buffer_length - bytes_left);
                            bytes_left = buffer_length - bytes_left;

                            // Try again
                            continue;
                        } else {
                            // We don't have any more data. We may have further records, but this case is very complicated so I don't handle it.
                            // Not even the reference implementation handles it, so I think I'm safe here.

                            fprintf(stderr, "[FCGI] Parameter record too complex!\n");
                            return 1;
                        }
                    }

                    size_t consumed = 0;

                    size_t name_len = fcgi_length_decode(body, &consumed);
                    bytes_left -= consumed;
                    body += consumed;

                    size_t value_len = fcgi_length_decode(body, &consumed);
                    bytes_left -= consumed;
                    body += consumed;

                    if (bytes_left < name_len + value_len)
                    {
                        // This goes past the end of our current buffer.
                        // TODO: Fetch more if exists
                        return 1;
                    }

                    // Grab pointers to these here
                    char *value = (char *)(body + name_len);
                    char *name = (char *)body;

                    // We will have consumed these regardless.
                    bytes_left -= (name_len + value_len);
                    body += (name_len + value_len);

                    // Do name matching
                    for (size_t i = 0; i < request->param_count; i++)
                    {
                        if (request->params[i].value_len == -1 && request->params[i].name_len == name_len)
                        {
                            if (!strncmp(request->params[i].name, name, request->params[i].name_len))
                            {
                                // We found this parameter.
                                request->params[i].value_len = value_len;

                                if (!(request->params[i].value = malloc(value_len + 1)))
                                {
                                    for (ssize_t j = i - 1; j >= 0; j--) {
                                        free(request->params[j].value);
                                    }

                                    // TODO: Do something better herre?
                                    return 1;
                                }

                                strncpy(request->params[i].value, value, value_len);
                                request->params[i].value[value_len] = 0;

                                unmatched_count--;
                            }
                        }
                    }
                }
            } break;
            case FCGI_RECORD_BEGIN_REQUEST:
            case FCGI_RECORD_STDIN: {
                // This shouldn't occur here.
                fprintf(stderr, "[FCGI] Ignoring misordered record of type \"%u\"", record.type);
            } break;
            case FCGI_RECORD_ABORT_REQUEST: HANDLE_ABORT_RECORD(request, &record, data_buffer, received_length); break;
            HANDLE_MANAGEMENT_RECORD(request, &record, data_buffer, received_length);
        }

        SKIP_CONTENT(request, &record, received_length);
    } while (!done);

    request->state = FCGI_REQUEST_STATE_READ_DATA;
    return 0;
}

// This function operates on the request->params and request->param_count variables.
// Receive request parameters. Here, we store all parameter (name, value) pairs in the order we received them (on the heap).
// Return the number of parameters stored, -1 on failure.
// Here, the caller takes ownership of the request->params pointer. It can be deleted by the fcgi_delete_params() function.
ssize_t fcgi_request_read_params_all(fcgi_request_t *request)
{
    // TODO: Implement this.
    return 1;
}

// Delete parameters read by the fcgi_read_params_all function.
void fcgi_delete_params(fcgi_request_t *request)
{
    for (size_t i = 0; i < request->param_count; i++)
    {
        // We allocate a single buffer for both names and values so we can just free this buffer only.
        free(request->params[i].name);
    }

    free(request->params);

    // The library owns these values in this case.
    request->param_count = 0;
    request->params = NULL;
}

int fcgi_read_input(fcgi_request_t *request, void *recv_buffer, const size_t recv_buffer_length)
{
    if (request->state != FCGI_REQUEST_STATE_READ_DATA)
    {
        fprintf(stderr, "[FCGI] Found request in wrong state when attempting to read input!\n");
        return 1;
    }

    off_t recv_index = 0;

    if (request->_record_remaining)
    {
        if (recv_buffer_length <= request->_record_remaining) {
            // Just read bytes out of the ongoing record.
            if (do_recv(request->socket, recv_buffer, recv_buffer_length))
            {
                fprintf(stderr, "[FCGI] Failed to resume input data receive!\n");
                return 1;
            }

            request->_record_remaining -= recv_buffer_length;

            if (!request->_record_remaining && request->_pad_remaining)
            {
                if (do_recv(request->socket, REQUEST_BUFFER(request), REQUEST_BUFFER_LEN(request)))
                {
                    fprintf(stderr, "[FCGI] Failed to resume input data receive!\n");
                    return 1;
                }

                request->_pad_remaining = 0;
            }

            return 0;
        } else {
            if (do_recv(request->socket, recv_buffer, request->_record_remaining))
            {
                fprintf(stderr, "[FCGI] Failed to resume input data receive!\n");
                return 1;
            }

            if (do_recv(request->socket, REQUEST_BUFFER(request), REQUEST_BUFFER_LEN(request)))
            {
                fprintf(stderr, "[FCGI] Failed to resume input data receive!\n");
                return 1;
            }

            // Start reading further at this index.
            recv_index = request->_record_remaining;

            request->_record_remaining = 0;
            request->_pad_remaining = 0;
        }
    }

    fcgi_record_t record;
    bool done = false;

    do {
        ssize_t data_size = fcgi_receive_next_record(request->socket, &record);
        if (data_size == -1) { return 1; }

        fprintf(stdout, "[FCGI] Got record from remote. Request: %hu, type: %hu\n", record.requestId, record.type);
        fprintf(stdout, "[FCGI] Record content length: %u (pad: %u)\n", record.contentLength, record.paddingLength);

        // We haven't got any record data yet.
        ssize_t record_received = 0;

        if (record.requestId && record.requestId != request->id)
        {
            fprintf(stderr, "[FCGI] Got record for mismatched request id! (%hu vs %hu)\n", record.requestId, request->id);
            continue;
        }

        switch (record.type)
        {
            case FCGI_RECORD_STDIN: {
                if (!record.contentLength)
                {
                    // There is no more input data.
                    done = true;
                    break;
                }

                size_t recv_remaining = (recv_buffer_length - recv_index);

                if (record.contentLength < recv_remaining) {
                    if (do_recv(request->socket, &recv_buffer[recv_index], record.contentLength))
                    {
                        fprintf(stderr, "[FCGI] Failed to receive input data!\n");
                        return 1;
                    }

                    request->input_received += record.contentLength;
                    recv_index += record.contentLength;

                    record_received = record.contentLength;
                } else {
                    // We have more content than we can store. Receive as much as we can and update request state for the rest.
                    if (do_recv(request->socket, &recv_buffer[recv_index], recv_remaining))
                    {
                        fprintf(stderr, "[FCGI] Failed to receive input data!\n");
                        return 1;
                    }

                    request->_record_remaining = record.contentLength - recv_remaining;
                    request->_pad_remaining = record.paddingLength;

                    request->input_received += recv_remaining;
                    return 0;
                }
            } break;
            case FCGI_RECORD_BEGIN_REQUEST:
            case FCGI_RECORD_PARAMS: {
                // This shouldn't occur here.
                fprintf(stderr, "[FCGI] Ignoring misordered record of type \"%u\"", record.type);
            } break;
            case FCGI_RECORD_ABORT_REQUEST: HANDLE_ABORT_RECORD(request, &record, NULL, 0); break;
            HANDLE_MANAGEMENT_RECORD(request, &record, NULL, 0);
        }

        SKIP_CONTENT(request, &record, record_received);
    } while (!done);

    // If we got here, the input data stream closed.
    request->state = FCGI_REQUEST_STATE_WRITE_RESPONSE;
    return 0;
}

// I'd prefer to allocate once and write less vs allocate multiple times. If you're giving me a size hint, I'll take it.
void *fcgi_read_input_dynamic(fcgi_request_t *request, const size_t content_length)
{
    void *recv_buffer = malloc(content_length);
    if (!recv_buffer) return NULL;

    if (fcgi_read_input(request, recv_buffer, content_length)) {
        free(recv_buffer);
        return NULL;
    } else {
        return recv_buffer;
    }
}

int fcgi_exhaust_input(fcgi_request_t *request)
{
    if (request->state != FCGI_REQUEST_STATE_READ_DATA)
    {
        fprintf(stderr, "[FCGI] Found request in wrong state when attempting to read input!\n");
        return 1;
    }

    size_t buffer_length = REQUEST_BUFFER_LEN(request);
    void *data_buffer = REQUEST_BUFFER(request);
    ssize_t received_length;
    fcgi_record_t record;
    bool done = false;

    do {
        RECEIVE_RECORD(request, &record, data_buffer, buffer_length, received_length, { return 1; });

        if (record.requestId && record.requestId != request->id)
        {
            fprintf(stderr, "[FCGI] Got record for mismatched request id! (%hu vs %hu)\n", record.requestId, request->id);
            continue;
        }

        switch (record.type)
        {
            case FCGI_RECORD_STDIN: {
                if (!record.contentLength)
                {
                    // There is no more input data.
                    done = true;
                    break;
                }
            } break;
            case FCGI_RECORD_BEGIN_REQUEST:
            case FCGI_RECORD_PARAMS: {
                // This shouldn't occur here.
                fprintf(stderr, "[FCGI] Ignoring misordered record of type \"%u\"", record.type);
            } break;
            case FCGI_RECORD_ABORT_REQUEST: HANDLE_ABORT_RECORD(request, &record, data_buffer, received_length); break;
            HANDLE_MANAGEMENT_RECORD(request, &record, data_buffer, received_length);
        }

        SKIP_CONTENT(request, &record, received_length);
    } while (!done);

    request->state = FCGI_REQUEST_STATE_WRITE_RESPONSE;
    return 0;
}

int fcgi_request_send_data(fcgi_request_t *request, const void *buffer, size_t buffer_length)
{
    if (request->state == FCGI_REQUEST_STATE_INACTIVE)
    {
        fprintf(stderr, "[FCGI] Found request in wrong state when attempting to write output!\n");
        return 1;
    }

    size_t i = 0;

    while (buffer_length)
    {
        uint16_t send_length = (buffer_length > UINT16_MAX) ? UINT16_MAX : buffer_length;

        if (fcgi_send_stdout_record(request->socket, request->id, &buffer[i], send_length))
        {
            fprintf(stderr, "[FCGI] Failed to send output data.\n");
            return 1;
        }

        fprintf(stderr, "[FCGI] Wrote output record for request \"%hu\" (%hu bytes)\n", request->id, send_length);
        buffer_length -= send_length;
    }

    return 0;
}

int fcgi_request_finalize(fcgi_request_t *request, fcgi_status_t status)
{
    if (!request->_output_finished)
    {
        fprintf(stderr, "[FCGI] Closed output stream for request \"%hu\"\n", request->id);

        fcgi_send_close_stdout(request->socket, request->id);
        request->_output_finished = true;
    }

    if (fcgi_send_end_record(request->socket, 0, status, request->id))
    {
        fprintf(stderr, "[FCGI] Failed to finalize request (id: %hu)\n", request->id);
        return 1;
    }

    fprintf(stderr, "[FCGI] Finalized request \"%hu\" (status: %u)\n", request->id, status);

    if (!request->keep_alive)
    {
        do_shutdown(request->socket, SHUT_RDWR);
        request->socket = -1;

        fprintf(stderr, "[FCGI] Closed socket for request \"%hu\"\n", request->id);
    }

    request->state = FCGI_REQUEST_STATE_INACTIVE;
    return 0;
}

// This macro is no longer needed
#undef HANDLE_MANAGEMENT_RECORD

// Neither is this one
#undef RECEIVE_RECORD

// "
#undef HANDLE_ABORT_RECORD

// ""
#undef SKIP_CONTENT
