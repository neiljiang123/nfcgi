#ifndef __NFCGI__
#define __NFCGI__ 1

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "nfcgi_protocol.h"

/* Library-Specific Types */

// Macro for defining param search names in an array statically. Generally best for static strings
#define FCGI_SEARCH_NAME(str) ((fcgi_pair_t){ .name = (str), .name_len = strlen(str), .value = NULL, .value_len = -1 })

// A single (name, value) pair of strings, lengths cached.
typedef struct fcgi_pair {
    size_t name_len;
    char *name; // This may be NULL if name_len == 0

    // This is an ssize to indicate `value` is unset.
    ssize_t value_len;
    char *value; // This may be NULL if value_len == 0
} fcgi_pair_t;

// FCGI spec for responder role says we get exactly BEGIN, PARAMS (stream), STDIN (stream)
// Then, we write a response and an end record before (maybe) closing the connection.
typedef enum fcgi_request_state {
    FCGI_REQUEST_STATE_INACTIVE,
    FCGI_REQUEST_STATE_STARTED,
    FCGI_REQUEST_STATE_READ_PARAMS,
    FCGI_REQUEST_STATE_READ_DATA,
    FCGI_REQUEST_STATE_WRITE_RESPONSE
} fcgi_request_state_t;

typedef struct fcgi_request {
    fcgi_request_state_t state;
    uint16_t id;

    int socket;
    bool keep_alive;

    size_t param_count;
    fcgi_pair_t *params;

    // How many bytes of input data have been received?
    size_t input_received;

    // If we read a partial record how much data is left there?
    // This is used by the library for reading input data.
    size_t _record_remaining;
    size_t _pad_remaining;

    bool _output_finished;
} fcgi_request_t;

typedef struct fcgi_lib_config {
    size_t max_connections;
    size_t max_requests;
    size_t can_multiplex;

    // Host and port for listen socket.
    char *host; // Set this to NULL for localhost
    uint16_t port;

    // # of connections for listen backlog size
    int listen_backlog;
} fcgi_lib_config_t;

typedef struct fcgi_lib_state {
    fcgi_lib_config_t config;
    int listen_socket;
} fcgi_lib_state_t;

// Initialize FCGI library (open listening socket, etc)
extern fcgi_lib_state_t *fcgi_lib_init(const fcgi_lib_config_t *config);

// De-initialize FCGI library (if you want to)
extern void fcgi_lib_deinit(fcgi_lib_state_t *state);

// Allocate a new request struct
extern fcgi_request_t *fcgi_request_alloc(void);

// Delete the passed request struct
extern void fcgi_request_destroy(fcgi_request_t *request);

// Begin a new request on the passed request
extern int fcgi_request_accept(fcgi_request_t *request);

// Read parameters, saving values for search names. (memory is caller owned, values are put on the heap)
extern int fcgi_request_read_params(fcgi_request_t *request);

// Read parameters, saving all parameters.
extern ssize_t fcgi_request_read_params_all(fcgi_request_t *request);

// Delete parameter list as created by fcgi_read_params_all()
extern void fcgi_delete_params(fcgi_request_t *request);

// Read the request input up to `buffer_length` bytes.
extern int fcgi_read_input(fcgi_request_t *request, void *buffer, const size_t buffer_length);

// Read the request input in full, placing it in a dynamically allocated buffer.
extern void *fcgi_read_input_dynamic(fcgi_request_t *request, const size_t content_length);

// Dump the rest of the input into the void
extern int fcgi_exhaust_input(fcgi_request_t *request);

extern int fcgi_request_send_data(fcgi_request_t *request, const void *buffer, const size_t buffer_length);

// If you don't feel like calling strlen yourself...
#define fcgi_request_send_str(req, str) fcgi_request_send_data((req), (str), strlen(str))

// Finalize the passed request
extern int fcgi_request_finalize(fcgi_request_t *request, fcgi_status_t status);

#endif /* !defined(__NFCGI__) */
