#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <stdio.h>
#include <netdb.h>

#include "nfcgi.h"
#include "nfcgi_protocol.h"

#define TEST_VERSION    "0.1"
#define SOCKET_BACKLOG  10

#define RECEIVE_BUFFER_LENGTH   4096

const static struct option options[] = {
    {
        .name = "host",
        .has_arg = required_argument,
        .flag = NULL,
        .val = 'h'
    }, {
        .name = "port",
        .has_arg = required_argument,
        .flag = NULL,
        .val = 'p'
    }, {
        .name = "version",
        .has_arg = no_argument,
        .flag = NULL,
        .val = 'v'
    }, {
        .name = "help",
        .has_arg = no_argument,
        .flag = NULL,
        .val = '?'
    }
};

void usage(const char *program)
{
    fprintf(stderr, "Usage: %s [--host hostname] [--port port]\n", program);
}

int main(int argc, char *const *argv)
{
    const char *program = argv[0];
    uint16_t port = 9000;
    char *host = NULL;
    char opt;

    while ((opt = getopt_long(argc, argv, "h:p:v", options, NULL)) != -1)
    {
        switch (opt)
        {
            case 'h': {
                host = optarg;
            } break;
            case 'p': {
                char *endptr;
                port = strtol(optarg, &endptr, 10);

                if ((*endptr) != '\0' || (*optarg) == '\0')
                {
                    fprintf(stderr, "Invalid port value \"%s\"\n", optarg);

                    usage(program);
                    exit(1);
                }
            } break;
            case 'v':
                fprintf(stderr, "%s version %s\n", program, TEST_VERSION);
                exit(0);
            case '?':
            default:
                usage(program);
                exit(0);
        }
    }

    fcgi_lib_config_t fcgi_config = {
        .max_connections = 1,
        .max_requests = 1,
        .can_multiplex = 0,

        .host = host,
        .port = port,

        .listen_backlog = SOCKET_BACKLOG
    };

    fcgi_lib_state_t *fcgi_state = fcgi_lib_init(&fcgi_config);

    if (!fcgi_state)
    {
        fprintf(stderr, "Failed to initialize FCGI library!\n");
        return 1;
    }

    fcgi_request_t *request = fcgi_request_alloc();
    if (!request) { return 1; }

    // These are the parameters we care about.
    fcgi_pair_t param_search_query[] = {
        FCGI_SEARCH_NAME("CONTENT_LENGTH"),
        FCGI_SEARCH_NAME("DOCUMENT_ROOT"),
        FCGI_SEARCH_NAME("REQUEST_METHOD"),
        FCGI_SEARCH_NAME("REQUEST_URI")
    };

    do {
        if (fcgi_request_accept(request))
        {
            fprintf(stdout, "Sad.\n");
            continue;
        }

        // Now we have a valid request. Setup parameter search.
        request->param_count = sizeof(param_search_query) / sizeof(fcgi_pair_t);
        request->params = param_search_query;

        if (fcgi_request_read_params(request))
        {
            fprintf(stderr, "Failed to get request parameters!\n");

            request->keep_alive = false;
            fcgi_request_finalize(request, FCGI_STATUS_OVERLOADED);
            continue;
        }

        printf("Got params:\n");

        for (size_t i = 0; i < request->param_count; i++) {
            printf("%s=%s\n", request->params[i].name, request->params[i].value);
        }

        if (request->params[0].value_len != -1)
        {
            char *endptr;
            size_t content_length = strtoll(request->params[0].value, &endptr, 10);

            if ((*endptr) != '\0')
            {
                fprintf(stderr, "Got bad content length parameter!");

                request->keep_alive = false;
                fcgi_request_finalize(request, FCGI_STATUS_OVERLOADED);
                continue;
            }

            uint8_t *input_data = fcgi_read_input_dynamic(request, content_length);
            printf("Got input data: '%s'\n", input_data);
            free(input_data);
        }

        if (request->state != FCGI_REQUEST_STATE_WRITE_RESPONSE)
        {
            // Skip (maybe) the rest of input
            //fcgi_exhaust_input(request);
        }

        printf("Writing output data...\n");

        fcgi_request_send_str(request, "Content-Type: application/json\r\n\r\n");
        fcgi_request_send_str(request, "{ \"test\": 5 }");

        fcgi_request_finalize(request, FCGI_STATUS_REQUEST_COMPLETE);

        for (size_t i = 0; i < request->param_count; i++) {
            if (request->params[i].value_len != -1) {
                free(request->params[i].value);
            }
        }
    } while (true);

    fcgi_lib_deinit(fcgi_state);
    return 0;
}
