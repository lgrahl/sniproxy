/*
 * Copyright (c) 2016, Lennart Grahl <lennart.grahl@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * This 'protocol' tries to multiplex all supported protocols.
 * Currently these are TLS and HTTP.
 */
#include <stdio.h>
#include <stdbool.h>
#include "any.h"
#include "protocol.h"
#include "logger.h"

static int parse_any_header(const char *, size_t, char **);
static void set_abort_message(size_t pos);

static const char dummy_response[] = "";

/* The protocols will be tried out in the defined order */
static const struct Protocol protocols[] = {
        tls_protocol,
        http_protocol
};
static const size_t protocols_len = sizeof(protocols) / sizeof(protocols[0]);

static const struct Protocol any_protocol_st = {
    .name = "any",
    .default_port = 0,
    .parse_packet = &parse_any_header,
    .abort_message = dummy_response,
    .abort_message_len = sizeof(dummy_response)
};
const struct Protocol *const any_protocol = &any_protocol_st;


/* Pass any data to the specified possible protocols.
 *
 * Returns:
 *  >=0  - length of the hostname and updates *hostname
 *         caller is responsible for freeing *hostname
 *  -1   - Incomplete request
 *  -2   - No Host header included in this request
 *  -3   - Invalid hostname pointer
 *  -4   - malloc failure
 *  < -4 - Other protocol errors
 */
static int
parse_any_header(const char *data, size_t data_len, char **hostname) {
    int code;
    size_t no_host_header_included = -1;
    size_t incomplete_request = -1;

    if (hostname == NULL)
        return -3;

    /* Try out specified protocols */
    for (size_t i = 0; i < protocols_len; ++i) {
        code = protocols[i].parse_packet(data, hostname);

        /* Stop in case...
         * >= 0: the protocol has accepted the data.
         * -3:   of invalid hostname pointer.
         * -4:   of malloc failure. */
        if (code >= 0 || code == -3 || code == -4) {
            set_abort_message(i);
            return code;
        }

        /* Incomplete request or no host header included? */
        switch (code) {
            case -1:
                incomplete_request = i;
                break;
            case -2:
                no_host_header_included = i;
                break;
        }
    }

    /* Did someone say no host header included? */
    if (no_host_header_included != -1) {
        set_abort_message(no_host_header_included);
        return -2;
    }

    /* Did someone say incomplete request? */
    if (incomplete_request != -1) {
        set_abort_message(incomplete_request);
        return -1;
    }
}

static void set_abort_message(size_t pos) {
    any_protocol->abort_message = protocols[pos].abort_message;
    any_protocol->abort_message_len = protocols[pos].abort_message_len;
}
