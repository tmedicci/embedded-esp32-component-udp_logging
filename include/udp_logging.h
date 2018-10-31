//  Copyright 2017 by Malte Janduda
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

#ifndef UDP_LOGGING_MAX_PAYLOAD_LEN
#define UDP_LOGGING_MAX_PAYLOAD_LEN 2048
#endif

#include "esp_system.h"
#include "esp_log.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"

#include <string.h>

extern int udp_log_fd;
extern struct sockaddr_in udp_log_socket;

int udp_logging_init(const char *ipaddr, unsigned long port, vprintf_like_t func);
int udp_logging_vprintf( const char *str, va_list l );
void udp_logging_free(vprintf_like_t func);
int get_socket_error_code(int socket);
