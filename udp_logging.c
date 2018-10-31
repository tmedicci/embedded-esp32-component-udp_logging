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

#include "udp_logging.h"

#include "esp_system.h"
#include "esp_log.h"

#include <string.h>


int udp_log_fd;
struct sockaddr_in udp_log_socket;
static uint8_t buf[UDP_LOGGING_MAX_PAYLOAD_LEN];

int get_socket_error_code(int socket)
{
	int result;
	u32_t optlen = sizeof(int);
	if(getsockopt(socket, SOL_SOCKET, SO_ERROR, &result, &optlen) == -1) {
	return -1;
	}
	return result;
}

void udp_logging_free(vprintf_like_t func) {
	int err = 0;
	if (udp_log_fd != 0) {
        esp_log_set_vprintf(vprintf);

        if( (err = shutdown(udp_log_fd, 2)) == 0 ) {
            ESP_LOGW("UDP_LOGGING", "UDP logging shutdown");
        } else {
            ESP_LOGE("UDP_LOGGING", "Shutting-down UDP log socket failed: %d!\n", err);
        }

        if( (err = close( udp_log_fd )) == 0 ) {
            ESP_LOGW("UDP_LOGGING", "Closed UDP log socket ");
        } else {
            ESP_LOGE("UDP_LOGGING", "Closing UDP log socket failed: %d!\n", err);
        }
        if (func != NULL) {
            esp_log_set_vprintf(func);
        }
        udp_log_fd = 0;
	}
}


int udp_logging_vprintf( const char *str, va_list l ) {
    int err = 0;
	int len;
	char task_name[16];
	char *cur_task = pcTaskGetTaskName(xTaskGetCurrentTaskHandle());
	strncpy(task_name, cur_task, 16);
	if (udp_log_fd) {
        if (strncmp(task_name, "tiT", 4) != 0)
        {
            len = vsprintf((char*)buf, str, l);
            if( (err = sendto(udp_log_fd, buf, len, 0, (struct sockaddr *)&udp_log_socket, sizeof(udp_log_socket))) < 0 )
            {
                int socket_error = get_socket_error_code(udp_log_fd);
                udp_logging_free(vprintf);
                ESP_LOGE("UDP_LOGGING", "UDP logging failed with the following error code: %d", socket_error);
            }
        }
	}
	return vprintf( str, l );
}

int udp_logging_init(const char *ipaddr, unsigned long port, vprintf_like_t func) {
	struct timeval send_timeout = {1,0};
	udp_log_fd = 0;
	ESP_LOGI("UDP_LOGGING", "Initializing udp logging...");
    if( (udp_log_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
       ESP_LOGE("UDP_LOGGING", "Cannot open socket!");
       udp_log_fd = 0;
       return -1;
    }

    uint32_t ip_addr_bytes;
    inet_aton(ipaddr, &ip_addr_bytes);
    ESP_LOGI("UDP_LOGGING", "Logging to 0x%x", ip_addr_bytes);

    memset( &udp_log_socket, 0, sizeof(udp_log_socket) );
    udp_log_socket.sin_family = AF_INET;
    udp_log_socket.sin_port = htons( port );
    udp_log_socket.sin_addr.s_addr = ip_addr_bytes;

    int err = setsockopt(udp_log_fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&send_timeout, sizeof(send_timeout));
	if (err < 0) {
	   ESP_LOGE("UDP_LOGGING", "Failed to set SO_SNDTIMEO. Error %d", err);
	   udp_log_fd = 0;
       return -1;
	}

	if (func != NULL) {
	    esp_log_set_vprintf(func);
	}

    return 0;
}


