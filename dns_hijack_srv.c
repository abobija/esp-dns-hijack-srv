#include <string.h>
#include <sys/param.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_netif.h"
#include "esp_log.h"
#include "esp_event.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>

#include <byteswap.h>

#include "dns_hijack_srv.h"

static const char *TAG = "dns_hijack_srv";

static ip4_addr_t hijack_ip_addr;
static TaskHandle_t dns_hijack_srv_task_handle;

static void dns_hijack_srv_task(void *pvParameters) {
    uint8_t rx_buffer[128];

    for(;;) {
        struct sockaddr_in dest_addr;

        dest_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(53);

        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

        if(sock < 0) {
            ESP_LOGE(TAG, "Unable to create socket");
            break;
        }

        ESP_LOGI(TAG, "Socket created");

        int err = bind(sock, (struct sockaddr*) &dest_addr, sizeof(dest_addr));

        if(err < 0) {
            ESP_LOGE(TAG, "Socket unable to bind");
            break;
        }
        
        ESP_LOGI(TAG, "Listening...");

        for(;;) {
            struct sockaddr_in source_addr;
            socklen_t socklen = sizeof(source_addr);

            memset(rx_buffer, 0x00, sizeof(rx_buffer));
            int len = recvfrom(sock, rx_buffer, sizeof(rx_buffer), 0, (struct sockaddr*) &source_addr, &socklen);

            if(len < 0) {
                ESP_LOGE(TAG, "revfrom failed");
                break;
            }

            if(len > DNS_HIJACK_SRV_HEADER_SIZE + DNS_HIJACK_SRV_QUESTION_MAX_LENGTH) {
                ESP_LOGW(TAG, "Received more data [%d] than expected. Ignoring.", len);
                continue;
            }

            // Nul termination. To prevent pointer escape
            rx_buffer[sizeof(rx_buffer) - 1] = '\0';

            dns_header_t *header = (dns_header_t*) rx_buffer;

            header->QR      = 1;
            header->OPCODE  = 0;
            header->AA      = 1;
            header->RCODE   = 0;
            header->TC      = 0;
            header->Z       = 0;
            header->RA      = 0;
            header->ANCOUNT = header->QDCOUNT;
            header->NSCOUNT = 0;
            header->ARCOUNT = 0;

            // ptr points to the beginning of the QUESTION
            uint8_t *ptr = rx_buffer + sizeof(dns_header_t);

            // Jump over QNAME
            while(*ptr++);

            // Jump over QTYPE
            ptr += 2;

            // Jump over QCLASS
            ptr += 2;

            dns_hijack_answer_t *answer = (dns_hijack_answer_t*) ptr;

            answer->NAME     = __bswap_16(0xC00C);
            answer->TYPE     = __bswap_16(1);
            answer->CLASS    = __bswap_16(1);
            answer->TTL      = 0;
            answer->RDLENGTH = __bswap_16(4);
            answer->RDATA    = hijack_ip_addr.addr;

            // Jump over ANSWER
            ptr += sizeof(dns_hijack_answer_t);

            int err = sendto(sock, rx_buffer, ptr - rx_buffer, 0, (struct sockaddr *)&source_addr, sizeof(source_addr));

            if (err < 0) {
                ESP_LOGE(TAG, "Error occurred during sending");
                break;
            }
        }

        if(sock != -1) {
            ESP_LOGI(TAG, "Shutting down socket and restarting...");
            shutdown(sock, 0);
            close(sock);
        }
    }

    dns_hijack_srv_stop();
}

esp_err_t dns_hijack_srv_start(const ip4_addr_t hijack_ip) {
    if(dns_hijack_srv_task_handle != NULL) {
        return ESP_OK;
    }

    hijack_ip_addr = hijack_ip;

	ESP_LOGI(TAG, "Hijack ip: "IPSTR, 
        ip4_addr1(&hijack_ip_addr),
        ip4_addr2(&hijack_ip_addr), 
        ip4_addr3(&hijack_ip_addr),
        ip4_addr4(&hijack_ip_addr));

    xTaskCreate(dns_hijack_srv_task, "dns_hijack_srv", 4096, NULL, 5, &dns_hijack_srv_task_handle);
    return ESP_OK;
}

esp_err_t dns_hijack_srv_stop() {
    vTaskDelete(dns_hijack_srv_task_handle);
    dns_hijack_srv_task_handle = NULL;
    return ESP_OK;
}