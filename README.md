# dns-hijack-srv
Esp32 DNS Hijack Server, packaged as ESP-IDF component

## How to use

This directory is an ESP-IDF component. Clone it (or add it as submodule) into `components` directory of the project.

## Example

```C
ip4_addr_t resolve_ip;
inet_pton(AF_INET, "192.168.4.1", &resolve_ip);

if(dns_hijack_srv_start(resolve_ip) == ESP_OK) {
    ESP_LOGI(TAG, "DNS hijack server started");
} else {
    ESP_LOGE(TAG, "DNS hijack server has not started");
}
```
