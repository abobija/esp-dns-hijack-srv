# esp-dns-hijack-srv
Esp32 [DNS Hijack](https://en.wikipedia.org/wiki/DNS_hijacking) Server, packaged as ESP-IDF component.

This is simple DNS server that resolves all lookups to one IP address. Handy for use to open [Captive Portal](https://en.wikipedia.org/wiki/Captive_portal).

## How to use

This directory is an ESP-IDF component. Clone it (or add it as submodule) into `components` directory of the project.

## Example

In this example all requested domains will be redirected to the IP address 192.168.4.1

```C
ip4_addr_t resolve_ip;
inet_pton(AF_INET, "192.168.4.1", &resolve_ip);

if(dns_hijack_srv_start(resolve_ip) == ESP_OK) {
    ESP_LOGI(TAG, "DNS hijack server started");
} else {
    ESP_LOGE(TAG, "DNS hijack server has not started");
}
```
