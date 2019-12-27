idf_component_register(
    SRCS "dns_hijack_srv.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES wpa_supplicant
)