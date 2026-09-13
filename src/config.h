#ifndef HSP_CONFIG_H
#define HSP_CONFIG_H
#include <netinet/in.h>
#include "core.h"
struct config {
    char name[64], module[512], serial[32], reader[65], key_id[129], certificate[512];
    char peer_name[64], public_key[512], pin_hex[65];
    char listen[16], target[16], role[16], bind[32], peer[32];
    uint16_t ports[3], max_payload;
    struct sockaddr_in local[3], delivery[3], tunnel_bind, tunnel_peer;
};
bool parse_hex(const char *, uint8_t *, size_t *);
bool config_load(const char *, struct config *, char *, size_t);
#endif
