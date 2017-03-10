
#ifndef _OSCOAP_CONTEXTS_H
#define _OSCOAP_CONTEXTS_H

#include "er-oscoap.h"
#include "er-coap.h"
#include <sys/types.h>
#include <inttypes.h>
#include "sha.h"
#include "lib/memb.h"

void oscoap_ctx_store_init();

size_t get_info_len(size_t cid_len, size_t id_len, uint8_t out_len);

uint8_t compose_info(uint8_t* buffer, uint8_t* cid, size_t cid_len, uint8_t alg, uint8_t* id, size_t id_len, uint8_t out_len);
OSCOAP_COMMON_CONTEXT* oscoap_derrive_ctx(uint8_t* cid, size_t cid_len, uint8_t* master_secret,
           size_t master_secret_len, uint8_t alg, uint8_t hkdf_alg,
            uint8_t* sid, size_t sid_len, uint8_t* rid, size_t rid_len, uint8_t replay_window);

OSCOAP_COMMON_CONTEXT* oscoap_new_ctx( uint8_t* cid, uint8_t* sw_k, uint8_t* sw_iv, uint8_t* rw_k, uint8_t* rw_iv,
  uint8_t* s_id, uint8_t s_id_len, uint8_t* r_id, uint8_t r_id_len, uint8_t replay_window);

OSCOAP_COMMON_CONTEXT* oscoap_find_ctx_by_cid(uint8_t* cid);

int oscoap_free_ctx(OSCOAP_COMMON_CONTEXT *ctx);

#endif /*_OSCOAP_CONTEXTS_H */