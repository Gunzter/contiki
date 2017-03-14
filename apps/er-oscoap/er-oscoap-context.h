
#ifndef _OSCOAP_CONTEXT_H
#define _OSCOAP_CONTEXT_H

//#include "er-oscoap.h"
//#include "er-coap.h"
#include <stddef.h> /* for size_t */
//#include <sys/types.h>
#include <inttypes.h>
#include "sha.h"
#include "lib/memb.h"

//#define CONTEXT_ID_LEN 8
#define CONTEXT_ID_LEN 5
#define CONTEXT_KEY_LEN 16 
#define CONTEXT_INIT_VECT_LEN 7
#define CONTEXT_SEQ_LEN 4 

#define CONTEXT_ID_LEN 8
#define OSCOAP_SERVER   1
#define OSCOAP_CLIENT   0
#define OSCOAP_SENDER  1
#define OSCOAP_RECEIPIENT 0

#define ID_LEN 6

typedef struct OSCOAP_SENDER_CONTEXT OSCOAP_SENDER_CONTEXT;
typedef struct OSCOAP_RECIPIENT_CONTEXT OSCOAP_RECIPIENT_CONTEXT;
typedef struct OSCOAP_COMMON_CONTEXT OSCOAP_COMMON_CONTEXT;

struct OSCOAP_SENDER_CONTEXT
{
  uint8_t   SENDER_KEY[CONTEXT_KEY_LEN];
  uint8_t   SENDER_IV[CONTEXT_INIT_VECT_LEN];
  uint8_t   SENDER_ID[ID_LEN];
  uint8_t   SENDER_ID_LEN;
  uint32_t  SENDER_SEQ;
};

struct OSCOAP_RECIPIENT_CONTEXT
{
  OSCOAP_RECIPIENT_CONTEXT* RECIPIENT_CONTEXT; //This field facilitates easy integration of OSCOAP multicast
  uint8_t   RECIPIENT_KEY[CONTEXT_KEY_LEN];
  uint8_t   RECIPIENT_IV[CONTEXT_INIT_VECT_LEN];
  uint8_t   RECIPIENT_ID[ID_LEN];
  uint8_t   RECIPIENT_ID_LEN;
  uint32_t  RECIPIENT_SEQ;
  uint8_t   REPLAY_WINDOW;
};

struct OSCOAP_COMMON_CONTEXT{
  uint8_t CONTEXT_ID[CONTEXT_ID_LEN];
  uint8_t* BASE_KEY;
  size_t BASE_KEY_LEN;
  OSCOAP_SENDER_CONTEXT* SENDER_CONTEXT;
  OSCOAP_RECIPIENT_CONTEXT* RECIPIENT_CONTEXT;
  OSCOAP_COMMON_CONTEXT* NEXT_CONTEXT;
  uint8_t ALG;
};


#define CONTEXT_NUM 1

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

/*
void oscoap_print_context(OSCOAP_COMMON_CONTEXT* ctx);
// Functions for handling the security contexts 
void oscoap_ctx_store_init();
OSCOAP_COMMON_CONTEXT* oscoap_derrive_ctx(uint8_t* cid, size_t cid_len, uint8_t* master_secret,
           size_t master_secret_len, uint8_t alg, uint8_t hkdf_alg,
            uint8_t* sid, size_t sid_len, uint8_t* rid, size_t rid_len, uint8_t replay_window);
OSCOAP_COMMON_CONTEXT* oscoap_new_ctx( uint8_t* cid, uint8_t* sw_k, uint8_t* sw_iv, uint8_t* rw_k, uint8_t* rw_iv,
  uint8_t* s_id, uint8_t s_id_len, uint8_t* r_id, uint8_t r_id_len, uint8_t replay_window);
OSCOAP_COMMON_CONTEXT* oscoap_find_ctx_by_cid(uint8_t* cid);
int oscoap_free_ctx(OSCOAP_COMMON_CONTEXT *ctx);
*/

#endif /*_OSCOAP_CONTEXT_H */