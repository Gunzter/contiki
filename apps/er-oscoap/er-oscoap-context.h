
#ifndef _OSCOAP_CONTEXT_H
#define _OSCOAP_CONTEXT_H

//#include "er-oscoap.h"
//#include "er-coap.h"
#include <stddef.h> /* for size_t */
//#include <sys/types.h>
#include <inttypes.h>
#include "sha.h"
#include "lib/memb.h"
#include "er-coap-conf.h"
#include "er-coap-constants.h"

#define CONTEXT_KEY_LEN 16 
#define CONTEXT_INIT_VECT_LEN 7
#define CONTEXT_SEQ_LEN sizeof(uint32_t) 


#define OSCOAP_SEQ_MAX 10000 //TODO calculate the real value
//oscoap_ctx_t
//oscoap_sender_ctx_t
//oscoap_recipient_ctx_t
//sender_key
//sender_iv

typedef struct oscoap_sender_ctx_t oscoap_sender_ctx_t;
typedef struct oscoap_recipient_ctx_t oscoap_recipient_ctx_t;
typedef struct oscoap_ctx_t oscoap_ctx_t;
typedef struct token_seq_t token_seq_t;

struct oscoap_sender_ctx_t
{
  uint8_t   sender_key[CONTEXT_KEY_LEN];
  uint8_t   sender_iv[CONTEXT_INIT_VECT_LEN];
  uint8_t   token[COAP_TOKEN_LEN];
  uint32_t  seq;
  uint8_t*  sender_id;
  uint8_t   sender_id_len;
  uint8_t   token_len;
};

struct oscoap_recipient_ctx_t
{
  uint32_t  last_seq;
  uint32_t  highest_seq;
  uint32_t  sliding_window;
  uint32_t  rollback_sliding_window;
  uint32_t  rollback_last_seq;
  oscoap_recipient_ctx_t* recipient_context; //This field facilitates easy integration of OSCOAP multicast
  uint8_t   recipient_key[CONTEXT_KEY_LEN];
  uint8_t   recipient_iv[CONTEXT_INIT_VECT_LEN];
  uint8_t*  recipient_id;
  uint8_t   recipient_id_len;
  uint8_t   replay_window_size;
  uint8_t   initial_state;
};

struct oscoap_ctx_t{
 // uint8_t   ContextId[CONTEXT_ID_LEN];
  uint8_t*  master_secret;
  uint8_t*  master_salt;
  oscoap_sender_ctx_t* sender_context;
  oscoap_recipient_ctx_t* recipient_context;
  oscoap_ctx_t* next_context;
  uint8_t    master_secret_len;
  uint8_t    master_salt_len;

  uint8_t alg;
};

struct token_seq_t{
  uint8_t token[8];
  uint8_t  token_len;
  uint32_t seq;
  token_seq_t* next;
};

/* This is the number of contexts that the store can handle */
#define CONTEXT_NUM 1
#define TOKEN_SEQ_NUM 1

void oscoap_ctx_store_init();

uint8_t get_info_len(uint8_t id_len, uint8_t out_len);

//uint8_t compose_info(uint8_t* buffer, uint8_t alg, uint8_t* id, uint8_t id_len, uint8_t out_len);
oscoap_ctx_t* oscoap_derrive_ctx(uint8_t* master_secret,
           uint8_t master_secret_len, uint8_t* master_salt, uint8_t master_salt_len, uint8_t alg, uint8_t hkdf_alg,
            uint8_t* sid, uint8_t sid_len, uint8_t* rid, uint8_t rid_len, uint8_t replay_window);

oscoap_ctx_t* oscoap_new_ctx( uint8_t* sw_k, uint8_t* sw_iv, uint8_t* rw_k, uint8_t* rw_iv,
  uint8_t* s_id, uint8_t s_id_len, uint8_t* r_id, uint8_t r_id_len, uint8_t replay_window);

//oscoap_ctx_t* oscoap_find_ctx_by_cid(uint8_t* cid);

oscoap_ctx_t* oscoap_find_ctx_by_rid(uint8_t* rid, uint8_t rid_len);
oscoap_ctx_t* oscoap_find_ctx_by_token(uint8_t* token, uint8_t token_len);

void init_token_seq_store();
uint8_t get_seq_from_token(uint8_t* token, uint8_t token_len, uint32_t* seq);
uint8_t set_seq_from_token(uint8_t* token, uint8_t token_len, uint32_t seq);
void remove_seq_from_token(uint8_t* token, uint8_t token_len);

int oscoap_free_ctx(oscoap_ctx_t *ctx);

#endif /*_OSCOAP_CONTEXT_H */
