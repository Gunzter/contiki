
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

#define OSCOAP_SERVER   1
#define OSCOAP_CLIENT   0
#define OSCOAP_SENDER  1
#define OSCOAP_RECEIPIENT 0

#define ID_LEN 6

typedef struct OscoapSenderContext OscoapSenderContext;
typedef struct OscoapRecipientContext OscoapRecipientContext;
typedef struct OscoapCommonContext OscoapCommonContext;

struct OscoapSenderContext
{
  uint8_t   SenderKey[CONTEXT_KEY_LEN];
  uint8_t   SenderIv[CONTEXT_INIT_VECT_LEN];
  uint8_t   SenderId[ID_LEN];
  uint8_t   SenderIdLen;
  uint32_t  SenderSeq;
};

struct OscoapRecipientContext
{
  OscoapRecipientContext* RECIPIENT_CONTEXT; //This field facilitates easy integration of OSCOAP multicast
  uint8_t   RecipientKey[CONTEXT_KEY_LEN];
  uint8_t   RecipientIv[CONTEXT_INIT_VECT_LEN];
  uint8_t   RecipientId[ID_LEN];
  uint8_t   RecipientIdLen;
  uint32_t  RecipientSeq;
  uint8_t   ReplayWindow;
};

struct OscoapCommonContext{
  uint8_t   ContextId[CONTEXT_ID_LEN];
  uint8_t*  MasterSecret;
  size_t    MasterSecretLen;
  uint8_t*  MasterSalt;
  size_t    MasterSaltLen;
  OscoapSenderContext* SenderContext;
  OscoapRecipientContext* RecipientContext;
  OscoapCommonContext* NextContext;
  uint8_t Alg;
};


#define CONTEXT_NUM 1

void oscoap_ctx_store_init();

size_t get_info_len(size_t cid_len, size_t id_len, uint8_t out_len);

uint8_t compose_info(uint8_t* buffer, uint8_t* cid, size_t cid_len, uint8_t alg, uint8_t* id, size_t id_len, uint8_t out_len);
OscoapCommonContext* oscoap_derrive_ctx(uint8_t* cid, size_t cid_len, uint8_t* master_secret,
           size_t master_secret_len, uint8_t alg, uint8_t hkdf_alg,
            uint8_t* sid, size_t sid_len, uint8_t* rid, size_t rid_len, uint8_t replay_window);

OscoapCommonContext* oscoap_new_ctx( uint8_t* cid, uint8_t* sw_k, uint8_t* sw_iv, uint8_t* rw_k, uint8_t* rw_iv,
  uint8_t* s_id, uint8_t s_id_len, uint8_t* r_id, uint8_t r_id_len, uint8_t replay_window);

OscoapCommonContext* oscoap_find_ctx_by_cid(uint8_t* cid);

int oscoap_free_ctx(OscoapCommonContext *ctx);

#endif /*_OSCOAP_CONTEXT_H */