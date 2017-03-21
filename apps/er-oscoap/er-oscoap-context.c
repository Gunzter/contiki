
#include "er-oscoap-context.h"
#include "er-oscoap.h"
#include "opt-cbor.h"
#include "opt-cose.h"


#define DEBUG 1
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINTF_HEX(data, len)  oscoap_printf_hex(data, len)
#define PRINTF_CHAR(data, len)   oscoap_printf(data, len)
#define PRINTF_BIN(data, len)  oscoap_printf_bin(data, len)

#else /* DEBUG */
#define PRINTF(...)
#define PRINTF_HEX(data, len)
#define PRINTF_CHAR(data, len)
#define PRINTF_BIN(data, len)
#endif /* OSCOAP_DEBUG */

OscoapCommonContext *common_context_store = NULL;

MEMB(common_contexts, OscoapCommonContext, CONTEXT_NUM);
MEMB(sender_contexts, OscoapSenderContext, CONTEXT_NUM);
MEMB(recipient_contexts, OscoapRecipientContext, CONTEXT_NUM);

void oscoap_ctx_store_init(){

  memb_init(&common_contexts);
  memb_init(&sender_contexts);
  memb_init(&recipient_contexts);
}

size_t get_info_len(size_t cid_len, size_t id_len, uint8_t out_len){
  size_t len = cid_len + id_len;
  if(out_len == 16){
    len += 3;
  } else {
    len += 2;
  }
  len += 6;
  return len;
}


uint8_t compose_info(uint8_t* buffer, uint8_t* cid, size_t cid_len, uint8_t alg, uint8_t* id, size_t id_len, uint8_t out_len){
    uint8_t ret = 0;
    ret = OPT_CBOR_put_array(&buffer, 5);
    ret = OPT_CBOR_put_bytes(&buffer, cid_len, cid);
    ret = OPT_CBOR_put_bytes(&buffer, id_len, id);
    ret = OPT_CBOR_put_unsigned(&buffer, alg);
    char* text;
    if( out_len == 16 ){
        text = "Key";
    } else {
        text = "IV";
    }
    ret = OPT_CBOR_put_text(&buffer, text, strlen(text));
    ret = OPT_CBOR_put_unsigned(&buffer, out_len);

    return ret;
}
uint8_t zeroes[32];
uint8_t info_buffer[40 + 10]; // TODO, calculate max buffer and run with that

OscoapCommonContext* oscoap_derrive_ctx(uint8_t* cid, size_t cid_len, uint8_t* master_secret,
           size_t master_secret_len, uint8_t alg, uint8_t hkdf_alg,
            uint8_t* sid, size_t sid_len, uint8_t* rid, size_t rid_len, uint8_t replay_window){
  //  printf("derrive context\n");

    OscoapCommonContext* common_ctx = memb_alloc(&common_contexts);
    if(common_ctx == NULL) return 0;
   
    OscoapRecipientContext* recipient_ctx = memb_alloc(&recipient_contexts);
    if(recipient_ctx == NULL) return 0;
   
    OscoapSenderContext* sender_ctx = memb_alloc(&sender_contexts);
    if(sender_ctx == NULL) return 0;

    memset(zeroes, 0x00, 32);
  
    size_t info_buffer_size;
    info_buffer_size = get_info_len(cid_len, sid_len, CONTEXT_KEY_LEN);
    //Sender Key
    info_buffer_size = get_info_len(cid_len, sid_len, CONTEXT_KEY_LEN);
    compose_info(info_buffer, cid, cid_len, alg, sid, sid_len, CONTEXT_KEY_LEN);
    hkdf(SHA256, zeroes, 32, master_secret, master_secret_len, info_buffer, info_buffer_size, sender_ctx->SenderKey, CONTEXT_KEY_LEN );

    //Sender IV
    info_buffer_size = get_info_len(cid_len, sid_len, CONTEXT_INIT_VECT_LEN);
    compose_info(info_buffer, cid, cid_len, alg, sid, sid_len, CONTEXT_INIT_VECT_LEN);
    hkdf(SHA256, zeroes, 32, master_secret, master_secret_len, info_buffer, info_buffer_size, sender_ctx->SenderIv, CONTEXT_INIT_VECT_LEN );

    //Receiver Key
    info_buffer_size = get_info_len(cid_len, rid_len, CONTEXT_KEY_LEN);
    compose_info(info_buffer, cid, cid_len, alg, rid, rid_len, CONTEXT_KEY_LEN);
    hkdf(SHA256, zeroes, 32, master_secret, master_secret_len, info_buffer, info_buffer_size, recipient_ctx->RecipientKey, CONTEXT_KEY_LEN );

    //Receiver IV
    info_buffer_size = get_info_len(cid_len, rid_len, CONTEXT_INIT_VECT_LEN);
    compose_info(info_buffer, cid, cid_len, alg, rid, rid_len, CONTEXT_INIT_VECT_LEN);
    hkdf(SHA256, zeroes, 32, master_secret, master_secret_len, info_buffer, info_buffer_size, recipient_ctx->RecipientIv, CONTEXT_INIT_VECT_LEN );

    common_ctx->MasterSecret = master_secret;
    common_ctx->MasterSecretLen = master_secret_len;
    common_ctx->Alg = alg;
  //  memcpy(common_ctx->ContextId, cid, CONTEXT_ID_LEN);
    common_ctx->RecipientContext = recipient_ctx;
    common_ctx->SenderContext = sender_ctx;
    sender_ctx->Seq = 0;

    recipient_ctx->LastSeq = 0;
    recipient_ctx->ReplayWindowSize = replay_window;
    recipient_ctx->RollbackLastSeq = 0;
    recipient_ctx->SlidingWindow = 0;
    recipient_ctx->RollbackSlidingWindow = 0;
   
   //TODO add checks to assert ( rid_len < ID_LEN && cid_len < ID_len)
    recipient_ctx->RecipientId = rid;
    sender_ctx->SenderId = sid;
    recipient_ctx->RecipientIdLen = rid_len;
    sender_ctx->SenderIdLen = sid_len;

    common_ctx->NextContext = common_context_store;
    common_context_store = common_ctx;
    return common_ctx;

}

//TODO add support for key generation using a base key and HKDF, this will come at a later stage
//TODO add SID 
OscoapCommonContext* oscoap_new_ctx( uint8_t* cid, uint8_t* sw_k, uint8_t* sw_iv, uint8_t* rw_k, uint8_t* rw_iv,
  uint8_t* s_id, uint8_t s_id_len, uint8_t* r_id, uint8_t r_id_len, uint8_t replay_window){
   
    OscoapCommonContext* common_ctx = memb_alloc(&common_contexts);
    if(common_ctx == NULL) return 0;
   
    OscoapRecipientContext* recipient_ctx = memb_alloc(&recipient_contexts);
    if(recipient_ctx == NULL) return 0;
   
    OscoapSenderContext* sender_ctx = memb_alloc(&sender_contexts);
    if(sender_ctx == NULL) return 0;

    common_ctx->Alg = COSE_Algorithm_AES_CCM_64_64_128;

    common_ctx->RecipientContext = recipient_ctx;
    common_ctx->SenderContext = sender_ctx;

    memcpy(sender_ctx->SenderKey, sw_k, CONTEXT_KEY_LEN);
    memcpy(sender_ctx->SenderIv, sw_iv, CONTEXT_INIT_VECT_LEN);
    sender_ctx->Seq = 0;

    memcpy(recipient_ctx->RecipientKey, rw_k, CONTEXT_KEY_LEN);
    memcpy(recipient_ctx->RecipientIv, rw_iv, CONTEXT_INIT_VECT_LEN);
    recipient_ctx->LastSeq = 0;
    recipient_ctx->ReplayWindowSize = replay_window;
    recipient_ctx->RollbackLastSeq = 0;
    recipient_ctx->SlidingWindow = 0;
    recipient_ctx->RollbackSlidingWindow = 0;

   
    //TODO This is to easly identify the sender and recipient ID
    printf("rid ptr %p\n", recipient_ctx->RecipientId);
    recipient_ctx->RecipientId = r_id;
    sender_ctx->SenderId =  s_id;
    recipient_ctx->RecipientIdLen = r_id_len;
    sender_ctx->SenderIdLen = s_id_len;

    common_ctx->NextContext = common_context_store;
    common_context_store = common_ctx;
    
    return common_ctx;
}
/*
OscoapCommonContext* oscoap_find_ctx_by_cid(uint8_t* cid){
    if(common_context_store == NULL){
      return NULL;
    }

    OscoapCommonContext *ctx_ptr = common_context_store;

    while(memcmp(ctx_ptr->ContextId, cid, CONTEXT_ID_LEN) != 0){
      ctx_ptr = ctx_ptr->NextContext;
    
      if(ctx_ptr == NULL){
        return NULL;
      }
    }
    return ctx_ptr;
} */

OscoapCommonContext* oscoap_find_ctx_by_rid(uint8_t* rid, size_t rid_len){
    if(common_context_store == NULL){
      return NULL;
    }
    printf("looking for:\n");
    oscoap_printf_hex(rid, rid_len);

    OscoapCommonContext *ctx_ptr = common_context_store;
    size_t cmp_len = MIN(rid_len, ctx_ptr->RecipientContext->RecipientIdLen);

    while(memcmp(ctx_ptr->RecipientContext->RecipientId, rid, cmp_len) != 0){
     printf("tried:\n");
    oscoap_printf_hex(ctx_ptr->RecipientContext->RecipientId, ctx_ptr->RecipientContext->RecipientIdLen);
      ctx_ptr = ctx_ptr->NextContext;
      cmp_len = MIN(rid_len, ctx_ptr->RecipientContext->RecipientIdLen);
      if(ctx_ptr == NULL){
        return NULL;
      }
    }
    return ctx_ptr;
}

OscoapCommonContext* oscoap_find_ctx_by_token(uint8_t* token, uint8_t token_len){
    if(common_context_store == NULL){
      return NULL;
    }
    PRINTF("looking for:\n");
    oscoap_printf_hex(token, token_len);

    OscoapCommonContext *ctx_ptr = common_context_store;
    size_t cmp_len = MIN(token_len, ctx_ptr->SenderContext->TokenLen);

    while(memcmp(ctx_ptr->SenderContext->SenderId, token, cmp_len) != 0){
     PRINTF("tried:\n");
     oscoap_printf_hex(ctx_ptr->SenderContext->Token, ctx_ptr->SenderContext->TokenLen);
      ctx_ptr = ctx_ptr->NextContext;
      cmp_len = MIN(token_len, ctx_ptr->SenderContext->TokenLen);
      if(ctx_ptr == NULL){
        return NULL;
      }
    }
    return ctx_ptr;
}

int oscoap_free_ctx(OscoapCommonContext *ctx){

    if(common_context_store == ctx){
      common_context_store = ctx->NextContext;

    }else{

      OscoapCommonContext *ctx_ptr = common_context_store;

      while(ctx_ptr->NextContext != ctx){
        ctx_ptr = ctx_ptr->NextContext;
      }

      if(ctx_ptr->NextContext->NextContext != NULL){
        ctx_ptr->NextContext = ctx_ptr->NextContext->NextContext;
      }else{
        ctx_ptr->NextContext = NULL;
      }
    }
    memset(ctx->MasterSecret, 0x00, ctx->MasterSecretLen);
    memset(ctx->SenderContext->SenderKey, 0x00, CONTEXT_KEY_LEN);
    memset(ctx->SenderContext->SenderIv, 0x00, CONTEXT_INIT_VECT_LEN);
    memset(ctx->RecipientContext->RecipientKey, 0x00, CONTEXT_KEY_LEN);
    memset(ctx->RecipientContext->RecipientIv, 0x00, CONTEXT_INIT_VECT_LEN);

    int ret = 0;
    ret += memb_free(&sender_contexts, ctx->SenderContext);
    ret += memb_free(&recipient_contexts, ctx->RecipientContext);
    ret += memb_free(&common_contexts, ctx);
  
    return ret;
}

void oscoap_print_context(OscoapCommonContext* ctx){
    PRINTF("Print Context:\n");
  //  PRINTF("Context ID: ");
  //  oscoap_printf_hex(ctx->ContextId, CONTEXT_ID_LEN);
    PRINTF("Base Key: ");
    oscoap_printf_hex(ctx->MasterSecret, ctx->MasterSecretLen);
    PRINTF("ALG: %d\n", ctx->Alg);

    OscoapSenderContext* s = ctx->SenderContext;
    PRINTF("Sender Context: {\n");
    PRINTF("\tSender ID: ");
    oscoap_printf_hex(s->SenderId, ID_LEN);
    PRINTF("\tSender Key: ");
    oscoap_printf_hex(s->SenderKey, CONTEXT_KEY_LEN);
    PRINTF("\tSender IV: ");
    oscoap_printf_hex(s->SenderIv, CONTEXT_INIT_VECT_LEN);
    PRINTF("}\n");

    OscoapRecipientContext* r = ctx->RecipientContext;
    PRINTF("Recipient Context: {\n");
    PRINTF("\tRecipient ID: ");
    oscoap_printf_hex(r->RecipientId, ID_LEN);
    PRINTF("\tRecipient Key: ");
    oscoap_printf_hex(r->RecipientKey, CONTEXT_KEY_LEN);
    PRINTF("\tRecipient IV: ");
    oscoap_printf_hex(r->RecipientIv, CONTEXT_INIT_VECT_LEN);
    PRINTF("}\n");
  
}