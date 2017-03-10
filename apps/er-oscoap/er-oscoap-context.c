
#include "er-oscoap-context.h"
#include "opt-cbor.h"
#include "opt-cose.h"

OSCOAP_COMMON_CONTEXT *common_context_store = NULL;

MEMB(common_contexts, OSCOAP_COMMON_CONTEXT, CONTEXT_NUM);
MEMB(sender_contexts, OSCOAP_SENDER_CONTEXT, CONTEXT_NUM);
MEMB(recipient_contexts, OSCOAP_RECIPIENT_CONTEXT, CONTEXT_NUM);

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

OSCOAP_COMMON_CONTEXT* oscoap_derrive_ctx(uint8_t* cid, size_t cid_len, uint8_t* master_secret,
           size_t master_secret_len, uint8_t alg, uint8_t hkdf_alg,
            uint8_t* sid, size_t sid_len, uint8_t* rid, size_t rid_len, uint8_t replay_window){
  //  printf("derrive context\n");

    OSCOAP_COMMON_CONTEXT* common_ctx = memb_alloc(&common_contexts);
    if(common_ctx == NULL) return 0;
   
    OSCOAP_RECIPIENT_CONTEXT* recipient_ctx = memb_alloc(&recipient_contexts);
    if(recipient_ctx == NULL) return 0;
   
    OSCOAP_SENDER_CONTEXT* sender_ctx = memb_alloc(&sender_contexts);
    if(sender_ctx == NULL) return 0;

    memset(zeroes, 0x00, 32);
  
    size_t info_buffer_size;
    info_buffer_size = get_info_len(cid_len, sid_len, CONTEXT_KEY_LEN);
    //Sender Key
    info_buffer_size = get_info_len(cid_len, sid_len, CONTEXT_KEY_LEN);
    compose_info(info_buffer, cid, cid_len, alg, sid, sid_len, CONTEXT_KEY_LEN);
    hkdf(SHA256, zeroes, 32, master_secret, master_secret_len, info_buffer, info_buffer_size, sender_ctx->SENDER_KEY, CONTEXT_KEY_LEN );

    //Sender IV
    info_buffer_size = get_info_len(cid_len, sid_len, CONTEXT_INIT_VECT_LEN);
    compose_info(info_buffer, cid, cid_len, alg, sid, sid_len, CONTEXT_INIT_VECT_LEN);
    hkdf(SHA256, zeroes, 32, master_secret, master_secret_len, info_buffer, info_buffer_size, sender_ctx->SENDER_IV, CONTEXT_INIT_VECT_LEN );

    //Receiver Key
    info_buffer_size = get_info_len(cid_len, rid_len, CONTEXT_KEY_LEN);
    compose_info(info_buffer, cid, cid_len, alg, rid, rid_len, CONTEXT_KEY_LEN);
    hkdf(SHA256, zeroes, 32, master_secret, master_secret_len, info_buffer, info_buffer_size, recipient_ctx->RECIPIENT_KEY, CONTEXT_KEY_LEN );

    //Receiver IV
    info_buffer_size = get_info_len(cid_len, rid_len, CONTEXT_INIT_VECT_LEN);
    compose_info(info_buffer, cid, cid_len, alg, rid, rid_len, CONTEXT_INIT_VECT_LEN);
    hkdf(SHA256, zeroes, 32, master_secret, master_secret_len, info_buffer, info_buffer_size, recipient_ctx->RECIPIENT_IV, CONTEXT_INIT_VECT_LEN );

    common_ctx->BASE_KEY = master_secret;
    common_ctx->BASE_KEY_LEN = master_secret_len;
    common_ctx->ALG = alg;
    memcpy(common_ctx->CONTEXT_ID, cid, CONTEXT_ID_LEN);
    common_ctx->RECIPIENT_CONTEXT = recipient_ctx;
    common_ctx->SENDER_CONTEXT = sender_ctx;
    sender_ctx->SENDER_SEQ = 0;

    recipient_ctx->RECIPIENT_SEQ = 0;
    recipient_ctx->REPLAY_WINDOW = replay_window;
   
   //TODO add checks to assert ( rid_len < ID_LEN && cid_len < ID_len)
    memcpy(recipient_ctx->RECIPIENT_ID, rid, rid_len);
    memcpy(sender_ctx->SENDER_ID, sid, sid_len);
    recipient_ctx->RECIPIENT_ID_LEN = rid_len;
    sender_ctx->SENDER_ID_LEN = sid_len;

    common_ctx->NEXT_CONTEXT = common_context_store;
    common_context_store = common_ctx;
    return common_ctx;

}

//TODO add support for key generation using a base key and HKDF, this will come at a later stage
//TODO add SID 
OSCOAP_COMMON_CONTEXT* oscoap_new_ctx( uint8_t* cid, uint8_t* sw_k, uint8_t* sw_iv, uint8_t* rw_k, uint8_t* rw_iv,
  uint8_t* s_id, uint8_t s_id_len, uint8_t* r_id, uint8_t r_id_len, uint8_t replay_window){
   
    OSCOAP_COMMON_CONTEXT* common_ctx = memb_alloc(&common_contexts);
    if(common_ctx == NULL) return 0;
   
    OSCOAP_RECIPIENT_CONTEXT* recipient_ctx = memb_alloc(&recipient_contexts);
    if(recipient_ctx == NULL) return 0;
   
    OSCOAP_SENDER_CONTEXT* sender_ctx = memb_alloc(&sender_contexts);
    if(sender_ctx == NULL) return 0;

    common_ctx->ALG = COSE_Algorithm_AES_CCM_64_64_128;
    memcpy(common_ctx->CONTEXT_ID, cid, CONTEXT_ID_LEN);
    common_ctx->RECIPIENT_CONTEXT = recipient_ctx;
    common_ctx->SENDER_CONTEXT = sender_ctx;

    memcpy(sender_ctx->SENDER_KEY, sw_k, CONTEXT_KEY_LEN);
    memcpy(sender_ctx->SENDER_IV, sw_iv, CONTEXT_INIT_VECT_LEN);
    sender_ctx->SENDER_SEQ = 0;

    memcpy(recipient_ctx->RECIPIENT_KEY, rw_k, CONTEXT_KEY_LEN);
    memcpy(recipient_ctx->RECIPIENT_IV, rw_iv, CONTEXT_INIT_VECT_LEN);
    recipient_ctx->RECIPIENT_SEQ = 0;
    recipient_ctx->REPLAY_WINDOW = replay_window;
   
    //TODO This is to easly identify the sender and recipient ID
    memcpy(recipient_ctx->RECIPIENT_ID, r_id, r_id_len);
    memcpy(sender_ctx->SENDER_ID, s_id, s_id_len);
    recipient_ctx->RECIPIENT_ID_LEN = r_id_len;
    sender_ctx->SENDER_ID_LEN = s_id_len;

    common_ctx->NEXT_CONTEXT = common_context_store;
    common_context_store = common_ctx;
    
    return common_ctx;
}

OSCOAP_COMMON_CONTEXT* oscoap_find_ctx_by_cid(uint8_t* cid){
    if(common_context_store == NULL){
      return NULL;
    }

    OSCOAP_COMMON_CONTEXT *ctx_ptr = common_context_store;

    while(memcmp(ctx_ptr->CONTEXT_ID, cid, CONTEXT_ID_LEN) != 0){
      ctx_ptr = ctx_ptr->NEXT_CONTEXT;
    
      if(ctx_ptr == NULL){
        return NULL;
      }
    }
    return ctx_ptr;
}

int oscoap_free_ctx(OSCOAP_COMMON_CONTEXT *ctx){

    if(common_context_store == ctx){
      common_context_store = ctx->NEXT_CONTEXT;

    }else{

      OSCOAP_COMMON_CONTEXT *ctx_ptr = common_context_store;

      while(ctx_ptr->NEXT_CONTEXT != ctx){
        ctx_ptr = ctx_ptr->NEXT_CONTEXT;
      }

      if(ctx_ptr->NEXT_CONTEXT->NEXT_CONTEXT != NULL){
        ctx_ptr->NEXT_CONTEXT = ctx_ptr->NEXT_CONTEXT->NEXT_CONTEXT;
      }else{
        ctx_ptr->NEXT_CONTEXT = NULL;
      }
    }
    memset(ctx->BASE_KEY, 0x00, ctx->BASE_KEY_LEN);
    memset(ctx->SENDER_CONTEXT->SENDER_KEY, 0x00, CONTEXT_KEY_LEN);
    memset(ctx->SENDER_CONTEXT->SENDER_IV, 0x00, CONTEXT_INIT_VECT_LEN);
    memset(ctx->RECIPIENT_CONTEXT->RECIPIENT_KEY, 0x00, CONTEXT_KEY_LEN);
    memset(ctx->RECIPIENT_CONTEXT->RECIPIENT_IV, 0x00, CONTEXT_INIT_VECT_LEN);

    int ret = 0;
    ret += memb_free(&sender_contexts, ctx->SENDER_CONTEXT);
    ret += memb_free(&recipient_contexts, ctx->RECIPIENT_CONTEXT);
    ret += memb_free(&common_contexts, ctx);
  
    return ret;
}
