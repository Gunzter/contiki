
#include "er-oscoap-context.h"
#include "er-oscoap.h"
#include "opt-cbor.h"
#include "opt-cose.h"


#define DEBUG 0
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
TokenSeq *token_seq_store = NULL;

MEMB(common_contexts, OscoapCommonContext, CONTEXT_NUM);
MEMB(sender_contexts, OscoapSenderContext, CONTEXT_NUM);
MEMB(recipient_contexts, OscoapRecipientContext, CONTEXT_NUM);

MEMB(token_seq, TokenSeq, TOKEN_SEQ_NUM);

void oscoap_ctx_store_init(){

  memb_init(&common_contexts);
  memb_init(&sender_contexts);
  memb_init(&recipient_contexts);
}

uint8_t get_info_len(uint8_t id_len, uint8_t out_len){
  uint8_t len = id_len;
  if(out_len == 16){
    len += 3;
  } else {
    len += 2;
  }
  len += 6;
  return len;
}

uint8_t compose_info(uint8_t* buffer, uint8_t alg, uint8_t* id, uint8_t id_len, uint8_t out_len){
    uint8_t ret = 0;
    ret += OPT_CBOR_put_array(&buffer, 4);
    ret += OPT_CBOR_put_bytes(&buffer, id_len, id);
    ret += OPT_CBOR_put_unsigned(&buffer, alg);
    char* text;
    uint8_t text_len;
    if( out_len == 16 ){
        text = "Key";
        text_len = 3;
    } else {
        text = "IV";
        text_len = 2;
    }

    ret += OPT_CBOR_put_text(&buffer, text, text_len);
    ret += OPT_CBOR_put_unsigned(&buffer, out_len);
    return ret;
}


OscoapCommonContext* oscoap_derrive_ctx(uint8_t* master_secret,uint8_t master_secret_len,
       uint8_t* master_salt, uint8_t master_salt_len, uint8_t alg, uint8_t hkdf_alg,
            uint8_t* sid, uint8_t sid_len, uint8_t* rid, uint8_t rid_len, uint8_t replay_window){
  //  PRINTF("derrive context\n");

    OscoapCommonContext* common_ctx = memb_alloc(&common_contexts);
    if(common_ctx == NULL) return 0;

    OscoapRecipientContext* recipient_ctx = memb_alloc(&recipient_contexts);
    if(recipient_ctx == NULL) return 0;

    OscoapSenderContext* sender_ctx = memb_alloc(&sender_contexts);
    if(sender_ctx == NULL) return 0;

    uint8_t zeroes[32];
    uint8_t info_buffer[15]; 

    uint8_t* salt;
    uint8_t  salt_len;

    if(master_secret_len == 0 || master_salt == NULL){
      memset(zeroes, 0x00, 32);
      salt = zeroes;
      salt_len = 32;
    } else {
      salt = master_salt;
      salt_len = master_salt_len;
    }
  
  //  uint8_t info_buffer_size;
    uint8_t info_len;

    //Sender Key
 //   info_buffer_size = get_info_len( sid_len, CONTEXT_KEY_LEN);
    info_len = compose_info(info_buffer, alg, sid, sid_len, CONTEXT_KEY_LEN);
  //  PRINTF("Sender key info len: %d\n", info_len);
  //  PRINTF_HEX(info_buffer, info_len);
    hkdf(SHA256, salt, salt_len, master_secret, master_secret_len, info_buffer, info_len, sender_ctx->SenderKey, CONTEXT_KEY_LEN );

    //Sender IV
 //   info_buffer_size = get_info_len( sid_len, CONTEXT_INIT_VECT_LEN);
    info_len = compose_info(info_buffer, alg, sid, sid_len, CONTEXT_INIT_VECT_LEN);
 //   PRINTF("Sender IV info len: %d\n", info_len);
 //   PRINTF_HEX(info_buffer, info_len);
    hkdf(SHA256, salt, salt_len, master_secret, master_secret_len, info_buffer, info_len, sender_ctx->SenderIv, CONTEXT_INIT_VECT_LEN );

    //Receiver Key
   // info_buffer_size = get_info_len( rid_len, CONTEXT_KEY_LEN);
    info_len = compose_info(info_buffer, alg, rid, rid_len, CONTEXT_KEY_LEN);
 //   PRINTF("Receiver Key info len: %d\n", info_len);
 //   PRINTF_HEX(info_buffer, info_len);
    hkdf(SHA256, salt, salt_len, master_secret, master_secret_len, info_buffer, info_len, recipient_ctx->RecipientKey, CONTEXT_KEY_LEN );

    //Receiver IV
  //  info_buffer_size = get_info_len( rid_len, CONTEXT_INIT_VECT_LEN);
    info_len = compose_info(info_buffer, alg, rid, rid_len, CONTEXT_INIT_VECT_LEN);
  //  PRINTF("Receiver IV info len: %d\n", info_len);
  //  PRINTF_HEX(info_buffer, info_len);
    hkdf(SHA256, salt, salt_len, master_secret, master_secret_len, info_buffer, info_len, recipient_ctx->RecipientIv, CONTEXT_INIT_VECT_LEN );

    common_ctx->MasterSecret = master_secret;
    common_ctx->MasterSecretLen = master_secret_len;
    common_ctx->MasterSalt = master_salt;
    common_ctx->MasterSaltLen = master_salt_len;
    common_ctx->Alg = alg;

    common_ctx->RecipientContext = recipient_ctx;
    common_ctx->SenderContext = sender_ctx;
   

    sender_ctx->SenderId = sid;
    sender_ctx->SenderIdLen = sid_len;   
    sender_ctx->Seq = 0;

    recipient_ctx->RecipientId = rid;
    recipient_ctx->RecipientIdLen = rid_len;
    recipient_ctx->LastSeq = 0;
    recipient_ctx->HighestSeq = 0;
    recipient_ctx->ReplayWindowSize = replay_window;
    recipient_ctx->RollbackLastSeq = 0;
    recipient_ctx->SlidingWindow = 0;
    recipient_ctx->RollbackSlidingWindow = 0;
    recipient_ctx->InitialState = 1;
   

    common_ctx->NextContext = common_context_store;
    common_context_store = common_ctx;
    return common_ctx;

}

//TODO add support for key generation using a base key and HKDF, this will come at a later stage
//TODO add SID 
OscoapCommonContext* oscoap_new_ctx( uint8_t* sw_k, uint8_t* sw_iv, uint8_t* rw_k, uint8_t* rw_iv,
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
    
    sender_ctx->SenderId =  s_id;
    sender_ctx->SenderIdLen = s_id_len;
    sender_ctx->Seq = 0;

    memcpy(recipient_ctx->RecipientKey, rw_k, CONTEXT_KEY_LEN);
    memcpy(recipient_ctx->RecipientIv, rw_iv, CONTEXT_INIT_VECT_LEN);
   

    recipient_ctx->RecipientId = r_id;
    recipient_ctx->RecipientIdLen = r_id_len;
    recipient_ctx->LastSeq = 0;
    recipient_ctx->HighestSeq = 0;
    recipient_ctx->ReplayWindowSize = replay_window;
    recipient_ctx->RollbackLastSeq = 0;
    recipient_ctx->SlidingWindow = 0;
    recipient_ctx->RollbackSlidingWindow = 0;
    recipient_ctx->InitialState = 1;

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

OscoapCommonContext* oscoap_find_ctx_by_rid(uint8_t* rid, uint8_t rid_len){
    if(common_context_store == NULL){
      return NULL;
    }
    PRINTF("looking for:\n");
    PRINTF_HEX(rid, rid_len);

    OscoapCommonContext *ctx_ptr = common_context_store;
    uint8_t cmp_len = MIN(rid_len, ctx_ptr->RecipientContext->RecipientIdLen);

    while(memcmp(ctx_ptr->RecipientContext->RecipientId, rid, cmp_len) != 0){
    PRINTF("tried:\n");
    PRINTF_HEX(ctx_ptr->RecipientContext->RecipientId, ctx_ptr->RecipientContext->RecipientIdLen);
      ctx_ptr = ctx_ptr->NextContext;
      
      if(ctx_ptr == NULL){
        return NULL;
      }
      cmp_len = MIN(rid_len, ctx_ptr->RecipientContext->RecipientIdLen);
    }
    return ctx_ptr;
}

OscoapCommonContext* oscoap_find_ctx_by_token(uint8_t* token, uint8_t token_len){
    if(common_context_store == NULL){
      return NULL;
    }
    PRINTF("looking for:\n");
    PRINTF_HEX(token, token_len);

    OscoapCommonContext *ctx_ptr = common_context_store;
    uint8_t cmp_len = MIN(token_len, ctx_ptr->SenderContext->TokenLen);

    while(memcmp(ctx_ptr->SenderContext->Token, token, cmp_len) != 0){
     PRINTF("tried:\n");
     PRINTF_HEX(ctx_ptr->SenderContext->Token, ctx_ptr->SenderContext->TokenLen);
      ctx_ptr = ctx_ptr->NextContext;
      
      if(ctx_ptr == NULL){
        return NULL;
      }
      cmp_len = MIN(token_len, ctx_ptr->SenderContext->TokenLen);
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
    memset(ctx->MasterSalt, 0x00, ctx->MasterSaltLen);
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

/*
void list_init(list_t list); // Initialize a list.
void *list_head(list_t list); // Get a pointer to the first item of a list.
void *list_tail(list_t list); // Get the tail of a list. 
void *list_item_next(void *item); // Get the next item of a list. 
int list_length(list_t list); // Get the length of a list. 
void list_push(list_t list, void *item); // Add an item to the start of the list.
void list_add(list_t list, void *item); // Add an item at the end of a list.
void list_insert(list_t list, void *previtem, void *newitem); // Insert an item after a specified item on the list. 
void *list_pop(list_t list); // Remove the first object on a list. 
void *list_chop(list_t list); // Remove the last object on the list. 
void list_remove(list_t list, void *item); // Remove a specific element from a list.
*/
void init_token_seq_store(){
  memb_init(&token_seq);
  //list_init(list_t list);
}

uint8_t get_seq_from_token(uint8_t* token, uint8_t token_len, uint32_t* seq){
   TokenSeq* ptr = token_seq_store;

   uint8_t cmp_len = MIN(token_len, ptr->TokenLen);

  while(memcmp(ptr->Token, token, cmp_len) != 0){
    
    ptr = ptr->Next;
    if(ptr == NULL){
      return 0; //TODO handle error
    }

    cmp_len = MIN(token_len, ptr->TokenLen);
  }

  *seq = ptr->Seq;

  PRINTF("fetching seq %" PRIu32 "\n with token :", *seq);
  PRINTF_HEX(token, token_len);
  return 1; 

}

void remove_seq_from_token(uint8_t* token, uint8_t token_len){
  TokenSeq* ptr = token_seq_store;

  uint8_t cmp_len = MIN(token_len, ptr->TokenLen);
  if(memcmp(ptr->Token, token, cmp_len) == 0){ // first element
    token_seq_store = ptr->Next;
    memb_free(&token_seq, ptr);
    return;
  }

  ptr = ptr->Next;
  
  while(1){
    if(ptr == NULL){
      return;
    }
    cmp_len = MIN(token_len, ptr->Next->TokenLen);
    if(memcmp(ptr->Next->Token, token, cmp_len) == 0){
      TokenSeq* tmp = ptr->Next;
      ptr->Next = ptr->Next->Next;
      memb_free(&token_seq, tmp);
      return;
    }

    ptr = ptr->Next;
    
  }


}

uint8_t set_seq_from_token(uint8_t* token, uint8_t token_len, uint32_t seq){
  TokenSeq* token_seq_ptr = memb_alloc(&token_seq);
  if(token_seq_ptr == NULL){
    return 0;
  }

  memcpy(token_seq_ptr->Token, token, token_len);
  token_seq_ptr->TokenLen = token_len;
  token_seq_ptr->Seq = seq;
  token_seq_ptr->Next = token_seq_store;
  token_seq_store = token_seq_ptr;
  PRINTF("storing seq %" PRIu32 "\n with token :", seq);
  PRINTF_HEX(token, token_len);
  return 1;
}

#if DEBUG
void oscoap_print_context(OscoapCommonContext* ctx){

    PRINTF("Print Context:\n");
    PRINTF("Master Secret: ");
    PRINTF_HEX(ctx->MasterSecret, ctx->MasterSecretLen);
    PRINTF("Master Salt\n");
    PRINTF_HEX(ctx->MasterSalt, ctx->MasterSaltLen);
    PRINTF("ALG: %d\n", ctx->Alg);
    OscoapSenderContext* s = ctx->SenderContext;
    PRINTF("Sender Context: {\n");
    PRINTF("\tSender ID: ");
    PRINTF_HEX(s->SenderId, s->SenderIdLen);
    PRINTF("\tSender Key: ");
    PRINTF_HEX(s->SenderKey, CONTEXT_KEY_LEN);
    PRINTF("\tSender IV: ");
    PRINTF_HEX(s->SenderIv, CONTEXT_INIT_VECT_LEN);
    PRINTF("}\n");

    OscoapRecipientContext* r = ctx->RecipientContext;
    PRINTF("Recipient Context: {\n");
    PRINTF("\tRecipient ID: ");
    PRINTF_HEX(r->RecipientId, r->RecipientIdLen);
    PRINTF("\tRecipient Key: ");
    PRINTF_HEX(r->RecipientKey, CONTEXT_KEY_LEN);
    PRINTF("\tRecipient IV: ");
    PRINTF_HEX(r->RecipientIv, CONTEXT_INIT_VECT_LEN);
    PRINTF("}\n");


}
#endif  
