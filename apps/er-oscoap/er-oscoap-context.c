
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

//oscoap_ctx_t
//oscoap_sender_ctx_t
//oscoap_recipient_ctx_t
//sender_key
//sender_iv
oscoap_ctx_t *common_context_store = NULL;
token_seq_t *token_seq_store = NULL;

MEMB(common_contexts, oscoap_ctx_t, CONTEXT_NUM);
MEMB(sender_contexts, oscoap_sender_ctx_t, CONTEXT_NUM);
MEMB(recipient_contexts, oscoap_recipient_ctx_t, CONTEXT_NUM);

MEMB(token_seq, token_seq_t, TOKEN_SEQ_NUM);

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
        text = "key";
        text_len = 3;
    } else {
        text = "IV";
        text_len = 2;
    }

    ret += OPT_CBOR_put_text(&buffer, text, text_len);
    ret += OPT_CBOR_put_unsigned(&buffer, out_len);
    return ret;
}


oscoap_ctx_t* oscoap_derrive_ctx(uint8_t* master_secret,uint8_t master_secret_len,
       uint8_t* master_salt, uint8_t master_salt_len, uint8_t alg, uint8_t hkdf_alg,
            uint8_t* sid, uint8_t sid_len, uint8_t* rid, uint8_t rid_len, uint8_t replay_window){
  //  PRINTF("derrive context\n");

    oscoap_ctx_t* common_ctx = memb_alloc(&common_contexts);
    if(common_ctx == NULL) return 0;

    oscoap_recipient_ctx_t* recipient_ctx = memb_alloc(&recipient_contexts);
    if(recipient_ctx == NULL) return 0;

    oscoap_sender_ctx_t* sender_ctx = memb_alloc(&sender_contexts);
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

    //sender_ key
 //   info_buffer_size = get_info_len( sid_len, CONTEXT_KEY_LEN);
    info_len = compose_info(info_buffer, alg, sid, sid_len, CONTEXT_KEY_LEN);
  //  PRINTF("sender_ key info len: %d\n", info_len);
  //  PRINTF_HEX(info_buffer, info_len);
    hkdf(SHA256, salt, salt_len, master_secret, master_secret_len, info_buffer, info_len, sender_ctx->sender_key, CONTEXT_KEY_LEN );

    //sender_ IV
 //   info_buffer_size = get_info_len( sid_len, CONTEXT_INIT_VECT_LEN);
    info_len = compose_info(info_buffer, alg, sid, sid_len, CONTEXT_INIT_VECT_LEN);
 //   PRINTF("sender_ IV info len: %d\n", info_len);
 //   PRINTF_HEX(info_buffer, info_len);
    hkdf(SHA256, salt, salt_len, master_secret, master_secret_len, info_buffer, info_len, sender_ctx->sender_iv, CONTEXT_INIT_VECT_LEN );

    //Receiver key
   // info_buffer_size = get_info_len( rid_len, CONTEXT_KEY_LEN);
    info_len = compose_info(info_buffer, alg, rid, rid_len, CONTEXT_KEY_LEN);
 //   PRINTF("Receiver key info len: %d\n", info_len);
 //   PRINTF_HEX(info_buffer, info_len);
    hkdf(SHA256, salt, salt_len, master_secret, master_secret_len, info_buffer, info_len, recipient_ctx->recipient_key, CONTEXT_KEY_LEN );

    //Receiver IV
  //  info_buffer_size = get_info_len( rid_len, CONTEXT_INIT_VECT_LEN);
    info_len = compose_info(info_buffer, alg, rid, rid_len, CONTEXT_INIT_VECT_LEN);
  //  PRINTF("Receiver IV info len: %d\n", info_len);
  //  PRINTF_HEX(info_buffer, info_len);
    hkdf(SHA256, salt, salt_len, master_secret, master_secret_len, info_buffer, info_len, recipient_ctx->recipient_iv, CONTEXT_INIT_VECT_LEN );

    common_ctx->master_secret = master_secret;
    common_ctx->master_secret_len = master_secret_len;
    common_ctx->master_salt = master_salt;
    common_ctx->master_salt_len = master_salt_len;
    common_ctx->alg = alg;

    common_ctx->recipient_context = recipient_ctx;
    common_ctx->sender_context = sender_ctx;
   

    sender_ctx->sender_id = sid;
    sender_ctx->sender_id_len = sid_len;   
    sender_ctx->seq = 0;

    recipient_ctx->recipient_id = rid;
    recipient_ctx->recipient_id_len = rid_len;
    recipient_ctx->last_seq = 0;
    recipient_ctx->highest_seq = 0;
    recipient_ctx->replay_window_size = replay_window;
    recipient_ctx->rollback_last_seq = 0;
    recipient_ctx->sliding_window = 0;
    recipient_ctx->rollback_sliding_window = 0;
    recipient_ctx->initial_state = 1;
   

    common_ctx->next_context = common_context_store;
    common_context_store = common_ctx;
    return common_ctx;

}

//TODO add support for key generation using a base key and HKDF, this will come at a later stage
//TODO add SID 
oscoap_ctx_t* oscoap_new_ctx( uint8_t* sw_k, uint8_t* sw_iv, uint8_t* rw_k, uint8_t* rw_iv,
  uint8_t* s_id, uint8_t s_id_len, uint8_t* r_id, uint8_t r_id_len, uint8_t replay_window){
   
    oscoap_ctx_t* common_ctx = memb_alloc(&common_contexts);
    if(common_ctx == NULL) return 0;
   
    oscoap_recipient_ctx_t* recipient_ctx = memb_alloc(&recipient_contexts);
    if(recipient_ctx == NULL) return 0;
   
    oscoap_sender_ctx_t* sender_ctx = memb_alloc(&sender_contexts);
    if(sender_ctx == NULL) return 0;

    common_ctx->alg = COSE_Algorithm_AES_CCM_64_64_128;

    common_ctx->recipient_context = recipient_ctx;
    common_ctx->sender_context = sender_ctx;

    memcpy(sender_ctx->sender_key, sw_k, CONTEXT_KEY_LEN);
    memcpy(sender_ctx->sender_iv, sw_iv, CONTEXT_INIT_VECT_LEN);
    
    sender_ctx->sender_id =  s_id;
    sender_ctx->sender_id_len = s_id_len;
    sender_ctx->seq = 0;

    memcpy(recipient_ctx->recipient_key, rw_k, CONTEXT_KEY_LEN);
    memcpy(recipient_ctx->recipient_iv, rw_iv, CONTEXT_INIT_VECT_LEN);
   

    recipient_ctx->recipient_id = r_id;
    recipient_ctx->recipient_id_len = r_id_len;
    recipient_ctx->last_seq = 0;
    recipient_ctx->highest_seq = 0;
    recipient_ctx->replay_window_size = replay_window;
    recipient_ctx->rollback_last_seq = 0;
    recipient_ctx->sliding_window = 0;
    recipient_ctx->rollback_sliding_window = 0;
    recipient_ctx->initial_state = 1;

    common_ctx->next_context = common_context_store;
    common_context_store = common_ctx;
    
    return common_ctx;
}
/*
oscoap_ctx_t* oscoap_find_ctx_by_cid(uint8_t* cid){
    if(common_context_store == NULL){
      return NULL;
    }

    oscoap_ctx_t *ctx_ptr = common_context_store;

    while(memcmp(ctx_ptr->Contextid, cid, CONTEXT_ID_LEN) != 0){
      ctx_ptr = ctx_ptr->next_context;
    
      if(ctx_ptr == NULL){
        return NULL;
      }
    }
    return ctx_ptr;
} */

uint8_t bytes_equal(uint8_t* a_ptr, uint8_t a_len, uint8_t* b_ptr, uint8_t b_len){
	if(a_len != b_len){
		return 0;
	}
	
	if( memcmp(a_ptr, b_ptr, a_len) == 0){
		return 1;
	} else {
		return 0;
	}
}

oscoap_ctx_t* oscoap_find_ctx_by_rid(uint8_t* rid, uint8_t rid_len){
    if(common_context_store == NULL){
      return NULL;
    }
    PRINTF("looking for:\n");
    PRINTF_HEX(rid, rid_len);

    oscoap_ctx_t *ctx_ptr = common_context_store;
	
    while(!bytes_equal(ctx_ptr->recipient_context->recipient_id, ctx_ptr->recipient_context->recipient_id_len, rid, rid_len)){
    PRINTF("tried:\n");
    PRINTF_HEX(ctx_ptr->recipient_context->recipient_id, ctx_ptr->recipient_context->recipient_id_len);
      ctx_ptr = ctx_ptr->next_context;
      
      if(ctx_ptr == NULL){
        return NULL;
      }
    }
    return ctx_ptr;
}

oscoap_ctx_t* oscoap_find_ctx_by_token(uint8_t* token, uint8_t token_len){
    if(common_context_store == NULL){
      return NULL;
    }
    PRINTF("looking for:\n");
    PRINTF_HEX(token, token_len);

    oscoap_ctx_t *ctx_ptr = common_context_store;
  
    while(!bytes_equal(ctx_ptr->sender_context->token, ctx_ptr->sender_context->token_len,  token, token_len)){
     PRINTF("tried:\n");
     PRINTF_HEX(ctx_ptr->sender_context->token, ctx_ptr->sender_context->token_len);
      ctx_ptr = ctx_ptr->next_context;
      
      if(ctx_ptr == NULL){
        return NULL;
      }
    }
    return ctx_ptr;
}

int oscoap_free_ctx(oscoap_ctx_t *ctx){

    if(common_context_store == ctx){
      common_context_store = ctx->next_context;

    }else{

      oscoap_ctx_t *ctx_ptr = common_context_store;

      while(ctx_ptr->next_context != ctx){
        ctx_ptr = ctx_ptr->next_context;
      }

      if(ctx_ptr->next_context->next_context != NULL){
        ctx_ptr->next_context = ctx_ptr->next_context->next_context;
      }else{
        ctx_ptr->next_context = NULL;
      }
    }

    memset(ctx->master_secret, 0x00, ctx->master_secret_len);
    memset(ctx->master_salt, 0x00, ctx->master_salt_len);
    memset(ctx->sender_context->sender_key, 0x00, CONTEXT_KEY_LEN);
    memset(ctx->sender_context->sender_iv, 0x00, CONTEXT_INIT_VECT_LEN);
    memset(ctx->recipient_context->recipient_key, 0x00, CONTEXT_KEY_LEN);
    memset(ctx->recipient_context->recipient_iv, 0x00, CONTEXT_INIT_VECT_LEN);

    int ret = 0;
    ret += memb_free(&sender_contexts, ctx->sender_context);
    ret += memb_free(&recipient_contexts, ctx->recipient_context);
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
}

uint8_t get_seq_from_token(uint8_t* token, uint8_t token_len, uint32_t* seq){
   token_seq_t* ptr = token_seq_store;

  while(!bytes_equal(ptr->token, ptr->token_len,  token, token_len)){
    
    ptr = ptr->next;
    if(ptr == NULL){
      return 0; //TODO handle error
    }

  }

  *seq = ptr->seq;

  PRINTF("fetching seq %" PRIu32 "\n with token :", *seq);
  PRINTF_HEX(token, token_len);
  return 1; 

}

void remove_seq_from_token(uint8_t* token, uint8_t token_len){
  token_seq_t* ptr = token_seq_store;


  if(bytes_equal(ptr->token, ptr->token_len, token, token_len)){ // first element
    token_seq_store = ptr->next;
    memb_free(&token_seq, ptr);
    return;
  }

  ptr = ptr->next;
  
  while(1){
    if(ptr == NULL){
      return;
    }
    
    if(bytes_equal(ptr->next->token, ptr->token_len, token, token_len)){
      token_seq_t* tmp = ptr->next;
      ptr->next = ptr->next->next;
      memb_free(&token_seq, tmp);
      return;
    }

    ptr = ptr->next;
    
  }


}

uint8_t set_seq_from_token(uint8_t* token, uint8_t token_len, uint32_t seq){
  token_seq_t* token_seq_ptr = memb_alloc(&token_seq);
  if(token_seq_ptr == NULL){
    return 0;
  }

  memcpy(token_seq_ptr->token, token, token_len);
  token_seq_ptr->token_len = token_len;
  token_seq_ptr->seq = seq;
  token_seq_ptr->next = token_seq_store;
  token_seq_store = token_seq_ptr;
  PRINTF("storing seq %" PRIu32 "\n with token :", seq);
  PRINTF_HEX(token, token_len);
  return 1;
}

#define DEBUG 1
#if DEBUG
void oscoap_print_context(oscoap_ctx_t* ctx){

    PRINTF("Print Context:\n");
    PRINTF("Master Secret: ");
    PRINTF_HEX(ctx->master_secret, ctx->master_secret_len);
    PRINTF("Master Salt\n");
    PRINTF_HEX(ctx->master_salt, ctx->master_salt_len);
    PRINTF("ALG: %d\n", ctx->alg);
    oscoap_sender_ctx_t* s = ctx->sender_context;
    PRINTF("sender_ Context: {\n");
    PRINTF("\tsender_ ID: ");
    PRINTF_HEX(s->sender_id, s->sender_id_len);
    PRINTF("\tsender_ key: ");
    PRINTF_HEX(s->sender_key, CONTEXT_KEY_LEN);
    PRINTF("\tsender_ IV: ");
    PRINTF_HEX(s->sender_iv, CONTEXT_INIT_VECT_LEN);
    PRINTF("}\n");

    oscoap_recipient_ctx_t* r = ctx->recipient_context;
    PRINTF("recipient_ Context: {\n");
    PRINTF("\trecipient_ ID: ");
    PRINTF_HEX(r->recipient_id, r->recipient_id_len);
    PRINTF("\trecipient_ key: ");
    PRINTF_HEX(r->recipient_key, CONTEXT_KEY_LEN);
    PRINTF("\trecipient_ IV: ");
    PRINTF_HEX(r->recipient_iv, CONTEXT_INIT_VECT_LEN);
    PRINTF("}\n");


}
#endif  
