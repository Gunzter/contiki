/*
Copyright (c) 2016, SICS
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the 
following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the 
following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the 
following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote 
products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE 
USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/**
 * \file
 *      A trial implementation of OSCOAP. Based on er-coap by Matthias Kovatsch <kovatsch@inf.ethz.ch>
 * \author
 *      Martin Gunnarsson martin.gunnarsson@sics.se and Joakim Brorsson b.joakim@gmail.com
 */
#include "er-oscoap.h"
#include "er-oscoap-context.h"

#include "er-coap.h"
#include "dev/watchdog.h"
#include <stdbool.h>

#include "opt-cose.h"
#include "opt-cbor.h"
#include <inttypes.h>
#include <sys/types.h>
#include "cose-compression.h"

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

//TODO this is a hotfix, maybe have this in the context instead
uint32_t observe_seq = 0;
uint32_t observing_seq = 0;

void parse_int(uint64_t in, uint8_t* bytes, int out_len){ 
	int x = out_len - 1;
	while(x >= 0){
		bytes[x] = (in >> (x * 8)) & 0xFF;
		x--;
	}
}

uint8_t to_bytes(uint32_t in, uint8_t* buffer){
//  PRINTF("in %" PRIu64 "\n", in);
	uint8_t outlen = 1;

  if(in > 255 && in <= 65535){
    outlen = 2;
  } else if( in > 65535 && in <= 16777215){
    outlen = 3;
  } else if( in > 16777215 ){
    outlen = 4;
  }

  parse_int(in, buffer, outlen);
	return outlen;
}

uint32_t bytes_to_uint32(uint8_t* bytes, size_t len){
  uint8_t buffer[4];
  memset(buffer, 0, 4); //function variables are not initializated to anything
  int offset = 4 - len;
  uint32_t num;
  
  memcpy((uint8_t*)(buffer + offset), bytes, len);

  num = 
      (uint32_t)buffer[0] << 24 |
      (uint32_t)buffer[1] << 16 |
      (uint32_t)buffer[2] << 8  |
      (uint32_t)buffer[3];

  return num;
}

uint8_t coap_is_request(coap_packet_t* coap_pkt){
	if(coap_pkt->code >= COAP_GET && coap_pkt->code <= COAP_DELETE){ 
		return 1;
	} else {
		return 0;
	}
}


size_t oscoap_prepare_external_aad(coap_packet_t* coap_pkt, opt_cose_encrypt_t* cose, uint8_t* buffer, uint8_t sending){

  uint8_t ret = 0;
  uint8_t seq_buffer[8];
  uint8_t protected_buffer[25];
  size_t  protected_len;
  ret += OPT_CBOR_put_array(&buffer, 6);
  ret += OPT_CBOR_put_unsigned(&buffer, 1); //version is always 1
  ret += OPT_CBOR_put_unsigned(&buffer, (coap_pkt->code));
  int32_t obs;

  if(!coap_is_request(coap_pkt) && IS_OPTION(coap_pkt, COAP_OPTION_OBSERVE)){

    if( sending == 1){
      coap_set_header_observe(coap_pkt, observe_seq);
    } else {
      int s = coap_get_header_observe(coap_pkt, &obs);
    }
    protected_len = oscoap_serializer(coap_pkt, protected_buffer, ROLE_PROTECTED);
    PRINTF("protected, len %d\n", protected_len);
    PRINTF_HEX(protected_buffer, protected_len);
 
  } else {
    protected_len = 0;
  }
  ret += OPT_CBOR_put_bytes(&buffer, protected_len, protected_buffer); 
  ret += OPT_CBOR_put_unsigned(&buffer, (coap_pkt->context->alg));


  if(sending == 1){
    if(coap_is_request(coap_pkt)) {
  
      uint8_t seq_len = to_bytes(coap_pkt->context->sender_context->seq, seq_buffer);

      ret += OPT_CBOR_put_bytes(&buffer, coap_pkt->context->sender_context->sender_id_len, coap_pkt->context->sender_context->sender_id);
      ret += OPT_CBOR_put_bytes(&buffer, seq_len, seq_buffer);
    } else {
        uint8_t seq_len = to_bytes(coap_pkt->context->recipient_context->last_seq, seq_buffer);
      
      ret += OPT_CBOR_put_bytes(&buffer, coap_pkt->context->recipient_context->recipient_id_len, coap_pkt->context->recipient_context->recipient_id);
      ret += OPT_CBOR_put_bytes(&buffer, seq_len, seq_buffer);
    } 
  } else {
    
    if(coap_is_request(coap_pkt)){
        uint8_t seq_len = to_bytes(coap_pkt->context->recipient_context->last_seq, seq_buffer);

        ret += OPT_CBOR_put_bytes(&buffer, coap_pkt->context->recipient_context->recipient_id_len, coap_pkt->context->recipient_context->recipient_id);
        ret += OPT_CBOR_put_bytes(&buffer, seq_len, seq_buffer);
    } else {
        if( IS_OPTION(coap_pkt, COAP_OPTION_OBSERVE) ){
          uint8_t seq_len = to_bytes(observing_seq, seq_buffer);
          
          ret += OPT_CBOR_put_bytes(&buffer, coap_pkt->context->sender_context->sender_id_len, coap_pkt->context->sender_context->sender_id);
          ret += OPT_CBOR_put_bytes(&buffer, seq_len, seq_buffer);
        } else {
          uint8_t seq_len = to_bytes(coap_pkt->context->sender_context->seq, seq_buffer);
          
          ret += OPT_CBOR_put_bytes(&buffer, coap_pkt->context->sender_context->sender_id_len, coap_pkt->context->sender_context->sender_id);
          ret += OPT_CBOR_put_bytes(&buffer, cose->partial_iv_len, cose->partial_iv);
        }
    } 

  }
    
  return ret;
  
}


size_t oscoap_external_aad_size(coap_packet_t* coap_pkt ){
  size_t ret = 0;
  if(coap_is_request(coap_pkt)){
      ret += 7;
   //   ret += coap_get_header_uri_path(coap_pkt, NULL);
      ret += 55; //upper bound ish for IP ADDR
  } else { // Response
      ret += 8+4;
      ret += 7;
  }

  //return ret;
  return 30; //TODO FIX THIS!
}



uint8_t oscoap_increment_sender_seq(oscoap_ctx_t* ctx){
    ctx->sender_context->seq++; 
    PRINTF("NEW SENDER SEQ: %" PRIu32 "\n", ctx->sender_context->seq);
    
    if(ctx->sender_context->seq >= OSCOAP_SEQ_MAX ){
      return 0;
    } else {
      return 1;
    }

}


uint8_t oscoap_validate_receiver_seq(oscoap_recipient_ctx_t* ctx, opt_cose_encrypt_t *cose){

  uint32_t incomming_seq = bytes_to_uint32(cose->partial_iv, cose->partial_iv_len);
  PRINTF("SEQ: incomming %" PRIu32 "\n", incomming_seq);
  PRINTF("SEQ: last %" PRIu32 "\n", ctx->last_seq);
  PRINTF_HEX(cose->partial_iv, cose->partial_iv_len);
   if (ctx->last_seq >= OSCOAP_SEQ_MAX) {
            PRINTF("SEQ ERROR: wrapped\n");
            return OSCOAP_SEQ_WRAPPED;
   }
  
  ctx->rollback_last_seq = ctx->last_seq; //recipient_seq;
  ctx->rollback_sliding_window = ctx->sliding_window;

  if (incomming_seq > ctx->highest_seq) {
     //Update the replay window
     int shift = incomming_seq - ctx->last_seq;
     ctx->sliding_window = ctx->sliding_window << shift;
     ctx->highest_seq = incomming_seq;
            
            
  } else if (incomming_seq == ctx->highest_seq) {
     // Special case since we do not use unisgned int for seq
     if(ctx->initial_state == 1 ){ 
        ctx->initial_state = 0;
        int shift = incomming_seq - ctx->highest_seq;
        ctx->sliding_window = ctx->sliding_window << shift;
        ctx->highest_seq = incomming_seq;
        
     } else {
        PRINTF("SEQ ERROR: replay\n");
        return OSCOAP_SEQ_REPLAY;
     }
  } else { //seq < this.recipient_seq
     if (incomming_seq + ctx->replay_window_size < ctx->highest_seq) {
        PRINTF("SEQ ERROR: old\n");
        return OSCOAP_SEQ_OLD_MESSAGE;
     }
     // seq+replay_window_size > recipient_seq
     int shift = ctx->highest_seq - incomming_seq;
     uint32_t pattern = 1 << shift;
     uint32_t verifier = ctx->sliding_window & pattern;
     verifier = verifier >> shift;
     if (verifier == 1) {
        PRINTF("SEQ ERROR: replay\n");
        return OSCOAP_SEQ_REPLAY;
     }
     ctx->sliding_window = ctx->sliding_window | pattern;
  }

  ctx->last_seq = incomming_seq;
  return 0;

}

void roll_back_seq(oscoap_recipient_ctx_t* ctx) {
  if (ctx->rollback_sliding_window != 0) {
      ctx->sliding_window =  ctx->rollback_sliding_window; 
      ctx->rollback_sliding_window = 0;
  }
  if (ctx->rollback_last_seq != 0) {
      ctx->last_seq = ctx->rollback_last_seq;
      ctx->rollback_last_seq = 0;
  }

}

/* Compose the nonce by XORing the static IV (Client Write IV) with
   the Partial IV parameter, received in the COSE Object.   */
void create_nonce(uint8_t* iv, uint8_t* out, uint8_t* seq, int seq_len ){

  memcpy(out, iv, 7);
	int i = 6;
	int j = seq_len - 1;
	while(i > (6-seq_len)){
		out[i] = out[i] ^ seq[j];
		j--;
		i--;
	}

}

size_t oscoap_prepare_message(void* packet, uint8_t *buffer){
    
  PRINTF("PREPARE MESAGE\n");
  static coap_packet_t * coap_pkt;
  opt_cose_encrypt_t cose;
  uint8_t plaintext_buffer[50]; //TODO, workaround this to decrease memory footprint
  uint8_t seq_buffer[CONTEXT_SEQ_LEN];
  uint8_t nonce_buffer[CONTEXT_INIT_VECT_LEN];

  coap_pkt = (coap_packet_t *)packet;
  OPT_COSE_Init(&cose);
  memset(plaintext_buffer, 0, 50);

  if(coap_pkt->context == NULL){
    PRINTF("ERROR: NO CONTEXT IN PREPARE MESSAGE!\n");
    return 0;
  }

  //Serialize options and payload
  size_t plaintext_size = oscoap_serializer(packet, plaintext_buffer, ROLE_CONFIDENTIAL);
  
  PRINTF("plaintext:\n");
  PRINTF_HEX(plaintext_buffer, plaintext_size);

  OPT_COSE_SetContent(&cose, plaintext_buffer, plaintext_size);
  OPT_COSE_SetAlg(&cose, COSE_Algorithm_AES_CCM_64_64_128);


  uint8_t seq_bytes_len;
  if(coap_is_request(coap_pkt)){
    seq_bytes_len = to_bytes(coap_pkt->context->sender_context->seq, seq_buffer);

    OPT_COSE_SetKeyID(&cose, coap_pkt->context->sender_context->sender_id,
            coap_pkt->context->sender_context->sender_id_len);
    OPT_COSE_SetPartialIV(&cose, seq_buffer, seq_bytes_len);
  } else {
    seq_bytes_len = to_bytes(coap_pkt->context->recipient_context->last_seq, seq_buffer);
  
    if(IS_OPTION(coap_pkt, COAP_OPTION_OBSERVE)){
      seq_bytes_len = to_bytes(observe_seq, seq_buffer);
      
    }
  }

  PRINTF("seq + context iv\n");
  PRINTF_HEX(seq_buffer, seq_bytes_len);
  PRINTF_HEX(coap_pkt->context->sender_context->sender_iv, 7);

  create_nonce(coap_pkt->context->sender_context->sender_iv, nonce_buffer, seq_buffer, seq_bytes_len);
 
  if( (!IS_OPTION(coap_pkt, COAP_OPTION_OBSERVE)) && (!coap_is_request(coap_pkt))){ 
    //Non observe reply
    nonce_buffer[0] = nonce_buffer[0] ^ (1 << 7);
  }
  
  OPT_COSE_SetNonce(&cose, nonce_buffer, CONTEXT_INIT_VECT_LEN);
 
  size_t external_aad_size = oscoap_external_aad_size(coap_pkt); // this is a upper bound of the size
  uint8_t external_aad_buffer[external_aad_size]; 
  
  external_aad_size = oscoap_prepare_external_aad(coap_pkt, &cose, external_aad_buffer, 1);

  if(coap_is_request(coap_pkt) && IS_OPTION(coap_pkt, COAP_OPTION_OBSERVE)){
    observing_seq = coap_pkt->context->sender_context->seq;
  }
  if(coap_is_request(coap_pkt)){
      set_seq_from_token(coap_pkt->token, coap_pkt->token_len, coap_pkt->context->sender_context->seq);
      if( !oscoap_increment_sender_seq(coap_pkt->context) ){
        PRINTF("SEQ overrrun, send errors\n");
        //TODO send errors
      }
  } 
  OPT_COSE_SetExternalAAD(&cose, external_aad_buffer, external_aad_size);

  //This is a hotfix to get the AAD creation working
  if(IS_OPTION(coap_pkt, COAP_OPTION_OBSERVE) && !coap_is_request(coap_pkt)){
    OPT_COSE_SetPartialIV(&cose, seq_buffer, seq_bytes_len);
  }
  PRINTF("external aad \n");
  PRINTF_HEX(external_aad_buffer, external_aad_size);


  size_t aad_length = OPT_COSE_AAD_length(&cose);
  uint8_t aad_buffer[aad_length];
  aad_length = OPT_COSE_Build_AAD(&cose, aad_buffer);

  OPT_COSE_SetAAD(&cose, aad_buffer, aad_length);
  PRINTF("serialized aad\n");
  PRINTF_HEX(aad_buffer, aad_length);
 

  size_t ciphertext_len = cose.plaintext_len + 8; 

  OPT_COSE_SetCiphertextBuffer(&cose, plaintext_buffer, ciphertext_len);
  OPT_COSE_Encrypt(&cose, coap_pkt->context->sender_context->sender_key, CONTEXT_KEY_LEN);
  
  //TODO Here we need to fix stuff with compression and without
  size_t serialized_len = OPT_COSE_Encoded_length(&cose);

  uint8_t opt_buffer[serialized_len];
  
  serialized_len = cose_compress(&cose, opt_buffer);
 
  if(coap_pkt->payload_len > 0){
      	coap_set_object_security_payload(coap_pkt, opt_buffer, serialized_len);	
  } else {
        coap_set_header_object_security_content(packet, opt_buffer, serialized_len);     
  }

  clear_options(coap_pkt);
  coap_set_header_max_age(packet, 0); //OSCOAP messages shall always have an extra Max-Age = 0 to prevent cashing
  
  size_t serialized_size = oscoap_serializer(packet, buffer, ROLE_COAP);

  if(serialized_size == 0){
    PRINTF("%s\n", coap_error_message);
  }
  
  if(IS_OPTION(coap_pkt, COAP_OPTION_OBSERVE) && !coap_is_request(coap_pkt)){
      observe_seq++;
  }

  /*TODO it is unclear what this does. old comment: break this to new function */
  memset(coap_pkt->context->sender_context->token, 0, COAP_TOKEN_LEN);
  memcpy(coap_pkt->context->sender_context->token, coap_pkt->token, coap_pkt->token_len);
  coap_pkt->context->sender_context->token_len = coap_pkt->token_len;

  PRINTF("Serialized size = %d\n", serialized_size);
  PRINTF_HEX(buffer, serialized_size);
  return serialized_size;
  
}


coap_status_t oscoap_decode_packet(coap_packet_t* coap_pkt){

  uint8_t seq_buffer[CONTEXT_SEQ_LEN];
  uint8_t nonce_buffer[CONTEXT_INIT_VECT_LEN];
  opt_cose_encrypt_t cose;
  
  OPT_COSE_Init(&cose);

  if(coap_pkt->object_security_len == 0){
    PRINTF("DECODE COSE IN PAYLOAD\n");
    cose_decompress(&cose, coap_pkt->payload, coap_pkt->payload_len);
  }else{
    PRINTF("DECODE COSE IN OPTION\n");
    cose_decompress(&cose, coap_pkt->object_security, coap_pkt->object_security_len);
  }

  PRINTF("partial iv, key id\n");
  PRINTF_HEX(cose.partial_iv, cose.partial_iv_len);
  PRINTF_HEX(cose.kid, cose.kid_len);



  oscoap_ctx_t* ctx;
  if(coap_is_request(coap_pkt)){  // Find context by KeyID if a request, or token if receiving a reply
     ctx = oscoap_find_ctx_by_rid(cose.kid, cose.kid_len);
  }else {
     ctx = oscoap_find_ctx_by_token(coap_pkt->token, coap_pkt->token_len);
  }

  if(ctx == NULL){	
  	  PRINTF("context is not fetched form DB kid: ");
      PRINTF_HEX(cose.kid, cose.kid_len);
      coap_error_message = "Security context not found";
      return UNAUTHORIZED_4_01;
  }
  
  size_t seq_len;
  uint8_t *seq;

  if(coap_is_request(coap_pkt)){  //TODO add check to se that we do not have observe to
      
        uint8_t seq_result = oscoap_validate_receiver_seq(ctx->recipient_context, &cose);
        if(seq_result != 0){
          PRINTF("SEQ Error!\n");
          coap_error_message = "Replay protection failed";
	        return BAD_REQUEST_4_00;
        }

        seq = OPT_COSE_GetPartialIV(&cose, &seq_len);
        observe_seq = bytes_to_uint32(seq, seq_len);
  } else if(! IS_OPTION(coap_pkt, COAP_OPTION_OBSERVE)){ //Reply with no Observe

        uint32_t sequence_number;
        uint8_t result = get_seq_from_token(coap_pkt->token, coap_pkt->token_len, &sequence_number);

        remove_seq_from_token(coap_pkt->token, coap_pkt->token_len);

        seq_len = to_bytes(sequence_number, seq_buffer);
        seq = seq_buffer;
        PRINTF("seq bytes\n");
        PRINTF_HEX(seq, seq_len);
        OPT_COSE_SetPartialIV(&cose, seq, seq_len);
    	  observe_seq = sequence_number;
  } else { //Observe reply
        seq = OPT_COSE_GetPartialIV(&cose, &seq_len);
  }

  create_nonce((uint8_t*)ctx->recipient_context->recipient_iv, nonce_buffer, seq, seq_len);

  if( (!IS_OPTION(coap_pkt, COAP_OPTION_OBSERVE)) && (!coap_is_request(coap_pkt))){ 
      //Non observe reply
      nonce_buffer[0] = nonce_buffer[0] ^ (1 << 7);
  }

    coap_pkt->context = ctx; //THIS IS IMPORTANT, breaks AAD creation
    OPT_COSE_SetNonce(&cose, nonce_buffer, CONTEXT_INIT_VECT_LEN); 
    OPT_COSE_SetAlg(&cose, COSE_Algorithm_AES_CCM_64_64_128);

    size_t external_aad_size = 25; 
    uint8_t external_aad_buffer[external_aad_size]; 

    external_aad_size = oscoap_prepare_external_aad(coap_pkt, &cose, external_aad_buffer, 0);

  OPT_COSE_SetExternalAAD(&cose, external_aad_buffer, external_aad_size);
  PRINTF("external aad\n");
  PRINTF_HEX(external_aad_buffer, external_aad_size);


           

    size_t aad_len = OPT_COSE_AAD_length(&cose);
    uint8_t aad_buffer[aad_len];
    aad_len = OPT_COSE_Build_AAD(&cose, aad_buffer);
    OPT_COSE_SetAAD(&cose, aad_buffer, aad_len);

    size_t plaintext_len = cose.ciphertext_len - 8;
    uint8_t plaintext_buffer[plaintext_len];
    
    OPT_COSE_SetContent(&cose, plaintext_buffer, plaintext_len);

    if(OPT_COSE_Decrypt(&cose, ctx->recipient_context->recipient_key, CONTEXT_KEY_LEN)){
      roll_back_seq(ctx->recipient_context);
      PRINTF("Error: Crypto Error!\n");
      coap_error_message = "Decryption failed";
      return BAD_REQUEST_4_00;
    }

    PRINTF("PLAINTEXT DECRYPTED len %d\n", cose.plaintext_len);
    PRINTF_HEX(cose.plaintext, cose.plaintext_len);
    
    //TODO it is unclear what happens here
    memcpy(coap_pkt->object_security, cose.plaintext, cose.plaintext_len);     
    coap_pkt->object_security_len = cose.plaintext_len;


   // PRINTF("buffer before restore pkt\n");
   // PRINTF_HEX(coap_pkt->buffer, 50);
   // oscoap_restore_packet(coap_pkt);
    oscoap_parser(coap_pkt, coap_pkt->object_security, coap_pkt->object_security_len, ROLE_CONFIDENTIAL);
   // PRINTF("buffer after restore pkt\n");
   // PRINTF_HEX(coap_pkt->buffer, 50);
   // PRINTF("SEQ last in func decode %" PRIu32 "\n", ctx->recipient_context->last_seq);
    return NO_ERROR;
    
}

void clear_options(coap_packet_t* coap_pkt){
    coap_pkt->options[COAP_OPTION_IF_MATCH / OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_IF_MATCH % OPTION_MAP_SIZE));
    /* URI-Host should be unprotected */
    coap_pkt->options[COAP_OPTION_ETAG / OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_ETAG % OPTION_MAP_SIZE));
    coap_pkt->options[COAP_OPTION_IF_NONE_MATCH / OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_IF_NONE_MATCH % OPTION_MAP_SIZE));
    /* Observe should be duplicated */
    coap_pkt->options[COAP_OPTION_LOCATION_PATH / OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_LOCATION_PATH % OPTION_MAP_SIZE));
    coap_pkt->options[COAP_OPTION_URI_PATH / OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_URI_PATH % OPTION_MAP_SIZE));
    coap_pkt->options[COAP_OPTION_CONTENT_FORMAT / OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_CONTENT_FORMAT % OPTION_MAP_SIZE));
    /* Max-Age shall me duplicated */
    coap_pkt->options[COAP_OPTION_URI_QUERY / OPTION_MAP_SIZE] &=  ~(1 << (COAP_OPTION_URI_QUERY % OPTION_MAP_SIZE));
    coap_pkt->options[COAP_OPTION_ACCEPT / OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_ACCEPT % OPTION_MAP_SIZE));
    coap_pkt->options[COAP_OPTION_LOCATION_QUERY / OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_LOCATION_QUERY % OPTION_MAP_SIZE));
    /* Block2 should be duplicated */
    /* Block1 should be duplicated */
    /* Size2 should be duplicated */
    /* Proxy-URI should be unprotected */
    /* Proxy-Scheme should be unprotected */
    /* Size1 should be duplicated */
}

int
coap_set_header_object_security_content(void *packet, uint8_t* os, size_t os_len)
{
    coap_packet_t *const coap_pkt = (coap_packet_t *)packet;
    if(IS_OPTION(coap_pkt, COAP_OPTION_OBJECT_SECURITY)){
        coap_pkt->object_security_len = os_len;
        coap_pkt->object_security = os;
        return coap_pkt->object_security_len;
    }
    return 0;
}

int coap_get_header_object_security(void* packet, const uint8_t** os_opt){
    coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

    if(IS_OPTION(coap_pkt, COAP_OPTION_OBJECT_SECURITY)){
        *os_opt = coap_pkt->object_security;
        return coap_pkt->object_security_len;
    }
    return 0;
}


/* Below is debug functions */
void oscoap_printf_hex(unsigned char *data, unsigned int len){
	unsigned int i=0;
	for(i=0; i<len; i++)
	{
		printf("%02x ",data[i]);
	}
	printf("\n");
}

void oscoap_printf_char(unsigned char *data, unsigned int len){
	unsigned int i=0;
	for(i=0; i<len; i++)
	{
		printf(" %c ",data[i]);
	}
	printf("\n");
}

#define BYTETOBINARYPATTERN "%d%d%d%d%d%d%d%d"
#define BYTETOBINARY(byte)  \
      (byte & 0x80 ? 1 : 0), \
  (byte & 0x40 ? 1 : 0), \
  (byte & 0x20 ? 1 : 0), \
  (byte & 0x10 ? 1 : 0), \
  (byte & 0x08 ? 1 : 0), \
  (byte & 0x04 ? 1 : 0), \
  (byte & 0x02 ? 1 : 0), \
  (byte & 0x01 ? 1 : 0) 

void oscoap_printf_bin(unsigned char *data, unsigned int len){
	unsigned int i=0;
	for(i=0; i<len; i++)
	{
		PRINTF(" "BYTETOBINARYPATTERN" ",BYTETOBINARY(data[i]));
	}
	PRINTF("\n");
}

