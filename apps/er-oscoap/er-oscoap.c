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
#include "er-oscoap-int.h"
#include "er-oscoap-context.h"

#include "er-coap.h"
#include "dev/watchdog.h"
#include <stdbool.h>

#include "opt-cose.h"
#include "opt-cbor.h"
#include <inttypes.h>

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


void parse_int(uint32_t in, uint8_t* bytes, int out_len){ 
	int x = out_len - 1;
	while(x >= 0){
		bytes[x] = (in >> (x * 8)) & 0xFF;
		x--;
	}
}

//TODO Fix this to work for the entire 32 bit range
uint8_t to_bytes(uint32_t in, uint8_t* buffer){
//	int outlen = log_2(in)/8 + ((in)%8 > 0) ? 1 : 0; //altough neat this does not work for in%8 == 0
	uint8_t outlen = 1;
  if(in > 255){
    in = 2;
  }
  parse_int(in, buffer, outlen);
	return outlen;
}

uint8_t coap_is_request(coap_packet_t* coap_pkt){
	if(coap_pkt->code >= COAP_GET && coap_pkt->code <= COAP_DELETE){ 
		return 1;
	} else {
		return 0;
	}
}

size_t oscoap_prepare_external_aad(coap_packet_t* coap_pkt, uint8_t* buffer, uint8_t sender, uint8_t* seq, size_t seq_len){
  uint8_t ret = 0;
  uint8_t seq_buffer[4];
  ret += OPT_CBOR_put_array(&buffer, 5);
  ret += OPT_CBOR_put_unsigned(&buffer, 1); //version is always 1
  ret += OPT_CBOR_put_unsigned(&buffer, (coap_pkt->code)); //COAP code is one byte //TODO should be
  ret += OPT_CBOR_put_unsigned(&buffer, (coap_pkt->context->ALG));

//TODO The sequence numbers are wrong for external AAD when receiving requests

  if(coap_is_request(coap_pkt)){

      if(sender){
        OSCOAP_SENDER_CONTEXT* ctx = coap_pkt->context->SENDER_CONTEXT;
        uint8_t seq_len = to_bytes(ctx->SENDER_SEQ, seq_buffer);

        ret += OPT_CBOR_put_bytes(&buffer, ctx->SENDER_ID_LEN, ctx->SENDER_ID);
        ret += OPT_CBOR_put_bytes(&buffer, seq_len, seq_buffer);
      } else {
        OSCOAP_RECIPIENT_CONTEXT* ctx = coap_pkt->context->RECIPIENT_CONTEXT;
     //   uint8_t seq_len = to_bytes(ctx->RECIPIENT_SEQ, seq_buffer);

        ret += OPT_CBOR_put_bytes(&buffer, ctx->RECIPIENT_ID_LEN, ctx->RECIPIENT_ID);
        ret += OPT_CBOR_put_bytes(&buffer, seq_len, seq);
      }

  } else {

      if(sender){
        OSCOAP_RECIPIENT_CONTEXT* ctx = coap_pkt->context->RECIPIENT_CONTEXT;
        uint8_t seq_len = to_bytes(ctx->RECIPIENT_SEQ, seq_buffer);

        ret += OPT_CBOR_put_bytes(&buffer, ctx->RECIPIENT_ID_LEN, ctx->RECIPIENT_ID);
        ret += OPT_CBOR_put_bytes(&buffer, seq_len, seq_buffer);
      } else {
        OSCOAP_SENDER_CONTEXT* ctx = coap_pkt->context->SENDER_CONTEXT;
      //  uint8_t seq_len = to_bytes(ctx->SENDER_SEQ, seq_buffer);

        ret += OPT_CBOR_put_bytes(&buffer, ctx->SENDER_ID_LEN, ctx->SENDER_ID);
        ret += OPT_CBOR_put_bytes(&buffer, seq_len, seq);
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
      ret += 8+ID_LEN+CONTEXT_SEQ_LEN; // TID
      ret += 7;
  }

  //return ret;
  return 20; //TODO FIX THIS!
}



void oscoap_increment_sender_seq(OSCOAP_COMMON_CONTEXT* ctx){
    ctx->SENDER_CONTEXT->SENDER_SEQ++; 
    PRINTF("NEW SENDER SEQ: %d\n", ctx->SENDER_CONTEXT->SENDER_SEQ);
   //TODO CHECKS FOR LIMITS
}

//TODO only works for one byte seq ATM
//TODO updating the SEQ should be done when the message is verified
uint8_t oscoap_validate_receiver_seq(OSCOAP_COMMON_CONTEXT* ctx, opt_cose_encrypt_t *cose){
  if(cose->partial_iv_len == 0) {
    PRINTF("NO SEQ FOUND IN COSE\n");
    return false;
  }

	if(cose->partial_iv[0] >= ctx->RECIPIENT_CONTEXT->RECIPIENT_SEQ){ //TODO fix this, we want to handle multibyte seq too
    PRINTF("ctx->RECEIVER_WRITE_SEQ %d, cose->seq ", ctx->RECIPIENT_CONTEXT->RECIPIENT_SEQ); 
    PRINTF_HEX(cose->partial_iv, cose->partial_iv_len);
		//ctx->RECIPIENT_CONTEXT->RECIPIENT_SEQ = cose->partial_iv[0];
		return true;
	} else {
    PRINTF("ctx->RECEIVER_WRITE_SEQ %d, cose->seq ", ctx->RECIPIENT_CONTEXT->RECIPIENT_SEQ); 
    PRINTF_HEX(cose->partial_iv, cose->partial_iv_len);
		return false;
	}
}

/* Compose the nonce by XORing the static IV (Client Write IV) with
   the Partial IV parameter, received in the COSE Object.   */
void create_iv(uint8_t* iv, uint8_t* out, uint8_t* seq, int seq_len ){
//TODO fix usage of magic numbers and add support for longer seq
	out[0] = iv[0];
	out[1] = iv[1];
	out[2] = iv[2];	
	out[3] = iv[3];
	out[4] = iv[4];
	out[5] = iv[5];
	out[6] = iv[6];
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
  coap_pkt = (coap_packet_t *)packet;

  opt_cose_encrypt_t cose;
  OPT_COSE_Init(&cose);

  if(coap_pkt->context == NULL){
    PRINTF("ERROR: NO CONTEXT IN PREPARE MESSAGE!\n");
    return 0;
  }
  uint8_t plaintext_buffer[50]; //TODO, workaround this to decrease memory footprint
  memset(plaintext_buffer, 0, 50);
    
  //Serialize options and payload
  size_t plaintext_size =  oscoap_prepare_plaintext( packet, plaintext_buffer);
 
  OPT_COSE_SetContent(&cose, plaintext_buffer, plaintext_size);
  OPT_COSE_SetAlg(&cose, COSE_Algorithm_AES_CCM_64_64_128);

  oscoap_increment_sender_seq(coap_pkt->context);

  uint8_t seq_buffer[CONTEXT_SEQ_LEN];
  uint8_t nonce_buffer[CONTEXT_INIT_VECT_LEN];

  uint8_t seq_bytes_len = to_bytes((uint32_t)(coap_pkt->context->SENDER_CONTEXT->SENDER_SEQ), seq_buffer);

  create_iv((uint8_t*)coap_pkt->context->SENDER_CONTEXT->SENDER_IV, nonce_buffer, seq_buffer, seq_bytes_len);

  OPT_COSE_SetPartialIV(&cose, seq_buffer, seq_bytes_len);
  OPT_COSE_SetNonce(&cose, nonce_buffer, CONTEXT_INIT_VECT_LEN);
  OPT_COSE_SetKeyID(&cose, coap_pkt->context->CONTEXT_ID, CONTEXT_ID_LEN);


  size_t external_aad_size = oscoap_external_aad_size(coap_pkt); // this is a upper bound of the size
  uint8_t external_aad_buffer[external_aad_size]; 
  
  //TDOD FIX 1 and 0 to proper defined constants
  if(coap_is_request(coap_pkt)){
      PRINTF("we have a request!\n");
      external_aad_size = oscoap_prepare_external_aad(coap_pkt, external_aad_buffer, 1, NULL, 0);
   //   external_aad_size = oscoap_prepare_request_external_aad(coap_pkt, external_aad_buffer, 1); 
      printf("external aad \n");
      oscoap_printf_hex(external_aad_buffer, external_aad_size);
  } else {
      PRINTF("we have a response!\n");
      external_aad_size = oscoap_prepare_external_aad(coap_pkt, external_aad_buffer, 1, NULL, 0);
   //   external_aad_size = oscoap_prepare_response_external_aad(coap_pkt, external_aad_buffer, 1);
      printf("external aad \n");
      oscoap_printf_hex(external_aad_buffer, external_aad_size);
  }

  OPT_COSE_SetExternalAAD(&cose, external_aad_buffer, external_aad_size);

  size_t aad_length = OPT_COSE_AAD_length(&cose);
  uint8_t aad_buffer[aad_length];
  uint8_t *tmp_buffer = aad_buffer;
  aad_length = OPT_COSE_Build_AAD(&cose, tmp_buffer);
  //printf("serialized aad\n");
  //oscoap_printf_hex(aad_buffer, aad_length);
  OPT_COSE_SetAAD(&cose, aad_buffer, aad_length);
   
  size_t ciphertext_len = cose.plaintext_len + 8; 

  OPT_COSE_SetCiphertextBuffer(&cose, plaintext_buffer, ciphertext_len);

  OPT_COSE_Encrypt(&cose, coap_pkt->context->SENDER_CONTEXT->SENDER_KEY, CONTEXT_KEY_LEN);
  
  size_t serialized_len = OPT_COSE_Encoded_length(&cose);

  uint8_t opt_buffer[serialized_len];
  OPT_COSE_Encode(&cose, opt_buffer);
 
  if(coap_pkt->payload_len > 0){
      	coap_set_object_security_payload(coap_pkt, opt_buffer, serialized_len);	
  }else{
        coap_set_header_object_security_content(packet, opt_buffer, serialized_len);     
  }
  
  coap_set_header_max_age(packet, 0);
  clear_options(coap_pkt);
  size_t serialized_size = coap_serialize_message_coap(packet, buffer);
  if(serialized_size == 0){
    PRINTF("%s\n", coap_error_message);
  }

  PRINTF("Serialized size = %d\n", serialized_size);
  PRINTF_HEX(buffer, serialized_size);
  return serialized_size;
  
}


coap_status_t oscoap_decode_packet(coap_packet_t* coap_pkt){
       
  opt_cose_encrypt_t cose;
  OPT_COSE_Init(&cose);

  if(coap_pkt->object_security_len == 0){

   PRINTF("DECODE COSE IN PAYLOAD\n");
   
    PRINTF("serialized incomming COSE\n");
    PRINTF_HEX(coap_pkt->payload, coap_pkt->payload_len);

    OPT_COSE_Decode(&cose, coap_pkt->payload, coap_pkt->payload_len);

  }else{

    PRINTF("DECODE COSE IN OPTION\n");

    PRINTF("serialized incomming COSE\n");
    PRINTF_HEX(coap_pkt->object_security, coap_pkt->object_security_len);

    OPT_COSE_Decode(&cose, coap_pkt->object_security, coap_pkt->object_security_len);

  }

  	uint8_t nonce[CONTEXT_INIT_VECT_LEN];

    OSCOAP_COMMON_CONTEXT* ctx;
  	ctx = oscoap_find_ctx_by_cid(cose.kid);
  	if(ctx == NULL){	
  		  PRINTF("context is not fetched form DB cid: ");
        PRINTF_HEX(cose.kid, cose.kid_len);
        return OSCOAP_CONTEXT_NOT_FOUND;
  	}else{
        size_t seq_len;
        uint8_t *seq = OPT_COSE_GetPartialIV(&cose, &seq_len);

    	  create_iv((uint8_t*)ctx->RECIPIENT_CONTEXT->RECIPIENT_IV, nonce,seq, seq_len);
    		coap_pkt->context = ctx;
    		OPT_COSE_SetNonce(&cose, nonce, CONTEXT_INIT_VECT_LEN); 
  	}

    if(!oscoap_validate_receiver_seq(ctx, &cose)){
      return OSCOAP_SEQ_ERROR; 
    }
 
    OPT_COSE_SetAlg(&cose, COSE_Algorithm_AES_CCM_64_64_128);

    size_t external_aad_size = oscoap_external_aad_size(coap_pkt); // this is a upper bound of the size
    uint8_t external_aad_buffer[external_aad_size]; 
  
    if(coap_is_request(coap_pkt)){//this should match reqests
        PRINTF("we have a incomming request!\n");
        external_aad_size = oscoap_prepare_external_aad(coap_pkt, external_aad_buffer, 0, cose.partial_iv, cose.partial_iv_len );
      //  external_aad_size = oscoap_prepare_request_external_aad(coap_pkt, external_aad_buffer, 0);
      //  printf("external aad \n");
      //  oscoap_printf_hex(external_aad_buffer, external_aad_size);
    } else {
        PRINTF("we have a incomming response!\n");
        external_aad_size = oscoap_prepare_external_aad(coap_pkt, external_aad_buffer, 0, cose.partial_iv, cose.partial_iv_len );
      //  external_aad_size = oscoap_prepare_response_external_aad(coap_pkt, external_aad_buffer, 0);
      //  printf("external aad \n");
      //  oscoap_printf_hex(external_aad_buffer, external_aad_size); 
    }
    printf("external aad\n");
    oscoap_printf_hex(external_aad_buffer, external_aad_size);

    OPT_COSE_SetExternalAAD(&cose, external_aad_buffer, external_aad_size);
           
    //Verify and decrypt the message.  If the verification fails, the
    //server MUST stop processing the request.
  	size_t aad_len = OPT_COSE_AAD_length(&cose);
    uint8_t aad_buffer[aad_len];
    aad_len = OPT_COSE_Build_AAD(&cose, aad_buffer);
    OPT_COSE_SetAAD(&cose, aad_buffer, aad_len);

    size_t plaintext_len = cose.ciphertext_len - 8;
    uint8_t plaintext_buffer[plaintext_len];
    OPT_COSE_SetContent(&cose, plaintext_buffer, plaintext_len);

    if(OPT_COSE_Decrypt(&cose, ctx->RECIPIENT_CONTEXT->RECIPIENT_KEY, CONTEXT_KEY_LEN)){
      return OSCOAP_CRYPTO_ERROR;
    }
    ctx->RECIPIENT_CONTEXT->RECIPIENT_SEQ = cose.partial_iv[0];

    PRINTF("PLAINTEXT DECRYPTED len %d\n", cose.plaintext_len);
    PRINTF_HEX(cose.plaintext, cose.plaintext_len);
    
    memcpy(coap_pkt->object_security, cose.plaintext, cose.plaintext_len);     
    coap_pkt->object_security_len = cose.plaintext_len;


    //TODO, rädda PROXY URI; MAX AGE osv. från memset i restore_packet
    PRINTF("buffer before restore pkt\n");
    PRINTF_HEX(coap_pkt->buffer, 50);
    oscoap_restore_packet(coap_pkt);
    PRINTF("buffer after restore pkt\n");
    PRINTF_HEX(coap_pkt->buffer, 50);

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
coap_set_header_object_security_content(void *packet, const uint8_t* os, size_t os_len)
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

size_t oscoap_prepare_plaintext(void* packet, uint8_t* plaintext_buffer){
 PRINTF("prepare plaintext\n");  
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;
  uint8_t *option;
  unsigned int current_number = 0;

  /* Initialize */
  uint8_t* original_buffer = coap_pkt->buffer;
  coap_pkt->buffer = plaintext_buffer;

  PRINTF("-Serializing MID %u to %p, ", coap_pkt->mid, coap_pkt->buffer);

  //TODO is this correct?
  /* empty packet, dont need to do more stuff */
  if(!coap_pkt->code) {
    PRINTF("-Done serializing empty message at %p-\n", coap_pkt->buffer);
    coap_pkt->buffer = original_buffer;
    return 4;
  }
//TODO fix this so we dont make uneccesary wirites
 //Set Token
  PRINTF("Token (len %u)", coap_pkt->token_len);
  option = coap_pkt->buffer; // + COAP_HEADER_LEN-2; //TODO, fixa OSCOAP_HEADER_LEN
  for(current_number = 0; current_number < coap_pkt->token_len;
      ++current_number) {
    PRINTF(" %02X", coap_pkt->token[current_number]);
    *option = coap_pkt->token[current_number];
    ++option;
  }
  PRINTF("-\n");

  current_number = 0;
  option = coap_pkt->buffer;
  /* Serialize options */

  PRINTF("-Serializing options at %p-\n", option);

  /* The options must be serialized in the order of their number */
  COAP_SERIALIZE_BYTE_OPTION(COAP_OPTION_IF_MATCH, if_match, "If-Match");
  //COAP_SERIALIZE_STRING_OPTION(COAP_OPTION_URI_HOST, uri_host, '\0', 
  //                             "Uri-Host"); //Should be omitted
  COAP_SERIALIZE_BYTE_OPTION(COAP_OPTION_ETAG, etag, "ETag");
  COAP_SERIALIZE_INT_OPTION(COAP_OPTION_IF_NONE_MATCH,
                            content_format -
                            coap_pkt->
                            content_format /* hack to get a zero field */,
                            "If-None-Match");
  COAP_SERIALIZE_INT_OPTION(COAP_OPTION_OBSERVE, observe, "Observe");
 // COAP_SERIALIZE_INT_OPTION(COAP_OPTION_URI_PORT, uri_port, "Uri-Port");
  COAP_SERIALIZE_STRING_OPTION(COAP_OPTION_LOCATION_PATH, location_path, '/',
                               "Location-Path");
  COAP_SERIALIZE_STRING_OPTION(COAP_OPTION_URI_PATH, uri_path, '/',
                               "Uri-Path");
  PRINTF("Serialize content format: %d\n", coap_pkt->content_format);
  COAP_SERIALIZE_INT_OPTION(COAP_OPTION_CONTENT_FORMAT, content_format,
                            "Content-Format");
  //COAP_OPTION_MAX_AGE Should be omitted
  COAP_SERIALIZE_STRING_OPTION(COAP_OPTION_URI_QUERY, uri_query, '&',
                               "Uri-Query");
  COAP_SERIALIZE_INT_OPTION(COAP_OPTION_ACCEPT, accept, "Accept");
  COAP_SERIALIZE_STRING_OPTION(COAP_OPTION_LOCATION_QUERY, location_query,
                               '&', "Location-Query");
  //COAP_OPTION_OBJECT_SECURITY (21) SHOULD BE OMITTED
  COAP_SERIALIZE_BLOCK_OPTION(COAP_OPTION_BLOCK2, block2, "Block2");
  COAP_SERIALIZE_BLOCK_OPTION(COAP_OPTION_BLOCK1, block1, "Block1");
  COAP_SERIALIZE_INT_OPTION(COAP_OPTION_SIZE2, size2, "Size2");
  //COAP_OPTION_PROXY_URI Should be omitted
  //COAP_OPTION_PROXY_SCHEME Should be omitted
  COAP_SERIALIZE_INT_OPTION(COAP_OPTION_SIZE1, size1, "Size1");

  PRINTF("-Done serializing at %p----\n", option);

  /* Pack payload */
  if((option - coap_pkt->buffer) <= COAP_MAX_HEADER_SIZE) {
    /* Payload marker */
    if(coap_pkt->payload_len) {
      *option = 0xFF;
      ++option;
    }
    memmove(option, coap_pkt->payload, coap_pkt->payload_len);
  } else {
    /* an error occurred: caller must check for !=0 */
    coap_pkt->buffer = NULL;
    coap_error_message = "Serialized header exceeds COAP_MAX_HEADER_SIZE";
    return 0;
  }

  coap_pkt->buffer = original_buffer;
  return (option - plaintext_buffer) + coap_pkt->payload_len; /* packet length */
}

void oscoap_restore_packet(void* packet){
 
  coap_packet_t* coap_pkt = (coap_packet_t*) packet;
  uint8_t *data =  coap_pkt->object_security;
  uint8_t *current_option = data;
  /* parse options */
  memset(coap_pkt->options, 0, sizeof(coap_pkt->options));

  size_t data_len = coap_pkt->object_security_len;
  unsigned int option_number = 0;
  unsigned int option_delta = 0;
  size_t option_length = 0;
 
  while(current_option < data + data_len) {
    /* payload marker 0xFF, currently only checking for 0xF* because rest is reserved */
    if((current_option[0] & 0xF0) == 0xF0) {
      coap_pkt->payload = ++current_option;
      coap_pkt->payload_len = data_len - (coap_pkt->payload - data);

      /* also for receiving, the Erbium upper bound is REST_MAX_CHUNK_SIZE */
      if(coap_pkt->payload_len > REST_MAX_CHUNK_SIZE) {
        coap_pkt->payload_len = REST_MAX_CHUNK_SIZE;
        /* null-terminate payload */
      }
      coap_pkt->payload[coap_pkt->payload_len] = '\0';

      break;
    }

    option_delta = current_option[0] >> 4;
    option_length = current_option[0] & 0x0F;
    ++current_option;

    if(option_delta == 13) {
      option_delta += current_option[0];
      ++current_option;
    } else if(option_delta == 14) {
      option_delta += 255;
      option_delta += current_option[0] << 8;
      ++current_option;
      option_delta += current_option[0];
      ++current_option;
    }

    if(option_length == 13) {
      option_length += current_option[0];
      ++current_option;
    } else if(option_length == 14) {
      option_length += 255;
      option_length += current_option[0] << 8;
      ++current_option;
      option_length += current_option[0];
      ++current_option;
    }
    option_number += option_delta;
    PRINTF("OPTION %u (delta %u, len %zu): \n", option_number, option_delta,
           option_length);

    SET_OPTION(coap_pkt, option_number);

    switch(option_number) {
    case COAP_OPTION_CONTENT_FORMAT:
      coap_pkt->content_format = coap_parse_int_option(current_option,
                                                       option_length);
      PRINTF("Content-Format [%u]\n", coap_pkt->content_format);
      break;
    case COAP_OPTION_MAX_AGE:
      coap_pkt->max_age = coap_parse_int_option(current_option,
                                                option_length);
      PRINTF("Max-Age [%lu]\n", (unsigned long)coap_pkt->max_age);
      break;
    case COAP_OPTION_ETAG:
      coap_pkt->etag_len = MIN(COAP_ETAG_LEN, option_length);
      memcpy(coap_pkt->etag, current_option, coap_pkt->etag_len);
      PRINTF("ETag %u [0x%02X%02X%02X%02X%02X%02X%02X%02X]\n",
             coap_pkt->etag_len, coap_pkt->etag[0], coap_pkt->etag[1],
             coap_pkt->etag[2], coap_pkt->etag[3], coap_pkt->etag[4],
             coap_pkt->etag[5], coap_pkt->etag[6], coap_pkt->etag[7]
             );                 /*FIXME always prints 8 bytes */
      break;
    case COAP_OPTION_ACCEPT:
      coap_pkt->accept = coap_parse_int_option(current_option, option_length);
      PRINTF("Accept [%u]\n", coap_pkt->accept);
      break;
    case COAP_OPTION_IF_MATCH:
      /* TODO support multiple ETags */
      coap_pkt->if_match_len = MIN(COAP_ETAG_LEN, option_length);
      memcpy(coap_pkt->if_match, current_option, coap_pkt->if_match_len);
      PRINTF("If-Match %u [0x%02X%02X%02X%02X%02X%02X%02X%02X]\n",
             coap_pkt->if_match_len, coap_pkt->if_match[0],
             coap_pkt->if_match[1], coap_pkt->if_match[2],
             coap_pkt->if_match[3], coap_pkt->if_match[4],
             coap_pkt->if_match[5], coap_pkt->if_match[6],
             coap_pkt->if_match[7]
             ); /* FIXME always prints 8 bytes */
      break;
    case COAP_OPTION_IF_NONE_MATCH:
      coap_pkt->if_none_match = 1;
      PRINTF("If-None-Match\n");
      break;

    case COAP_OPTION_PROXY_URI:
#if COAP_PROXY_OPTION_PROCESSING
      coap_pkt->proxy_uri = (char *)current_option;
      coap_pkt->proxy_uri_len = option_length;
#endif
      PRINTF("Proxy-Uri NOT IMPLEMENTED [%.*s]\n", (int)coap_pkt->proxy_uri_len,
             coap_pkt->proxy_uri);
      coap_error_message = "This is a constrained server (Contiki)";
      //return PROXYING_NOT_SUPPORTED_5_05;
      break;
    case COAP_OPTION_PROXY_SCHEME:
#if COAP_PROXY_OPTION_PROCESSING
      coap_pkt->proxy_scheme = (char *)current_option;
      coap_pkt->proxy_scheme_len = option_length;
#endif
      PRINTF("Proxy-Scheme NOT IMPLEMENTED [%.*s]\n",
             (int)coap_pkt->proxy_scheme_len, coap_pkt->proxy_scheme);
      coap_error_message = "This is a constrained server (Contiki)";
      //return PROXYING_NOT_SUPPORTED_5_05;
      break;

    case COAP_OPTION_URI_HOST:
      coap_pkt->uri_host = (char *)current_option;
      coap_pkt->uri_host_len = option_length;
      PRINTF("Uri-Host [%.*s]\n", (int)coap_pkt->uri_host_len,
	     coap_pkt->uri_host);
      break;
    case COAP_OPTION_URI_PORT:
      coap_pkt->uri_port = coap_parse_int_option(current_option,
                                                 option_length);
      PRINTF("Uri-Port [%u]\n", coap_pkt->uri_port);
      break;
    case COAP_OPTION_URI_PATH:
      /* coap_merge_multi_option() operates in-place on the IPBUF, but final packet field should be const string -> cast to string */
      coap_merge_multi_option((char **)&(coap_pkt->uri_path),
                              &(coap_pkt->uri_path_len), current_option,
                              option_length, '/');
      PRINTF("Uri-Path [%.*s]\n", (int)coap_pkt->uri_path_len, coap_pkt->uri_path);
      break;
    case COAP_OPTION_URI_QUERY:
      /* coap_merge_multi_option() operates in-place on the IPBUF, but final packet field should be const string -> cast to string */
      coap_merge_multi_option((char **)&(coap_pkt->uri_query),
                              &(coap_pkt->uri_query_len), current_option,
                              option_length, '&');
      PRINTF("Uri-Query [%.*s]\n", (int)coap_pkt->uri_query_len,
             coap_pkt->uri_query);
      break;

    case COAP_OPTION_LOCATION_PATH:
      /* coap_merge_multi_option() operates in-place on the IPBUF, but final packet field should be const string -> cast to string */
      coap_merge_multi_option((char **)&(coap_pkt->location_path),
                              &(coap_pkt->location_path_len), current_option,
                              option_length, '/');
      PRINTF("Location-Path [%.*s]\n", (int)coap_pkt->location_path_len,
             coap_pkt->location_path);
      break;
    case COAP_OPTION_LOCATION_QUERY:
      /* coap_merge_multi_option() operates in-place on the IPBUF, but final packet field should be const string -> cast to string */
      coap_merge_multi_option((char **)&(coap_pkt->location_query),
                              &(coap_pkt->location_query_len), current_option,
                              option_length, '&');
      PRINTF("Location-Query [%.*s]\n", (int)coap_pkt->location_query_len,
             coap_pkt->location_query);
      break;

    case COAP_OPTION_OBSERVE:
      coap_pkt->observe = coap_parse_int_option(current_option,
                                                option_length);
      PRINTF("Observe [%lu]\n", (unsigned long)coap_pkt->observe);
      break;
    case COAP_OPTION_BLOCK2:
      coap_pkt->block2_num = coap_parse_int_option(current_option,
                                                   option_length);
      coap_pkt->block2_more = (coap_pkt->block2_num & 0x08) >> 3;
      coap_pkt->block2_size = 16 << (coap_pkt->block2_num & 0x07);
      coap_pkt->block2_offset = (coap_pkt->block2_num & ~0x0000000F)
        << (coap_pkt->block2_num & 0x07);
      coap_pkt->block2_num >>= 4;
      PRINTF("Block2 [%lu%s (%u B/blk)]\n",
             (unsigned long)coap_pkt->block2_num,
             coap_pkt->block2_more ? "+" : "", coap_pkt->block2_size);
      break;
    case COAP_OPTION_BLOCK1:
      coap_pkt->block1_num = coap_parse_int_option(current_option,
                                                   option_length);
      coap_pkt->block1_more = (coap_pkt->block1_num & 0x08) >> 3;
      coap_pkt->block1_size = 16 << (coap_pkt->block1_num & 0x07);
      coap_pkt->block1_offset = (coap_pkt->block1_num & ~0x0000000F)
        << (coap_pkt->block1_num & 0x07);
      coap_pkt->block1_num >>= 4;
      PRINTF("Block1 [%lu%s (%u B/blk)]\n",
             (unsigned long)coap_pkt->block1_num,
             coap_pkt->block1_more ? "+" : "", coap_pkt->block1_size);
      break;
    case COAP_OPTION_SIZE2:
      coap_pkt->size2 = coap_parse_int_option(current_option, option_length);
      PRINTF("Size2 [%lu]\n", (unsigned long)coap_pkt->size2);
      break;
    case COAP_OPTION_SIZE1:
      coap_pkt->size1 = coap_parse_int_option(current_option, option_length);
      PRINTF("Size1 [%lu]\n", (unsigned long)coap_pkt->size1);
      break;
    default:
      PRINTF("unknown (%u)\n", option_number);
/* check if critical (odd) */
      
      if(option_number & 1) {
        coap_error_message = "Unsupported critical option";
        //return BAD_OPTION_4_02;
      }
    }
    current_option += option_length;  
  }
}
/* Below is debug functions */
void oscoap_printf_hex(unsigned char *data, unsigned int len){
	int i=0;
	for(i=0; i<len; i++)
	{
		PRINTF("%02x ",data[i]);
	}
	PRINTF("\n");
}

void oscoap_printf_char(unsigned char *data, unsigned int len){
	int i=0;
	for(i=0; i<len; i++)
	{
		PRINTF(" %c ",data[i]);
	}
	PRINTF("\n");
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
	int i=0;
	for(i=0; i<len; i++)
	{
		PRINTF(" "BYTETOBINARYPATTERN" ",BYTETOBINARY(data[i]));
	}
	PRINTF("\n");
}

void oscoap_print_context(OSCOAP_COMMON_CONTEXT* ctx){
    PRINTF("Print Context:\n");
    PRINTF("Context ID: ");
    oscoap_printf_hex(ctx->CONTEXT_ID, CONTEXT_ID_LEN);
    PRINTF("Base Key: ");
    oscoap_printf_hex(ctx->BASE_KEY, ctx->BASE_KEY_LEN);
    PRINTF("ALG: %d\n", ctx->ALG);

    OSCOAP_SENDER_CONTEXT* s = ctx->SENDER_CONTEXT;
    PRINTF("Sender Context: {\n");
    PRINTF("\tSender ID: ");
    oscoap_printf_hex(s->SENDER_ID, ID_LEN);
    PRINTF("\tSender Key: ");
    oscoap_printf_hex(s->SENDER_KEY, CONTEXT_KEY_LEN);
    PRINTF("\tSender IV: ");
    oscoap_printf_hex(s->SENDER_IV, CONTEXT_INIT_VECT_LEN);
    PRINTF("}\n");

    OSCOAP_RECIPIENT_CONTEXT* r = ctx->RECIPIENT_CONTEXT;
    PRINTF("Recipient Context: {\n");
    PRINTF("\tRecipient ID: ");
    oscoap_printf_hex(r->RECIPIENT_ID, ID_LEN);
    PRINTF("\tRecipient Key: ");
    oscoap_printf_hex(r->RECIPIENT_KEY, CONTEXT_KEY_LEN);
    PRINTF("\tRecipient IV: ");
    oscoap_printf_hex(r->RECIPIENT_IV, CONTEXT_INIT_VECT_LEN);
    PRINTF("}\n");
  
}