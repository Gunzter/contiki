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
#include "opt-cose.h"
#include "cose-aes-ccm.h"
#include <string.h>
#include "er-oscoap.h"

#define DEBUG 1
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINTF_HEX(data, len) 	oscoap_printf_hex(data, len)
#else
#define PRINTF(...)
#define PRINTF_HEX(data, len)
#endif

size_t  OPT_COSE_Encode(opt_cose_encrypt_t *cose, uint8_t *buffer){
	size_t ret = 0;
	ret += OPT_CBOR_put_array(&buffer, 3);
	ret += OPT_COSE_Encode_Protected(cose, &buffer);
	ret += OPT_CBOR_put_map(&buffer, 0);
	PRINTF("ciphertext len dec: %d hex: %02x\n", cose->ciphertext_len, cose->ciphertext_len);
	ret += OPT_CBOR_put_bytes(&buffer, cose->ciphertext_len, cose->ciphertext);

	return ret;
}

uint8_t OPT_COSE_ENCRYPT(opt_cose_encrypt_t *cose, uint8_t *key, size_t key_len){
	return 0;
}

void OPT_COSE_Init(opt_cose_encrypt_t *cose){
	memset(cose, 0x00, sizeof(opt_cose_encrypt_t)); 
}

size_t OPT_COSE_Encoded_length(opt_cose_encrypt_t *cose){
	size_t ret = 0;
	ret += 1; //Array[3]
	ret += 4; // seq encoding
	ret += cose->partial_iv_len;
	if(cose->kid_len != 0){
		ret += cose->kid_len + 2; // 1 for key 1 for value
	}
	if(cose->sid_len != 0){
		ret += cose->sid_len + 2;
	}
	ret += 1; // Map[0]
	if(cose->ciphertext_len > 15){ //bytes[ciphertext_len]
		ret += 2;
	}else{
		ret += 1;
	}
	ret += cose->ciphertext_len;
	return ret;
}

uint8_t OPT_COSE_SetContent(opt_cose_encrypt_t *cose, uint8_t *plaintext_buffer, size_t plaintext_len){
	cose->plaintext = plaintext_buffer;
	cose->plaintext_len = plaintext_len;
	cose->serialized_len += plaintext_len;
	return 1;
}

uint8_t OPT_COSE_SetAlg(opt_cose_encrypt_t *cose, uint8_t alg){
	cose->alg = alg;
	cose->serialized_len += 1; 
	return 1;
}

uint8_t OPT_COSE_SetPartialIV(opt_cose_encrypt_t *cose, uint8_t *partial_iv_buffer, size_t partial_iv_len){
	cose->partial_iv =  partial_iv_buffer;
	cose->partial_iv_len = partial_iv_len;
	return 1;
}

uint8_t* OPT_COSE_GetPartialIV(opt_cose_encrypt_t *cose, size_t *partial_iv_len){
	*partial_iv_len = cose->partial_iv_len;
	return cose->partial_iv;
}

uint8_t OPT_COSE_SetKeyID(opt_cose_encrypt_t *cose, uint8_t *kid_buffer, size_t kid_len){
	cose->kid = kid_buffer;
	cose->kid_len = kid_len;
	cose->serialized_len += kid_len;
	return 1;
}

uint8_t* OPT_COSE_GetKeyID(opt_cose_encrypt_t *cose, size_t *kid_len){
	*kid_len = cose->kid_len;
	return cose->kid;
}


uint8_t OPT_COSE_SetExternalAAD(opt_cose_encrypt_t *cose, uint8_t *external_aad_buffer, size_t external_aad_len){
	cose->external_aad = external_aad_buffer;
	cose->external_aad_len = external_aad_len;
	return 1;
}

uint8_t OPT_COSE_SetAAD(opt_cose_encrypt_t *cose, uint8_t *aad_buffer, size_t aad_len){
	cose->aad = aad_buffer;
	cose->aad_len = aad_len;
	return 1;
}	

uint8_t OPT_COSE_Encode_Protected(opt_cose_encrypt_t *cose, uint8_t **buffer){

	if(cose->kid_len != 0){
		**buffer = (0x40 | (cose->partial_iv_len + 3 + cose->kid_len + 2));
		(*buffer)++;
		OPT_CBOR_put_map(buffer, 2);
		OPT_CBOR_put_unsigned(buffer, COSE_Header_KID);
		OPT_CBOR_put_bytes(buffer, cose->kid_len, cose->kid);
	}else{
		**buffer = (0x40 | (cose->partial_iv_len + 3 + cose->kid_len));
		(*buffer)++;
		OPT_CBOR_put_map(buffer, 1);
	}
	OPT_CBOR_put_unsigned(buffer, COSE_Header_Partial_IV);
	OPT_CBOR_put_bytes(buffer, cose->partial_iv_len, cose->partial_iv);
	return 1;
}

uint8_t OPT_COSE_Build_AAD(opt_cose_encrypt_t *cose, uint8_t *buffer){
	OPT_CBOR_put_array(&buffer, 3);
	char* encrypted = "Encrypted";
	OPT_CBOR_put_text(&buffer, encrypted , strlen(encrypted));
	OPT_COSE_Encode_Protected(cose, &buffer);
	OPT_CBOR_put_bytes(&buffer, cose->external_aad_len, cose->external_aad);
	return 1;
}

size_t  OPT_COSE_AAD_length(opt_cose_encrypt_t *cose){
	//TODO this only works for responses
	PRINTF("cose->partial_iv_len %d\n", cose->partial_iv_len);
	PRINTF("cose->external_aad_len %d\n", cose->external_aad_len);
	PRINTF("cose->kid_len %d\n", cose->kid_len);
	size_t ret = 12 + 3 + cose->partial_iv_len + 1 + cose->external_aad_len;
	//array + text(Encrypted) + bytes + seq_len + bytes + external_aad_len
	if(cose->kid_len > 0){
		ret += cose->kid_len;
		ret += 2; // one byte key one byte byte-tag
	}
	return ret;
}

uint8_t OPT_COSE_SetNonce(opt_cose_encrypt_t *cose, uint8_t *nonce_buffer, size_t nonce_len){
	cose->nonce = nonce_buffer;
	cose->nonce_len = nonce_len;
	return 1;
}
uint8_t OPT_COSE_SetCiphertextBuffer(opt_cose_encrypt_t *cose, uint8_t *ciphertext_buffer, size_t ciphertext_len){
	cose->ciphertext = ciphertext_buffer;
	cose->ciphertext_len = ciphertext_len;
	return 1;
}
uint8_t _OPT_COSE_cbor_protected_map(opt_cose_encrypt_t *cose, uint8_t *buffer, uint8_t len){

	uint8_t byte_len;
	uint8_t *end_ptr = (uint8_t*)(buffer + len);
	buffer++; //step by map tag
	while(buffer < end_ptr ){
		if(*buffer == COSE_Header_KID){//COSE_Header_KID = 2,
			buffer++; //step by key
			byte_len = (*buffer & 0x0F);
			buffer++; //step by tag
			cose->kid = buffer;
			cose->kid_len = byte_len;
			buffer += byte_len; //step by bytefield
		}else if(*buffer == COSE_Header_Partial_IV){ //COSE_Header_Partial_IV = 6,
			buffer++; //step by key
			byte_len = (*buffer & 0x0F);
			buffer++;// step by tag
			cose->partial_iv = buffer;
			cose->partial_iv_len = byte_len;
			buffer += byte_len; //step by bytefield
		}else if(*buffer == COSE_Header_Sender_ID ){ // COSE_Header_Sender_ID  = 8
			buffer++; //step by key
			byte_len = (*buffer & 0x0F);
			buffer++;// step by tag
			cose->sid = buffer;
			cose->sid_len = byte_len;
			buffer += byte_len; //step by bytefield
		}else{
			PRINTF("ERROR unknown map tag\n");
			buffer++;
		}
	}
	PRINTF("KID: len = %d\n", cose->kid_len);
	PRINTF_HEX(cose->kid, cose->kid_len);
	PRINTF("Header Partial IV: len = %d\n", cose->partial_iv_len);
	PRINTF_HEX(cose->partial_iv, cose->partial_iv_len);
	PRINTF("Sender ID, len = %d\n", cose->sid_len);
	PRINTF_HEX(cose->sid, cose->sid_len);
	return 1;
}
uint8_t _OPT_COSE_cbor_content(opt_cose_encrypt_t *cose, uint8_t *buffer, uint8_t len){
	cose->ciphertext = buffer;
	cose->ciphertext_len = len;
	return 1;
}

uint8_t _OPT_COSE_cbor_bytes(opt_cose_encrypt_t *cose, uint8_t *buffer, uint8_t len, uint8_t bytefield){
	if(bytefield == 0){
		return _OPT_COSE_cbor_protected_map(cose, buffer,len);
	}else if(bytefield == 1){
		return _OPT_COSE_cbor_content(cose, buffer, len);
	}else{
		PRINTF("ERROR Unexpected bytefield %d\n", bytefield);
		return 0;
	}
}

//TODO unify buffer len and len in this and the map function
size_t OPT_COSE_Decode(opt_cose_encrypt_t *cose, uint8_t *buffer, size_t buffer_len){
	PRINTF("Decoding COSE:\n");
	PRINTF_HEX(buffer, buffer_len);

	uint8_t bytefield = 0;
	uint8_t *end_ptr = (uint8_t*)(buffer + buffer_len);

	while(buffer < end_ptr){
		uint8_t len;
		
		switch(*buffer & 0xF0){
			case 0x80:
			//	PRINTF("array \n");
				buffer++;
				break;
			case 0xa0:
			//	PRINTF("map \n");
				buffer++;
				break;
			case 0x40:
			//	PRINTF("bytes\n");
				len = (*buffer & 0x0F);
				buffer++; //step by tag
				_OPT_COSE_cbor_bytes(cose, buffer, len, bytefield);
				bytefield++;
				buffer += len; //step by bytes
				break;
			case 0x50:
			//	PRINTF("bytes long field\n");
				
				if(*buffer == 0x58){
					buffer++;
					len = *buffer;
					buffer++;
					PRINTF("EXTRA bytes len %d\n", len);
				}else{
					len = (~(0x40) & *buffer);
					buffer++; //step by length
				}

				_OPT_COSE_cbor_bytes(cose, buffer, len, bytefield);
				bytefield++;
				buffer += len; //step by bytes
				break;
			case 0x00:
			//	OSCOAP_PRINTF("unsigned\n");
				buffer++;
				break;
			default:
				PRINTF("Error deafault %02x\n", *buffer);
				buffer++;
			
		}
		
	}
}


uint8_t OPT_COSE_Encrypt(opt_cose_encrypt_t *cose, uint8_t *key, size_t key_len){

	PRINTF("encrypt OPT_COSE\n");

	int ret = 0;


    size_t TSize = 8; //Sort this out

    if(cose->alg == COSE_Algorithm_AES_CCM_64_64_128 && key_len == 16){
		//cipher = MBEDTLS_CIPHER_ID_AES;
	}else{
		PRINTF("Error in Encrypt with key and algorithm\n");
		return 1;
	}


	PRINTF("Encrypting:\n");
	PRINTF("Plaintext:\n");
	PRINTF_HEX(cose->plaintext, cose->plaintext_len);
	PRINTF("IV: \n");
	PRINTF_HEX(cose->nonce, cose->nonce_len);
	PRINTF("Key:\n");
	PRINTF_HEX(key, key_len);
	PRINTF("AAD:\n");
	PRINTF_HEX(cose->aad, cose->aad_len);




  //aead work on one buffer for plaintext and ciphertext
 // memcpy(cose->ciphertext, cose->plaintext, cose->plaintext_len);


  COSE_AES_CCM.set_key(key);
  COSE_AES_CCM.aead(cose->nonce, cose->ciphertext, cose->plaintext_len, cose->aad, cose->aad_len, &cose->ciphertext[cose->plaintext_len], TSize, 1);
  PRINTF("CCM STAR ciphertext:\n");
  PRINTF_HEX(cose->ciphertext, cose->ciphertext_len);

		
	if(ret == 0){
		return 0;
	}

	PRINTF("Error in AES CCM Encrypt \n");
	int x = ret;
	PRINTF("%s%x\n", x<0?"-":"", x<0?-(unsigned)x:x);
	return 1;
}

uint8_t OPT_COSE_Decrypt(opt_cose_encrypt_t *cose, uint8_t *key, size_t key_len){

	PRINTF("Decrypt OPT_COSE\n");

	int ret = 0;
	

    if(cose->alg == COSE_Algorithm_AES_CCM_64_64_128 && key_len == 16){
//		cipher = MBEDTLS_CIPHER_ID_AES;
	}else{
		PRINTF("Error in Decrypt with key and algorithm\n");
		return 1;
	}
	size_t TagSize = 8; //Sort this out
	

	PRINTF("Decrypting:\n");
	PRINTF_HEX(cose->ciphertext, cose->ciphertext_len);
	PRINTF("IV: \n");
	PRINTF_HEX(cose->nonce, cose->nonce_len);
	PRINTF("Key:\n");
	PRINTF_HEX(key, key_len);
	PRINTF("AAD:\n");
	PRINTF_HEX(cose->aad, cose->aad_len);

  

  uint8_t tag[TagSize];

  COSE_AES_CCM.set_key(key);
  COSE_AES_CCM.aead(cose->nonce, cose->ciphertext, cose->plaintext_len, cose->aad, cose->aad_len, tag, TagSize, 0);

  if(memcmp(tag, &cose->ciphertext[cose->plaintext_len], TagSize) != 0){
  	PRINTF("ERROR vadidating AES-CCM tag\n");
  	return 1;
  }
  //Move the decrypted plaintext to the plaintext fielf
  memcpy(cose->plaintext, cose->ciphertext, cose->plaintext_len);


	if(ret == 0){
		PRINTF("COSE AES CCM plaintext:\n");
		PRINTF_HEX(cose->plaintext, cose->plaintext_len);
		return 0;
   	}

	PRINTF("Error in AES CCM Decrypt \n");
	int x = ret;
	PRINTF("%s%x\n", x<0?"-":"", x<0?-(unsigned)x:x);
	return 1;

}
