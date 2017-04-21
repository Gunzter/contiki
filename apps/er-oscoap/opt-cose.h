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
#ifndef _OPT_COSE_H
#define _OPT_COSE_H
#include <stddef.h>
#include <inttypes.h>

typedef struct opt_cose_encrypt_t{

	uint8_t alg;
	
	//Sequence number is stored as partial_iv
	uint8_t *partial_iv; //protected
	size_t partial_iv_len;
	
	uint8_t* kid; //protected - only if message is request
	size_t kid_len;

	/* Unprotected shall be empty */
	
	uint8_t *nonce;
	size_t nonce_len;

	uint8_t *aad;
	size_t aad_len;
	
	uint8_t *external_aad;
	size_t external_aad_len;

	uint8_t *plaintext;
	size_t plaintext_len;

	uint8_t *ciphertext;
	size_t ciphertext_len;

	size_t serialized_len;
} opt_cose_encrypt_t;

#define INCLUDE_KID 					  1
#define INCLUDE_PARTIAL_IV 				  2

#define COSE_Algorithm_AES_CCM_64_64_128 12 
#define COSE_Header_KID 				  4 
#define COSE_Header_Partial_IV 			  6

void OPT_COSE_Init(opt_cose_encrypt_t *cose);

uint8_t OPT_COSE_Encrypt_Encode(opt_cose_encrypt_t *cose, uint8_t *key, size_t key_len, uint8_t *buffer);

uint8_t OPT_COSE_SetContent(opt_cose_encrypt_t *cose, uint8_t *plaintext_buffer, size_t plaintext_len);

uint8_t OPT_COSE_SetAlg(opt_cose_encrypt_t *cose, uint8_t alg);

uint8_t OPT_COSE_SetPartialIV(opt_cose_encrypt_t *cose, uint8_t *partial_iv_buffer, size_t partial_iv_len);
uint8_t* OPT_COSE_GetPartialIV(opt_cose_encrypt_t *cose, size_t *partial_iv_len);

uint8_t OPT_COSE_SetKeyID(opt_cose_encrypt_t *cose, uint8_t *kid_buffer, size_t kid_len);
uint8_t* OPT_COSE_GetKeyID(opt_cose_encrypt_t *cose, size_t *kid_len);

uint8_t OPT_COSE_SetExternalAAD(opt_cose_encrypt_t *cose, uint8_t *external_aad_buffer, size_t external_aad_len);

uint8_t OPT_COSE_SetAAD(opt_cose_encrypt_t *cose, uint8_t *aad_buffer, size_t aad_len);

uint8_t OPT_COSE_SetNonce(opt_cose_encrypt_t *cose, uint8_t *nonce_buffer, size_t nonce_len);
uint8_t OPT_COSE_SetCiphertextBuffer(opt_cose_encrypt_t *cose, uint8_t *ciphertext_buffer, size_t ciphertext_len);

size_t OPT_COSE_Encoded_length(opt_cose_encrypt_t *cose);

size_t OPT_COSE_Decode(opt_cose_encrypt_t *cose, uint8_t *buffer, size_t buffer_len);

size_t OPT_COSE_Encode(opt_cose_encrypt_t *cose, uint8_t *buffer);
uint8_t OPT_COSE_Build_AAD(opt_cose_encrypt_t *cose, uint8_t *buffer);
size_t  OPT_COSE_AAD_length(opt_cose_encrypt_t *cose);

uint8_t OPT_COSE_Encode_Attributes(opt_cose_encrypt_t *cose, uint8_t **buffer);

uint8_t OPT_COSE_Encrypt(opt_cose_encrypt_t *cose, uint8_t *key, size_t key_len);
uint8_t OPT_COSE_Decrypt(opt_cose_encrypt_t *cose, uint8_t *key, size_t key_len);

#endif /* _OPT_COSE_H */