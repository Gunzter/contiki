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

uint8_t cose_compress(opt_cose_encrypt_t* cose, uint8_t* buffer){
	uint8_t header = 0;
	uint8_t i = 0;
	if(cose->kid != NULL){
		header |= (1 << 3);
	}

	if(cose->partial_iv != NULL){
		header |= (cose->partial_iv_len);
	}
	//TODO add countersign and group ID

	buffer[i] = header;
	i++;
	PRINTF("Header\n:");
	PRINTF_HEX(&header, 1);

	if(cose->partial_iv != NULL){
		memcpy(&buffer[i], cose->partial_iv, cose->partial_iv_len);
		i += cose->partial_iv_len;
	}

	if(cose->kid != NULL){
		buffer[i] = cose->kid_len;
		i++;
		memcpy(&buffer[i], cose->kid, cose->kid_len);
		i += cose->kid_len;
	}

	if(cose->ciphertext != NULL){
		memcpy(&buffer[i], cose->ciphertext, cose->ciphertext_len);
		i += cose->ciphertext_len;
	}

	return i;

}

uint8_t cose_decompress(opt_cose_encrypt_t* cose, uint8_t* buffer, size_t buffer_len){

	uint8_t i = 0; //offset in buffer

	if((buffer[0] & 0x07) != 0){ //Partial IV length is > 0
		cose->partial_iv_len = (buffer[i] & 0x07);
		i++;
		cose->partial_iv = &buffer[i];
		i += cose->partial_iv_len;
	}else {
		i++; //step by first byte
	}

	if((buffer[0] & (1 << 3)) != 0){ // KID is set
		cose->kid_len = buffer[i];
		i++;
		cose->kid = &buffer[i];
		i += cose->kid_len;
	}

	cose->ciphertext = &buffer[i];
	cose->ciphertext_len = buffer_len - i;

	return 0;
}

