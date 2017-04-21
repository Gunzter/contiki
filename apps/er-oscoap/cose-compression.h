#ifndef _COSE_COMPRESSION_H
#define _COSE_COMPRESSION_H
#include <stddef.h>
#include <inttypes.h>
#include "opt-cose.h"
#include "er-oscoap.h"


uint8_t cose_compress(opt_cose_encrypt_t* cose, uint8_t* buffer);

uint8_t cose_decompress(opt_cose_encrypt_t* cose, uint8_t* buffer, size_t buffer_len);


#endif /*_COSE_COMPRESSION_H*/