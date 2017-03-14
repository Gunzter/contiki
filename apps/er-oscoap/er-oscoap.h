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

#ifndef _OSCOAP_H
#define _OSCOAP_H

#include "er-oscoap-context.h"
#include "er-coap.h"
#include <sys/types.h>

#define CLEAR_OPTION(packet, opt) ((packet)->options[opt / OPTION_MAP_SIZE] &= ~(1 << (opt % OPTION_MAP_SIZE))) //clear one bit


//debug methods
void oscoap_printf_hex(unsigned char *data, unsigned int len);
void oscoap_printf_char(unsigned char *data, unsigned int len);
void oscoap_printf_bin(unsigned char *data, unsigned int len);


void clear_options(coap_packet_t* coap_pkt);
size_t oscoap_prepare_message(void* packet, uint8_t* buffer);
coap_status_t oscoap_decode_packet(coap_packet_t* coap_pkt);
void oscoap_restore_packet(void* packet);
size_t oscoap_prepare_plaintext(void* packet, uint8_t* plaintext_buffer);


#endif /* _OSCOAP_H */
