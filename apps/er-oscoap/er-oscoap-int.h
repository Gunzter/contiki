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
#ifndef _OSCOAP_INT_H
#define _OSCOAP_INT_H

#include "er-coap.h"
#include <sys/types.h>


#define CONTEXT_ID_LEN 8
#define CONTEXT_KEY_LEN 16 
#define CONTEXT_INIT_VECT_LEN 7
#define CONTEXT_SEQ_LEN 4 
#define ID_LEN 8
#define CONTEXT_ID_LEN 8

typedef struct OSCOAP_SENDER_CONTEXT OSCOAP_SENDER_CONTEXT;
typedef struct OSCOAP_RECIPIENT_CONTEXT OSCOAP_RECIPIENT_CONTEXT;
typedef struct OSCOAP_COMMON_CONTEXT OSCOAP_COMMON_CONTEXT;

struct OSCOAP_SENDER_CONTEXT
{
  uint8_t   SENDER_KEY[CONTEXT_KEY_LEN];
  uint8_t   SENDER_IV[CONTEXT_INIT_VECT_LEN];
  uint8_t   SENDER_ID[ID_LEN];
  uint8_t   SENDER_ID_LEN;
  uint32_t  SENDER_SEQ;
};

struct OSCOAP_RECIPIENT_CONTEXT
{
  OSCOAP_RECIPIENT_CONTEXT* RECIPIENT_CONTEXT; //This field facilitates easy integration of OSCOAP multicast
  uint8_t   RECIPIENT_KEY[CONTEXT_KEY_LEN];
  uint8_t   RECIPIENT_IV[CONTEXT_INIT_VECT_LEN];
  uint8_t   RECIPIENT_ID[ID_LEN];
  uint8_t   RECIPIENT_ID_LEN;
  uint32_t  RECIPIENT_SEQ;
  uint8_t   REPLAY_WINDOW;
};

struct OSCOAP_COMMON_CONTEXT{
  uint8_t CONTEXT_ID[CONTEXT_ID_LEN];
  uint8_t* BASE_KEY;
  size_t BASE_KEY_LEN;
  OSCOAP_SENDER_CONTEXT* SENDER_CONTEXT;
  OSCOAP_RECIPIENT_CONTEXT* RECIPIENT_CONTEXT;
  OSCOAP_COMMON_CONTEXT* NEXT_CONTEXT;
  uint8_t ALG;
};


#endif
