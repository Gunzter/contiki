/*
 * Copyright (c) 2013, Institute for Pervasive Computing, ETH Zurich
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 */

/**
 * \file
 *      Example resource
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */

#include <stdlib.h>
#include <string.h>
#include "rest-engine.h"
#include "er-coap.h"
#include "hw_interface.h"

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif


static void res_get_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);
static void res_put_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

uint8_t led_green;
uint8_t led_red;
uint8_t lock;
/*
 * A handler function named [resource name]_handler must be implemented for each RESOURCE.
 * A buffer for the response payload is provided through the buffer pointer. Simple resources can ignore
 * preferred_size and offset, but must respect the REST_MAX_CHUNK_SIZE limit for the buffer.
 * If a smaller block size is requested for CoAP, the REST framework automatically splits the data.
 */
RESOURCE(oscoap2_lock,
         "title=\"Lock ?len=0..\";rt=\"Text\"",
         res_get_handler,
         NULL,
         res_put_handler,
         NULL);

static void
res_get_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  PRINTF("GET handler 2\n");

  coap_packet_t* coap_request = (coap_packet_t*)request;
  if(IS_OPTION(coap_request, COAP_OPTION_OBJECT_SECURITY)){
    coap_packet_t* coap_response = (coap_packet_t*)response;
    coap_response->context = coap_request->context;
    coap_set_header_object_security(coap_response);
    PRINTF("OSCOAP!\n");
  }else {
    PRINTF("NOT OSCOAP\n");
    REST.set_response_status(response, REST.status.UNAUTHORIZED);
    char error_msg[] = "OSCORE only!";
    REST.set_response_payload(response, error_msg, strlen(error_msg));
    return;
  }


  char const *const locked_message = "1";
  int locked_len = 1;
  char const *const unlocked_message = "0";
  int unlocked_len = 1;

  REST.set_header_content_type(response, REST.type.TEXT_PLAIN); /* text/plain is the default, hence this option could be omitted. */

  int length = 1;
  if( lock == 1){ //lock locked
    memcpy(buffer, locked_message, locked_len);
  } else {
    memcpy(buffer, unlocked_message, unlocked_len);
  }
  
  REST.set_response_payload(response, buffer, length);

}


static void
res_put_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  //const char *len = NULL;
  PRINTF("PUT handler 2\n");

  coap_packet_t* coap_request = (coap_packet_t*)request;
  if(IS_OPTION(coap_request, COAP_OPTION_OBJECT_SECURITY)){
    coap_packet_t* coap_response = (coap_packet_t*)response;
    coap_response->context = coap_request->context;
    coap_set_header_object_security(coap_response);
    PRINTF("OSCOAP!\n");
  }else {
    PRINTF("NOT OSCOAP\n");
    REST.set_response_status(response, REST.status.UNAUTHORIZED);
    char error_msg[] = "OSCORE only!";
    REST.set_response_payload(response, error_msg, strlen(error_msg));
    return;
  }


  int len;
  const uint8_t *payload_buffer;
  len = REST.get_request_payload(request, &payload_buffer);
  int command = 0; 
  if(len == 1){
    const char* p_b= (char*)payload_buffer;
  
    if(*p_b == 0 || *p_b == 1){ //UGLY hack to accept both ASCII and int 0,1
      command = (int)(*p_b);
    }else {
      command = atoi(p_b);
    }

    PRINTF("command %d\n", command);
    
  }

  set_lock(command);

  //rest get payload
  //update HW monitor
  //send response
  REST.set_response_status(response, REST.status.CHANGED);
  REST.set_header_content_type(response, REST.type.TEXT_PLAIN); /* text/plain is the default, hence this option could be omitted. */
  REST.set_response_payload(response, payload_buffer, len);
}
