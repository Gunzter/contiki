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

#include "contiki.h"

#if PLATFORM_HAS_LEDS

#include <string.h>
#include "rest-engine.h"
#include "sys/energest.h"
#include "er-coap.h"

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINT6ADDR(addr) PRINTF("[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]", ((uint8_t *)addr)[0], ((uint8_t *)addr)[1], ((uint8_t *)addr)[2], ((uint8_t *)addr)[3], ((uint8_t *)addr)[4], ((uint8_t *)addr)[5], ((uint8_t *)addr)[6], ((uint8_t *)addr)[7], ((uint8_t *)addr)[8], ((uint8_t *)addr)[9], ((uint8_t *)addr)[10], ((uint8_t *)addr)[11], ((uint8_t *)addr)[12], ((uint8_t *)addr)[13], ((uint8_t *)addr)[14], ((uint8_t *)addr)[15])
#define PRINTLLADDR(lladdr) PRINTF("[%02x:%02x:%02x:%02x:%02x:%02x]", (lladdr)->addr[0], (lladdr)->addr[1], (lladdr)->addr[2], (lladdr)->addr[3], (lladdr)->addr[4], (lladdr)->addr[5])
#else
#define PRINTF(...)
#define PRINT6ADDR(addr)
#define PRINTLLADDR(addr)
#endif

static messages_received = 0;
static unsigned long last_cpu, last_lpm, last_listen, last_transmit;
static int i;
static int p_len;
static void res_post_put_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);
static void res_get_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

/*A simple actuator example, depending on the color query parameter and post variable mode, corresponding led is activated or deactivated*/
RESOURCE(res_performance,
         "title=\"LEDs: ?color=r|g|b, POST/PUT mode=on|off\";rt=\"Control\"",
         res_get_handler,
         res_post_put_handler,
         res_post_put_handler,
         NULL);

static void
res_get_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  const char *len = NULL;
//  printf("res handler\n");
  /* Some data that has the length up to REST_MAX_CHUNK_SIZE. For more, see the chunk resource. */

  coap_packet_t* coap_request = (coap_packet_t*)request;
  if(IS_OPTION(coap_request, COAP_OPTION_OBJECT_SECURITY)){
    coap_packet_t* coap_response = (coap_packet_t*)response;
    coap_response->context = coap_request->context;
    coap_set_header_object_security(coap_response);
  }else {
    printf("NOT OSCOAP\n");
    printf("TODO SEND ERRORS!\n");
    REST.set_response_status(response, REST.status.UNAUTHORIZED);
    char error_msg[] = "Resource guarded by ogres, stay away!";
    REST.set_response_payload(response, error_msg, strlen(error_msg));
    return;
  }


  char const *const message = "Hello World! ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxy";
  int length = 12; /*          |<-------->| */
  messages_received++;
  printf("p(%lu,%lu,%lu,%lu);v(%d);m(%d);len(%d)\n",
             energest_type_time(ENERGEST_TYPE_CPU) - last_cpu,
             energest_type_time(ENERGEST_TYPE_LPM) - last_lpm,
             energest_type_time(ENERGEST_TYPE_TRANSMIT) - last_transmit,
             energest_type_time(ENERGEST_TYPE_LISTEN) - last_listen,
            i++, messages_received, p_len);

  last_cpu = energest_type_time(ENERGEST_TYPE_CPU);
  last_lpm = energest_type_time(ENERGEST_TYPE_LPM);
  last_transmit = energest_type_time(ENERGEST_TYPE_TRANSMIT);
  last_listen = energest_type_time(ENERGEST_TYPE_LISTEN);
  messages_received = 0;
  p_len = 0;
  /* The query string can be retrieved by rest_get_query() or parsed for its key-value pairs. */
/*  if(REST.get_query_variable(request, "len", &len)) {
    length = atoi(len);
    if(length < 0) {
      length = 0;
    }
    if(length > REST_MAX_CHUNK_SIZE) {
      length = REST_MAX_CHUNK_SIZE;
    }
    memcpy(buffer, message, length);
  } else {
    memcpy(buffer, message, length);
  }
 REST.set_header_content_type(response, REST.type.TEXT_PLAIN); */
/* text/plain is the default, hence this option could be omitted. */
  
REST.set_response_payload(response, buffer, length);
}
  

static void
res_post_put_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{

  size_t len = 0;
  const uint8_t *bytes = NULL;
  coap_packet_t* coap_request = (coap_packet_t*)request;
  if(IS_OPTION(coap_request, COAP_OPTION_OBJECT_SECURITY)){
    coap_packet_t* coap_response = (coap_packet_t*)response;
    coap_response->context = coap_request->context;
    coap_set_header_object_security(coap_response);
//    printf("OSCOAP!\n");
  }else {
    printf("NOT OSCOAP\n");
    printf("TODO SEND ERRORS!\n");
    REST.set_response_status(response, REST.status.UNAUTHORIZED);
    char error_msg[] = "Resource guarded by ogres, stay away!";
    REST.set_response_payload(response, error_msg, strlen(error_msg));
    return;
  }

 messages_received++;
  char const *const msg = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghiljklmnopqrstuvwxyz012345678910111213141516171819202122232425262728293031323334353637383940";
//    REST.set_response_status(response, REST.status.BAD_REQUEST);
  REST.set_header_content_type(response, REST.type.TEXT_PLAIN); 
  /* text/plain is the default, hence this option could be omitted. */
  len =  REST.get_request_payload(request, &bytes);
  if(len > p_len){
  	p_len = len;
  }
  memcpy(buffer, msg, len);
  REST.set_response_payload(response, buffer, len);
}
#endif /* PLATFORM_HAS_LEDS */
