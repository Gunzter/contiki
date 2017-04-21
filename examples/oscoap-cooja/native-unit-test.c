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
 *      Erbium (Er) REST Engine example.
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "rest-engine.h"
#include "er-oscoap.h"
#include "cose-compression.h"


#if PLATFORM_HAS_BUTTON
#include "dev/button-sensor.h"
#endif

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

/*
 * Resources to be activated need to be imported through the extern keyword.
 * The build system automatically compiles the resources in the corresponding sub-directory.
 */
extern resource_t
  res_hello,
  res_mirror,
  res_chunks,
  res_separate,
  res_push,
  res_event,
	  res_sub,
	  res_b1_sep_b2;
#if PLATFORM_HAS_LEDS
extern resource_t res_leds, res_toggle;
#endif
#if PLATFORM_HAS_LIGHT
#include "dev/light-sensor.h"
extern resource_t res_light;
#endif
#if PLATFORM_HAS_BATTERY
#include "dev/battery-sensor.h"
extern resource_t res_battery;
#endif
#if PLATFORM_HAS_TEMPERATURE
#include "dev/temperature-sensor.h"
extern resource_t res_temperature;
#endif

#define NUMBER_OF_URLS 5
char *service_urls[NUMBER_OF_URLS] =
{ ".well-known/core", "/actuators/toggle", "battery/", "error/in//path", "/hello" };

/*
extern resource_t res_battery;
#endif
#if PLATFORM_HAS_RADIO
#include "dev/radio-sensor.h"
extern resource_t res_radio;
#endif
#if PLATFORM_HAS_SHT11
#include "dev/sht11/sht11-sensor.h"
extern resource_t res_sht11;
#endif
*/

uint8_t receiver_key[] = {0xEB,0x43,0x09,0x8A,0x0F,0x6F,0x7B,0x69,0xCE,0xDF,0x29,0xE0,0x80,0x50,0x95,0x82};
uint8_t receiver_iv[] = {0x58,0xF9,0x1A,0x5C,0xDF,0xF4,0xF5};

uint8_t sender_key[] =  {0xF8,0x20,0x1E,0xD1,0x5E,0x10,0x37,0xBC,0xAF,0x69,0x06,0x07,0x9A,0xD3,0x0B,0x4F};
uint8_t sender_iv[] =  {0xE8,0x28,0xA4,0x79,0xD0,0x88,0xC4};

uint8_t sender_id[] = { 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74 };
uint8_t receiver_id[] = { 0x73, 0x65, 0x72, 0x76, 0x65, 0x72 };

PROCESS(er_example_server, "Erbium Example Server");
AUTOSTART_PROCESSES(&er_example_server);

PROCESS_THREAD(er_example_server, ev, data)
{
  PROCESS_BEGIN();

  PROCESS_PAUSE();

  PRINTF("Starting Erbium Example Server\n");

#ifdef RF_CHANNEL
  PRINTF("RF channel: %u\n", RF_CHANNEL);
#endif
#ifdef IEEE802154_PANID
  PRINTF("PAN ID: 0x%04X\n", IEEE802154_PANID);
#endif

  PRINTF("uIP buffer: %u\n", UIP_BUFSIZE);
  PRINTF("LL header: %u\n", UIP_LLH_LEN);
  PRINTF("IP+UDP header: %u\n", UIP_IPUDPH_LEN);
  PRINTF("REST max chunk: %u\n", REST_MAX_CHUNK_SIZE);

  /* Initialize the REST engine. */
  rest_init_engine();
  static coap_packet_t request[1];
  static coap_packet_t incomming_request[1];
  static coap_packet_t incomming_request2[1];
  /*
   * Bind the resources to their Uri-Path.
   * WARNING: Activating twice only means alternate path, not two instances!
   * All static variables are the same for each URI path.
   */
  rest_activate_resource(&res_hello, "hello");

#if PLATFORM_HAS_LEDS
  rest_activate_resource(&res_toggle, "actuators/toggle");
#endif
#if PLATFORM_HAS_BATTERY
  rest_activate_resource(&res_battery, "sensors/battery");  
  SENSORS_ACTIVATE(battery_sensor);  
#endif


oscoap_ctx_store_init();


//Interop

if(oscoap_new_ctx( sender_key, sender_iv, receiver_key, receiver_iv, sender_id, 6, receiver_id, 6, 32) == 0){
  printf("Error: Could not create new Context!\n");
}

  
  opt_cose_encrypt_t cose;
  opt_cose_encrypt_t cose2;
  OPT_COSE_Init(&cose);

  uint8_t kid[] = { 0xAA, 0xAA, 0xAA};
  uint8_t piv[] = { 0xFF};
  uint8_t ciphertext[] = { 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xc0};
  uint8_t buffer[50];
  cose.kid = kid;
  cose.kid_len = 3;
  cose.partial_iv = piv;
  cose.partial_iv_len = 1;
  cose.ciphertext = ciphertext;
  cose.ciphertext_len = 10;
  
  uint8_t ret = cose_compress(&cose, buffer);
  oscoap_printf_hex(buffer, ret);
  OPT_COSE_Init(&cose2);
  cose_decompress(&cose2, buffer, ret);
  printf("c_len %d, kid_len %d, piv_len %d \n", cose2.ciphertext_len, cose2.kid_len, cose2.partial_iv_len);
  oscoap_printf_hex(cose2.ciphertext, cose2.ciphertext_len);
  oscoap_printf_hex(cose2.kid, cose2.kid_len);
  oscoap_printf_hex(cose2.partial_iv, cose2.partial_iv_len);

  OPT_COSE_Init(&cose);
  cose.partial_iv = piv;
  cose.partial_iv_len = 1;
  cose.ciphertext = ciphertext;
  cose.ciphertext_len = 10;
  ret = cose_compress(&cose, buffer);
  oscoap_printf_hex(buffer, ret);  
  OPT_COSE_Init(&cose2);
  cose_decompress(&cose2, buffer, ret);
  printf("c_len %d, kid_len %d, piv_len %d \n", cose2.ciphertext_len, cose2.kid_len, cose2.partial_iv_len);
  oscoap_printf_hex(cose2.ciphertext, cose2.ciphertext_len);
  oscoap_printf_hex(cose2.kid, cose2.kid_len);
  oscoap_printf_hex(cose2.partial_iv, cose2.partial_iv_len);

  OPT_COSE_Init(&cose);
  cose.kid = kid;
  cose.kid_len = 3;
  cose.ciphertext = ciphertext;
  cose.ciphertext_len = 10;
  ret = cose_compress(&cose, buffer);
  oscoap_printf_hex(buffer, ret);
  OPT_COSE_Init(&cose2);
  cose_decompress(&cose2, buffer, ret);
  printf("c_len %d, kid_len %d, piv_len %d \n", cose2.ciphertext_len, cose2.kid_len, cose2.partial_iv_len);
  oscoap_printf_hex(cose2.ciphertext, cose2.ciphertext_len);
  oscoap_printf_hex(cose2.kid, cose2.kid_len);
  oscoap_printf_hex(cose2.partial_iv, cose2.partial_iv_len);
/*
  OscoapCommonContext* c = NULL;
  uint8_t rid2[] = { 0x73, 0x65, 0x72, 0x76, 0x65, 0x72 };
  c = oscoap_find_ctx_by_rid(rid2, 6);
  PRINTF("COAP max s ize %d\n", COAP_MAX_PACKET_SIZE);
  if(c == NULL){
      PRINTF("could not fetch cid\n");
  } else {
    	PRINTF("Context sucessfully added to DB!\n");
  }

  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 65535);
 
  //TODO, this should be implemented using the uri -> cid map, not like this.
  uint8_t rid3[] = { 0x73, 0x65, 0x72, 0x76, 0x65, 0x72 };
  request->context = oscoap_find_ctx_by_rid(rid3, 6);

  coap_set_header_uri_path(request, service_urls[4]);

  coap_set_header_object_security(request);
  const uint8_t token[] = { 0x05, 0x05 };
  coap_set_token(request, token, 2);
  uint8_t buffer[100];
  memset(buffer, 0, 100);
  printf("serializing \n");
  uint16_t len = coap_serialize_message(request, buffer);
  printf("done serializing, len %d\n",len);
  oscoap_printf_hex(buffer, len);

  uint8_t message[40] =  {0x42, 0x01, 0x48, 0x7b, 0x05, 0x05, 0xd0, 0x01, 0x7d, 0x11, 0x83, 0x4c, 0xa2, 0x02, 0x46, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x06, 0x41, 0x07, 0xa0, 0x4e, 0x52, 0x09, 0x65, 0x8c, 0x57, 0xed, 0x11, 0x51, 0x32, 0x9c, 0x18, 0x15, 0x37, 0xc9 };
  uint8_t message2[40] = {0x42, 0x01, 0x48, 0x7c, 0x05, 0x05, 0xd0, 0x01, 0x7d, 0x11, 0x83, 0x4c, 0xa2, 0x02, 0x46, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x06, 0x41, 0x08, 0xa0, 0x4e, 0x82, 0xfb, 0x67, 0xc2, 0x8e, 0x6f, 0xee, 0x6c, 0xba, 0x69, 0x80, 0xbd, 0x59, 0x92}; 


  uint8_t buffer2[100];
  memcpy(buffer2, message, 40);
  coap_parse_message(incomming_request, buffer2, len);
  memcpy(buffer2, message2, 40);
  
  printf("\n\n\nOscoap parser\n");
  oscoap_parser(incomming_request2, buffer2, len, ROLE_COAP);
  printf("end \n",); */

  PROCESS_END();
}
