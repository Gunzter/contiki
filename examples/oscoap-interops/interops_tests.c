#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "er-coap-engine.h"
#include "er-oscoap.h"
#include <assert.h>
#include "interops_tests.h"

uint8_t test = 0;
uint8_t failed_tests = 0;
static coap_observee_t *obs;

char *urls[6] = { "/hello/coap", "/hello/1", "/hello/2", "/hello/3", "/observe", "/hello/6"};
uint8_t rid[] = { 0x73, 0x65, 0x72, 0x76, 0x65, 0x72 };

void test0_a(coap_packet_t* request){
  printf("\n\nTest 0a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, urls[0]);

  printf("Test 0a: Sending!\n");
}

void test0_a_handler(void* response){
  printf("Test 0a: Receiving Response!\n");

  const uint8_t *response_payload;
  const char desired[] = "Hello World!";
  int len = coap_get_payload(response, &response_payload);
  int res = strncmp( desired, response_payload, strlen(desired));
  if(res == 0){
    printf("Test 0a: PASSED!\n");
  }else {
    printf("Test 0a: FAILED!\n");
    printf("\t Expected result: \"Hello World!\" but was: ");
    oscoap_printf_char(response_payload, len);
    failed_tests++;
  }
}

void test1_a(coap_packet_t* request){
  printf("\n\nTest 1a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, urls[1]);
  coap_set_header_object_security(request);
 
  request->context = oscoap_find_ctx_by_rid(rid, 6); 
  if(request->context == NULL){
    printf("PROBLEMAS!\n");
  } 

  printf("Test 1a: Sending!\n");
}

void test1_a_handler(void* response){
  printf("Test 1a: Receiving Response!\n");

  const uint8_t *response_payload;
  const char desired[] = "Hello World!";
  int len = coap_get_payload(response, &response_payload);
  int res = strncmp( desired, response_payload, strlen(desired));

  if(res == 0){
    printf("Test 1a: PASSED!\n");
  }else {
    printf("Test 1a: FAILED!\n");
    printf("\t Expected result: \"Hello World!\" but was: ");
    oscoap_printf_char(response_payload, len);
    failed_tests++;
  }
} 

void test2_a(coap_packet_t* request){
  printf("\n\nTest 2a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, urls[2]);
  coap_set_header_object_security(request);
 
  request->context = oscoap_find_ctx_by_rid(rid, 6); 
  if(request->context == NULL){
    printf("PROBLEMAS!\n");
  }    

  char uri_query[] = "first=1";
  coap_set_header_uri_query(request, uri_query);
  printf("Test 2a: Sending!\n");
}

void test2_a_handler(void* response){
  printf("Test 2a: Receiving Response!\n");

  const uint8_t *response_payload;
  const char desired[] = "Hello World!";
  const uint8_t desired_etag = 0x2b;
  int len = coap_get_payload(response, &response_payload);
  int res = strncmp( desired, response_payload, strlen(desired));
  uint8_t *etag;

  int etag_len = coap_get_header_etag(response, &etag);
  if((etag_len != 1)){
    res++;
  }

  unsigned int content = 15;
  coap_get_header_content_format(response, &content);
  if(content != 0){
    res++;
  }
  
  res += memcmp(etag, &desired_etag, 1);

  if(res == 0){
    printf("Test 2a: PASSED!\n");
  }else {
    printf("Test 2a: FAILED!\n");
    printf("\t Expected result: \"Hello World!\" but was: ");
    oscoap_printf_char(response_payload, len);
    printf("Expected etag: \"0x2b\" or \"43\" but was %02x or %d, length %d\n", etag[0], etag[0], etag_len);
    failed_tests++;
  }
} 

void test3_a(coap_packet_t* request){
  printf("\n\nTest 3a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, urls[3]);
  coap_set_header_accept(request, 0);

  coap_set_header_object_security(request);
  request->context = oscoap_find_ctx_by_rid(rid, 6); 
  if(request->context == NULL){
    printf("PROBLEMAS!\n");
  } 

  printf("Test 3a: Sending!\n");
}

void test3_a_handler(void* response){
  printf("Test 3a: Receiving Response!\n");

  const uint8_t *response_payload;
  const char desired[] = "Hello World!";
  int len = coap_get_payload(response, &response_payload);
  int res = strncmp( desired, response_payload, strlen(desired));
  
  uint32_t age = 0;
  coap_get_header_max_age(response, &age);
  if(age != 0x05){
    res++;
  }

  unsigned int content = 15;
  coap_get_header_content_format(response, &content);
  if(content != 0){
    res++;
  }

  if(res == 0){
    printf("Test 3a: PASSED!\n");
  }else {
    printf("Test 3a: FAILED!\n");
    printf("\t Expected result: \"Hello World!\" but was: ");
    printf("Expected restult: Max Age \"5\", was %d, Content Format \"0\", was %d\n", age, content);
    oscoap_printf_char(response_payload, len);
    failed_tests++;
  }
}

void test4_a(uip_ipaddr_t *server_ipaddr, uint16_t server_port)
{
//  if(obs) {
//    printf("Stopping observation\n");
//    coap_obs_remove_observee(obs);
//    obs = NULL;
//  } else {
//   printf("Starting observation\n");
	printf("\n\nTest 4a: Starting!\n");

	OscoapCommonContext* ctx = oscoap_find_ctx_by_rid(rid, 6);
	if(ctx == NULL){
		printf("PROBLEMAS!\n");
	}

	printf("Test 4a: Sending!\n");
    obs = oscoap_obs_request_registration(server_ipaddr, server_port,
                                        urls[4], test4_a_handler, NULL, ctx);

 //   obs = coap_obs_request_registration(server_ipaddr, REMOTE_PORT,
 //                                       OBS_RESOURCE_URI, notification_callback, NULL);
 // }
}


static void test4_a_handler(coap_observee_t *obs, void *notification,
                      coap_notification_flag_t flag){
  int len = 0;
  const uint8_t *payload = NULL;

  printf("Test 4a handler\n");
  printf("Observee URI: %s\n", obs->url);
  if(notification) {
    len = coap_get_payload(notification, &payload);
  }
  switch(flag) {
  case NOTIFICATION_OK:
    printf("NOTIFICATION OK: %*s\n", len, (char *)payload);
    break;
  case OBSERVE_OK: /* server accepeted observation request */
    printf("OBSERVE_OK: %*s\n", len, (char *)payload);
    break;
  case OBSERVE_NOT_SUPPORTED:
    printf("OBSERVE_NOT_SUPPORTED: %*s\n", len, (char *)payload);
    obs = NULL;
    break;
  case ERROR_RESPONSE_CODE:
    printf("ERROR_RESPONSE_CODE: %*s\n", len, (char *)payload);
    obs = NULL;
    break;
  case NO_REPLY_FROM_SERVER:
    printf("NO_REPLY_FROM_SERVER: "
           "removing observe registration with token %x%x\n",
           obs->token[0], obs->token[1]);
    obs = NULL;
    break;
  }

}


static void
notification_callback(coap_observee_t *obs, void *notification,
                      coap_notification_flag_t flag)
{
  int len = 0;
  const uint8_t *payload = NULL;

  printf("Notification handler\n");
  printf("Observee URI: %s\n", obs->url);
  if(notification) {
    len = coap_get_payload(notification, &payload);
  }
  switch(flag) {
  case NOTIFICATION_OK:
    printf("NOTIFICATION OK: %*s\n", len, (char *)payload);
    break;
  case OBSERVE_OK: /* server accepeted observation request */
    printf("OBSERVE_OK: %*s\n", len, (char *)payload);
    break;
  case OBSERVE_NOT_SUPPORTED:
    printf("OBSERVE_NOT_SUPPORTED: %*s\n", len, (char *)payload);
    obs = NULL;
    break;
  case ERROR_RESPONSE_CODE:
    printf("ERROR_RESPONSE_CODE: %*s\n", len, (char *)payload);
    obs = NULL;
    break;
  case NO_REPLY_FROM_SERVER:
    printf("NO_REPLY_FROM_SERVER: "
           "removing observe registration with token %x%x\n",
           obs->token[0], obs->token[1]);
    obs = NULL;
    break;
  }
}
/*----------------------------------------------------------------------------*/
/*
 * Toggle the observation of the remote resource
 */

