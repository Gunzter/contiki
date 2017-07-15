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

char *urls[8] = { "/hello/coap", "/hello/1", "/hello/2", "/hello/3", "/observe", "/hello/6", "/hello/7", "/test"};
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

 // char uri_query[10];
  const char *uri_query = "first=1";
 // printf("uri_query :");
 // oscoap_printf_char( uri_query, 7);
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



void test6_a(coap_packet_t* request){
  printf("\n\nTest 6a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_POST, 0);
  coap_set_header_uri_path(request, urls[5]);
  coap_set_header_object_security(request);
  uint8_t payload[1];
  payload[0] = 0x4a;
  coap_set_header_content_format(request, 0);
  coap_set_payload(request, payload, 1);
  request->context = oscoap_find_ctx_by_rid(rid, 6); 
  if(request->context == NULL){
    printf("PROBLEMAS!\n");
  } 

  printf("Test 6a: Sending!\n");
}

void test6_a_handler(void* response){
  printf("Test 6a: Receiving Response!\n");
  int res = 0;

  const char *desired_location_path = "hello/6";
  const char *desired_location_query = "first=1";
  char *location_path;
  char *location_query;

  int path_len = coap_get_header_location_path(response, &location_path);
  if(strncmp( desired_location_path, location_path, strlen(desired_location_path)) != 0){
    res++;
    printf("fail 1\n");
  }

  int query_len = coap_get_header_location_query(response, &location_query);
  if(strncmp( desired_location_query, location_query, strlen(desired_location_query)) != 0){
    res++;
        printf("fail 2\n");
  }
  if(((coap_packet_t*)response)->code != CREATED_2_01){
    res++;
        printf("fail 3\n");
  }

  if(res == 0){
    printf("Test 6: PASSED!\n");
  }else {
    printf("Test 6a: FAILED!\n");
    printf("\t Result was: \n");
    oscoap_printf_char(location_path, path_len);
    oscoap_printf_char(location_query, query_len);
    printf("Code = %d\n", ((coap_packet_t*)response)->code);
    failed_tests++;
  }
} 

void test7_a(coap_packet_t* request){
  printf("\n\nTest 7a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_PUT, 0);
  coap_set_header_uri_path(request, urls[6]);
  coap_set_header_object_security(request);
  uint8_t payload[1];
  payload[0] = 0x7a;
  coap_set_header_content_format(request, 0);
  const uint8_t if_match[1] = { 0x7b };
  coap_set_header_if_match(request, if_match, 1);
  coap_set_payload(request, payload, 1);
  request->context = oscoap_find_ctx_by_rid(rid, 6); 
  if(request->context == NULL){
    printf("PROBLEMAS!\n");
  } 

  printf("Test 7a: Sending!\n");
}

void test7_a_handler(void* response){
  printf("Test 7a: Receiving Response!\n");
  int res = 0;

  if(((coap_packet_t*)response)->code != CHANGED_2_04){
    res++;
  }

  if(res == 0){
    printf("Test 7: PASSED!\n");
  }else {
    printf("Test 7a: FAILED!\n");
    printf("\t Expected result: 204 Changed.\n");

    failed_tests++;
  }
} 

void test8_a(coap_packet_t* request){
  printf("\n\nTest 8a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_PUT, 0);
  coap_set_header_uri_path(request, urls[6]);
  coap_set_header_object_security(request);
  uint8_t payload[1];
  payload[0] = 0x7a;
  coap_set_header_content_format(request, 0);
  coap_set_header_if_none_match(request);
  coap_set_payload(request, payload, 1);
  request->context = oscoap_find_ctx_by_rid(rid, 6); 
  if(request->context == NULL){
    printf("PROBLEMAS!\n");
  } 

  printf("Test 8a: Sending!\n");
}

void test8_a_handler(void* response){
  printf("Test 8a: Receiving Response!\n");
  int res = 0;

  if(((coap_packet_t*)response)->code != PRECONDITION_FAILED_4_12){
    res++;
  }

  if(res == 0){
    printf("Test 8: PASSED!\n");
  }else {
    printf("Test 8a: FAILED!\n");
    printf("\t Expected result: 4.12 Precondition Failed.\n");

    failed_tests++;
  }
} 

void test9_a(coap_packet_t* request){
  printf("\n\nTest 9a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_DELETE, 0);
  coap_set_header_uri_path(request, urls[7]);

  coap_set_header_object_security(request);
  request->context = oscoap_find_ctx_by_rid(rid, 6); 
  if(request->context == NULL){
    printf("PROBLEMAS!\n");
  } 

  printf("Test 9a: Sending!\n");
}

void test9_a_handler(void* response){
  printf("Test 9a: Receiving Response!\n");
  int res = 0;

  if(((coap_packet_t*)response)->code != DELETED_2_02){
    res++;
  }

  if(res == 0){
    printf("Test 9: PASSED!\n");
  }else {
    printf("Test 9a: FAILED!\n");
    printf("\t Expected result: 2.02 Deleted.\n");

    failed_tests++;
  }
} 
uint8_t false_sender_id[] = { 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x75 };
uint8_t real_sender_id[] = { 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74 };

uint8_t false_sender_key[] = {0x21, 0x64, 0x42, 0xda, 0x60, 0x3c, 0x51, 0x59, 0x2d, 0xf4, 0xc3, 0xd0, 0xcd, 0x1c, 0x0d, 0x48 };
uint8_t real_sender_key[] = {0x21, 0x64, 0x42, 0xda, 0x60, 0x3c, 0x51, 0x59, 0x2d, 0xf4, 0xc3, 0xd0, 0xcd, 0x1d, 0x0d, 0x48 };

uint8_t false_receiver_key[] =  {0xd1, 0xcb, 0x37, 0x10, 0x37, 0x15, 0x34, 0xa1, 0xca, 0x22, 0x4e, 0x19, 0xeb, 0x96, 0xe9, 0x6d };
uint8_t real_receiver_key[] =  {0xd5, 0xcb, 0x37, 0x10, 0x37, 0x15, 0x34, 0xa1, 0xca, 0x22, 0x4e, 0x19, 0xeb, 0x96, 0xe9, 0x6d };

OscoapCommonContext* context;
void test10_a(coap_packet_t* request){
  printf("\n\nTest 10a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, urls[1]);

  coap_set_header_object_security(request);
  request->context = oscoap_find_ctx_by_rid(rid, 6); 

  if(request->context == NULL){
    printf("PROBLEMAS!\n");
  } 
  request->context->SenderContext->SenderId = false_sender_id;
  context = request->context;
  printf("Test 10a: Sending!\n");
}

void test10_a_handler(void* response){
  printf("Test 10a: Receiving Response!\n");
  int res = 0;

  if(((coap_packet_t*)response)->code != UNAUTHORIZED_4_01){
    res++;
  }

  if(res == 0){
    printf("Test 10: PASSED!\n");
  }else {
    printf("Test 10a: FAILED!\n");
    printf("\t Expected result: 4.01 Unauthorized\n");

    failed_tests++;
  }

  context->SenderContext->SenderId = real_sender_id;
} 

void test11_a(coap_packet_t* request){
  printf("\n\nTest 11a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, urls[1]);

  coap_set_header_object_security(request);
  request->context = oscoap_find_ctx_by_rid(rid, 6); 

  if(request->context == NULL){
    printf("PROBLEMAS!\n");
  } 
  memcpy(request->context->SenderContext->SenderKey, false_sender_key, 16);
  context = request->context;
  printf("Test 11a: Sending!\n");
}

void test11_a_handler(void* response){
  printf("Test 11a: Receiving Response!\n");
  int res = 0;

  if(((coap_packet_t*)response)->code != BAD_REQUEST_4_00){
    res++;
  }

  if(res == 0){
    printf("Test 11: PASSED!\n");
  }else {
    printf("Test 11a: FAILED!\n");
    printf("\t Expected result: 4.00 Bad Request\n");

    failed_tests++;
  }
  memcpy(context->SenderContext->SenderKey, real_sender_key, 16);
} 

void test12_a(coap_packet_t* request){
  printf("\n\nTest 12a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, urls[1]);

  coap_set_header_object_security(request);
  request->context = oscoap_find_ctx_by_rid(rid, 6); 
  
  if(request->context == NULL){
    printf("PROBLEMAS!\n");
  } 
  memcpy(request->context->RecipientContext->RecipientKey, false_receiver_key, 16);
  context = request->context;
  printf("Test 12a: Sending!\n");
}

void test12_a_handler(void* response){
  printf("Test 12a: Receiving Response!\n");
  int res = 0;

  if(((coap_packet_t*)response)->code != BAD_REQUEST_4_00){
    res++;
  }

  if(res == 0){
    printf("Test 12: PASSED!\n");
  }else {
    printf("Test 12a: FAILED!\n");
    printf("\t Expected result: 4.00 Bad Request\n");

    failed_tests++;
  }
  memcpy(context->RecipientContext->RecipientKey, real_receiver_key, 16);
} 

void test13_a(coap_packet_t* request){
  printf("\n\nTest 13a: Starting!\n");
  printf("Restoring Recipient Key from Test 12a. \n");
  memcpy(context->RecipientContext->RecipientKey, real_receiver_key, 16);
  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, urls[1]);

  coap_set_header_object_security(request);
  request->context = oscoap_find_ctx_by_rid(rid, 6); 

  if(request->context == NULL){
    printf("PROBLEMAS!\n");
  } 
  request->context->SenderContext->Seq = 1;
  printf("Test 13a: Sending!\n");
}

void test13_a_handler(void* response){
  printf("Test 13a: Receiving Response!\n");
  int res = 0;

  if(((coap_packet_t*)response)->code != BAD_REQUEST_4_00){
    res++;
  }

  if(res == 0){
    printf("Test 13: PASSED!\n");
  }else {
    printf("Test 13a: FAILED!\n");
    printf("\t Expected result: 4.00 Bad Request\n");

    failed_tests++;
  }
context->SenderContext->Seq = 100;
} 

void test14_a(coap_packet_t* request){
  printf("\n\nTest 14a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, urls[0]);

  coap_set_header_object_security(request);
  request->context = oscoap_find_ctx_by_rid(rid, 6); 
  if(request->context == NULL){
    printf("PROBLEMAS!\n");
  } 
  printf("Test 14a: Sending!\n");
}

void test14_a_handler(void* response){
  printf("Test 14a: Receiving Response!\n");
  int res = 0;

  uint8_t *response_payload;
  int len = coap_get_payload(response, &response_payload);
  if(len != 0){
    res++;
  }

  if(((coap_packet_t*)response)->type != COAP_TYPE_ACK){
    res++;
  }

  if(res == 0){
    printf("Test 14: PASSED!\n");
  }else {
    printf("Test 14a: FAILED!\n");
    printf("\t Expected result: Empty ACK\n");

    failed_tests++;
  }
context->SenderContext->Seq = 100;
} 

void test15_a(coap_packet_t* request){
  printf("\n\nTest 15a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, urls[1]);

  printf("Test 15a: Sending!\n");
}

void test15_a_handler(void* response){
  printf("Test 15a: Receiving Response!\n");
  int res = 0;

  uint8_t *response_payload;
 // int len = coap_get_payload(response, &response_payload);
 // if(len != 0){
  //  res++;
 // }

  if(((coap_packet_t*)response)->code != UNAUTHORIZED_4_01){
    res++;
  }

  if(res == 0){
    printf("Test 15: PASSED!\n");
  }else {
    printf("Test 15a: FAILED!\n");

    printf("\t Expected result: UNAUTHORIZED_4_01 was %d\n", ((coap_packet_t*)response)->code);

    failed_tests++;
  }
context->SenderContext->Seq = 100;
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

