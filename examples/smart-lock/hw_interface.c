#include "hw_interface.h"
#include "contiki.h"
//#include "address_export.h"
#include "er-oscoap.h"
//uint8_t *a_ptr;
//uint8_t *b_ptr;

#define HW 1 
#if HW
#include "dev/gpio.h"
#endif

#define DEBUG 1
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif


uint8_t led_green = 0;
uint8_t led_red = 0;
uint8_t lock = 0;

static struct etimer two_sec;
static struct etimer ten_hz;

#define TOGGLE_INTERVAL 10
PROCESS(hw_interface, "Hardware Interface");


static void clear_led_red(){
	led_red = 0;
}

static void clear_led_green(){
	led_green = 0;
}

#if HW
static void
config_gpio(uint8_t port, uint8_t pin, uint8_t type)
{
  GPIO_SOFTWARE_CONTROL(GPIO_PORT_TO_BASE(port), GPIO_PIN_MASK(pin));
  if(type == HWTEST_GPIO_OUTPUT) {
    GPIO_SET_OUTPUT(GPIO_PORT_TO_BASE(port), GPIO_PIN_MASK(pin));
  } else if(type == HWTEST_GPIO_INPUT) {
    GPIO_SET_INPUT(GPIO_PORT_TO_BASE(port), GPIO_PIN_MASK(pin));
  }
}
#endif

//TODO add mutex
void set_lock(uint8_t status){
	if(status > 0){
		lock = 1;
	} else{
		lock = 0;
	}
}

void set_led_green(uint8_t status){
	clear_led_red();
	etimer_set(&two_sec, 2 * CLOCK_SECOND);
	if(status > 0){
		led_green = 1;
	} else{
		led_green = 0;
	}
}

void set_led_red(uint8_t status){
	clear_led_green();
	etimer_set(&two_sec, 2 * CLOCK_SECOND);
	if(status > 0){
		led_red = 1;
	} else{
		led_red = 0;
	}
}

static void update_hw(){
	#if HW
	if(led_red){
		GPIO_SET_PIN(GPIO_PORT_TO_BASE(GPIO_A_NUM), GPIO_PIN_MASK(4));
	}else {
		GPIO_CLR_PIN(GPIO_PORT_TO_BASE(GPIO_A_NUM), GPIO_PIN_MASK(4));
	}

	if(led_green){
		GPIO_SET_PIN(GPIO_PORT_TO_BASE(GPIO_A_NUM), GPIO_PIN_MASK(5));
	}else {
		GPIO_CLR_PIN(GPIO_PORT_TO_BASE(GPIO_A_NUM), GPIO_PIN_MASK(5));
	}

	if(lock){ // when PA3 is 0 the lock is locked, PA3 == 1 => open
		GPIO_CLR_PIN(GPIO_PORT_TO_BASE(GPIO_A_NUM), GPIO_PIN_MASK(3));
	}else {
		GPIO_SET_PIN(GPIO_PORT_TO_BASE(GPIO_A_NUM), GPIO_PIN_MASK(3));
	}
	#endif
}

void initiate_hw_interface(void)
{
  process_start(&hw_interface, NULL);
  #if HW
  config_gpio(GPIO_A_NUM, 5, HWTEST_GPIO_OUTPUT);
  config_gpio(GPIO_A_NUM, 4, HWTEST_GPIO_OUTPUT);
  config_gpio(GPIO_A_NUM, 3, HWTEST_GPIO_OUTPUT);
  GPIO_CLR_PIN(GPIO_PORT_TO_BASE(GPIO_A_NUM), GPIO_PIN_MASK(5));
  GPIO_CLR_PIN(GPIO_PORT_TO_BASE(GPIO_A_NUM), GPIO_PIN_MASK(4));
  GPIO_CLR_PIN(GPIO_PORT_TO_BASE(GPIO_A_NUM), GPIO_PIN_MASK(3));
  #endif
}

void print_stack_pointer(){
	void* p = NULL;
	PRINTF("sp = %p\n", (void*)&p);
}

void test_sp(){
	PRINTF("test sp ");
	uint8_t a[20];
	int q = 5;
	int b = 10 + q;
	a[5] = b;
	print_stack_pointer();
	a[1] = 5;
}

PROCESS_THREAD(hw_interface, ev, data)
{
  PROCESS_BEGIN();
   PRINTF("hw started\n");
  static struct etimer et;

  etimer_set(&et, 1 * CLOCK_SECOND);
  etimer_set(&ten_hz, CLOCK_SECOND/10);
  etimer_set(&two_sec, 2*CLOCK_SECOND);
  
  while(1) {
    PROCESS_YIELD();

      if(etimer_expired(&ten_hz)){
      //	PRINTF("update hw\n");
      	update_hw();
      	etimer_reset(&ten_hz);
      }

	  if(etimer_expired(&two_sec)) {
	  	PRINTF("clear leds: lock=%d, red=%d, green=%d\n", lock, led_red, led_green);
	  	clear_led_green();
	  	clear_led_red();
	  	etimer_reset(&two_sec);
	  }

	  if(etimer_expired(&et)) {
//	    oscoap_PRINTF_hex(a_ptr, 8);
//	    oscoap_PRINTF_hex(b_ptr, 8);
//	    print_stack_pointer();
//	    test_sp();
 	    PRINTF("lock=%d, red=%d, green=%d\n", lock, led_red, led_green);
	    etimer_reset(&et);	
	    } /* etimer */
	
	} /*while 1 */
    
  PROCESS_END();
}
