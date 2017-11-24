#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


extern uint8_t led_green;
extern uint8_t led_red;
extern uint8_t lock;

#define HWTEST_GPIO_INPUT            0
#define HWTEST_GPIO_OUTPUT           1
#define HWTEST_GPIO_OUTPUT_ODD       3
#define HWTEST_GPIO_OUTPUT_LIST      4
#define HWTEST_GPIO_OUTPUT_MASK      0x55
#define HWTEST_GPIO_OUTPUT_ODD_MASK  0xAA

void set_lock(uint8_t status);
void set_led_green(uint8_t status);
void set_led_red(uint8_t status);
void initiate_hw_interface(void);
