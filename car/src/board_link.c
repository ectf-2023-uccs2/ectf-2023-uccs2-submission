/**
 * @file board_link.h
 * @author Frederich Stine
 * @brief Firmware UART interface implementation.
 * @date 2023
 *
 * This source file is part of an example system for MITRE's 2023 Embedded
 * System CTF (eCTF). This code is being provided only for educational purposes
 * for the 2023 MITRE eCTF competition, and may not meet MITRE standards for
 * quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2023 The MITRE Corporation
 */

#include <stdbool.h>
#include <stdint.h>

#include "inc/hw_memmap.h"
#include "inc/hw_types.h"
#include "inc/hw_uart.h"

#include "driverlib/gpio.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/uart.h"

#include "board_link.h"

#ifdef EXAMPLE_AES
#include "aes.h"
#endif

/**
 * @brief Set the up board link object
 *
 * UART 1 is used to communicate between boards
 */
void setup_board_link(void) {
  SysCtlPeripheralEnable(SYSCTL_PERIPH_UART1);
  SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOB);

  GPIOPinConfigure(GPIO_PB0_U1RX);
  GPIOPinConfigure(GPIO_PB1_U1TX);

  GPIOPinTypeUART(GPIO_PORTB_BASE, GPIO_PIN_0 | GPIO_PIN_1);

  // Configure the UART for 115,200, 8-N-1 operation.
  UARTConfigSetExpClk(
      BOARD_UART, SysCtlClockGet(), 115200,
      (UART_CONFIG_WLEN_8 | UART_CONFIG_STOP_ONE | UART_CONFIG_PAR_NONE));

  while (UARTCharsAvail(BOARD_UART)) {
    UARTCharGet(BOARD_UART);
  }
}

/**
 * @brief Send a message between boards
 *
 * @param message pointer to message to send
 * @return uint32_t the number of bytes sent
 */
uint32_t send_board_message(MESSAGE_PACKET *message) {
  
/*#ifdef EXAMPLE_AES
      // -------------------------------------------------------------------------
      // example encryption using tiny-AES-c
      // -------------------------------------------------------------------------
      struct AES_ctx ctx;
      uint8_t key[6] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5};
      //uint8_t plaintext[16];

      // initialize context
      AES_init_ctx(&ctx, key);

      // encrypt buffer (encryption happens in place)
      AES_ECB_decrypt(&ctx, message->buffer);
      // -------------------------------------------------------------------------
      // end example
      // -------------------------------------------------------------------------
    //#endif*/
  
  UARTCharPut(BOARD_UART, message->magic);
  UARTCharPut(BOARD_UART, message->message_len);

  for (int i = 0; i < message->message_len; i++) {
    UARTCharPut(BOARD_UART, message->buffer[i]);
  }

  return message->message_len;
}

/**
 * @brief Receive a message between boards
 *
 * @param message pointer to message where data will be received
 * @return uint32_t the number of bytes received - 0 for error
 */
uint32_t receive_board_message(MESSAGE_PACKET *message) {

    /*#ifdef EXAMPLE_AES
          // -------------------------------------------------------------------------
          // example encryption using tiny-AES-c
          // -------------------------------------------------------------------------
          struct AES_ctx ctx;
          uint8_t key[6] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5};
          //uint8_t plaintext[16];

          // initialize context
          AES_init_ctx(&ctx, key);

          // encrypt buffer (encryption happens in place)
          AES_ECB_decrypt(&ctx, message->buffer);
          // -------------------------------------------------------------------------
          // end example
          // -------------------------------------------------------------------------
    #endif*/
    
  message->magic = (uint8_t)UARTCharGet(BOARD_UART);

  if (message->magic == 0) {
    return 0;
  }

  message->message_len = (uint8_t)UARTCharGet(BOARD_UART);

  for (int i = 0; i < message->message_len; i++) {
    message->buffer[i] = (uint8_t)UARTCharGet(BOARD_UART);
  }

  return message->message_len;
}

uint32_t receive_board_nonce(NONCE_PACKET *nonce) {

  nonce->message_len = (uint8_t)UARTCharGet(BOARD_UART);

  for (int i = 0; i < nonce->message_len; i++) {
    nonce->buffer[i] = (uint8_t)UARTCharGet(BOARD_UART);
  }

  return nonce->message_len;
}

/**
 * @brief Function that retreives messages until the specified message is found
 *
 * @param message pointer to message where data will be received
 * @param type the type of message to receive
 * @return uint32_t the number of bytes received
 */
uint32_t receive_board_message_by_type(MESSAGE_PACKET *message, uint8_t type) {
  do {
    receive_board_message(message);
  } while (message->magic != type);

  return message->message_len;
}
