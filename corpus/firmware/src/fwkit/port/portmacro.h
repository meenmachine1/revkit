/* A portable FreeRTOS port for fwkit: everything in C over the board's
 * interrupt controller (board.c). The context switch itself is the
 * board's (board_switch_context). Used on every architecture without a
 * GCC port in the kernel; Cortex-M uses the kernel's own ARM_CM3 port. */
#ifndef PORTMACRO_H
#define PORTMACRO_H

#include <stddef.h>
#include <stdint.h>

#define portCHAR       char
#define portFLOAT      float
#define portDOUBLE     double
#define portLONG       long
#define portSHORT      short
#define portSTACK_TYPE uintptr_t
#define portBASE_TYPE  long

typedef portSTACK_TYPE StackType_t;
typedef long BaseType_t;
typedef unsigned long UBaseType_t;
typedef uint32_t TickType_t;
#define portMAX_DELAY ((TickType_t)0xffffffffUL)
#define portTICK_TYPE_IS_ATOMIC 0

#define portSTACK_GROWTH   (-1)
#define portTICK_PERIOD_MS ((TickType_t)1000 / configTICK_RATE_HZ)
#ifdef __AVR__
#define portBYTE_ALIGNMENT 1
#else
#define portBYTE_ALIGNMENT 8
#endif
#define portPOINTER_SIZE_TYPE uintptr_t

UBaseType_t board_irq_save(void);
void board_irq_restore(UBaseType_t state);
void vPortEnterCritical(void);
void vPortExitCritical(void);
void vPortYield(void);

#define portDISABLE_INTERRUPTS() ((void)board_irq_save())
#define portENABLE_INTERRUPTS()  board_irq_restore(1)
#define portENTER_CRITICAL()     vPortEnterCritical()
#define portEXIT_CRITICAL()      vPortExitCritical()
#define portSET_INTERRUPT_MASK_FROM_ISR()       board_irq_save()
#define portCLEAR_INTERRUPT_MASK_FROM_ISR(x)    board_irq_restore(x)
#define portYIELD()                             vPortYield()
#define portYIELD_FROM_ISR(x)  do { if (x) vPortYield(); } while (0)
#define portEND_SWITCHING_ISR(x) portYIELD_FROM_ISR(x)
#define portNOP()

#define portTASK_FUNCTION_PROTO(vFunction, pvParameters) void vFunction(void *pvParameters)
#define portTASK_FUNCTION(vFunction, pvParameters)       void vFunction(void *pvParameters)

#endif
