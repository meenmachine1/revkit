/* fwkit's portable FreeRTOS port (see portmacro.h). */
#include "FreeRTOS.h"
#include "task.h"

#include "board.h"

static volatile UBaseType_t critical_nesting = 0xaaaa;
static volatile UBaseType_t saved_state;

/* The initial frame: what board_switch_context pops for a new task. */
StackType_t *pxPortInitialiseStack(StackType_t *pxTopOfStack, TaskFunction_t pxCode, void *pvParameters) {
  int i;
  *pxTopOfStack-- = (StackType_t)(uintptr_t)0x11111111UL;  /* a guard word */
  *pxTopOfStack-- = (StackType_t)(uintptr_t)pxCode;
  *pxTopOfStack-- = (StackType_t)(uintptr_t)pvParameters;
  *pxTopOfStack-- = (StackType_t)(uintptr_t)vTaskDelete;  /* where a task that returns goes */
  for (i = 0; i < BOARD_FRAME_WORDS; i++) *pxTopOfStack-- = (StackType_t)i;
  *pxTopOfStack = 0;  /* critical nesting */
  return pxTopOfStack;
}

void vPortEnterCritical(void) {
  UBaseType_t state = board_irq_save();
  if (critical_nesting == 0) saved_state = state;
  critical_nesting++;
}

void vPortExitCritical(void) {
  configASSERT(critical_nesting);
  critical_nesting--;
  if (critical_nesting == 0) board_irq_restore(saved_state);
}

void vPortYield(void) {
  UBaseType_t state = board_irq_save();
  vTaskSwitchContext();
  board_switch_context();
  board_irq_restore(state);
}

/* The tick interrupt (board_timer_isr calls it). */
void vPortTickISR(void) {
  UBaseType_t state = board_irq_save();
  if (xTaskIncrementTick() != pdFALSE) {
    vTaskSwitchContext();
    board_switch_context();
  }
  board_irq_restore(state);
}

BaseType_t xPortStartScheduler(void) {
  critical_nesting = 0;
  board_timer_start(configCPU_CLOCK_HZ / configTICK_RATE_HZ, vPortTickISR);
  board_start_first_task();
  return pdFALSE;  /* not reached */
}

void vPortEndScheduler(void) {
  board_timer_stop();
  configASSERT(critical_nesting == 1000);
}
