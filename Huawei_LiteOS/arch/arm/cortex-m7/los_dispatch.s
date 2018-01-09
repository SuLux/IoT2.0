        .global  LOS_StartToRun
        .global  osTaskSchedule
        .global  osPendSV

        .extern  g_pRunningTask
        .extern  g_pHighestTask
        .extern  g_pfnTskSwitchHook
        .extern  Syscall_Handler

	.syntax unified

.equ OS_NVIC_INT_CTRL,    0xE000ED04
.equ OS_NVIC_SYSPRI2,     0xE000ED20
.equ OS_NVIC_PENDSV_PRI,  0xF0F00000
.equ OS_NVIC_PENDSVSET,   0x10000000
.equ OS_TASK_STATUS_RUNNING,      0x0010
.equ OS_TSK_USERSPACE,    0x0002
.equ TCB_STACKF,          0x005C
.equ TCB_SWAP_FLAG,           0x0060
.equ CONTROL_PSP_USR_MODE,    0x0002
.equ CONTROL_PSP_KERNEL_MODE, 0x0003

    .text
    .thumb
    .type    osFirstTimeSwitch, %function
/*    .thumb_func
    .align 2
    .global    osResetVector
    .type    osResetVector, %function
*/
LOS_StartToRun:
    ldr    R4, =OS_NVIC_SYSPRI2
    ldr     R5, =OS_NVIC_PENDSV_PRI
    str     R5, [R4]

    LDR     R0, =g_bTaskScheduled
    MOV     R1, #1
    STR     R1, [R0]
    mov     R0, #2
    msr     CONTROL, R0


    LDR     R0, =g_stLosTask
    LDR     R2, [R0, #4]
    LDR     R0, =g_stLosTask
    STR     R2, [R0]

    LDR     R3, =g_stLosTask
    LDR     R0, [R3]
    LDRH    R7, [R0 , #4]
    MOV     R8,  #OS_TASK_STATUS_RUNNING
    ORR     R7,  R7,  R8
    STRH    R7,  [R0 , #4]

    LDR     R12, [R0]
    ADD     R12, R12, #100

    LDMFD   R12!, {R0-R7}
    ADD     R12, R12, #72
    MSR     PSP, R12
    /*VPUSH   S0;
    VPOP    S0;*/

    MOV     LR, R5
    MSR     xPSR_nzcvq, R7

    CPSIE   I
    BX      R6

    .text
    .thumb
    .type    LOS_IntLock, %function
LOS_IntLock:
    MRS     R0, PRIMASK
    CPSID   I
    BX      LR

    .text
    .thumb
    .type    LOS_IntUnLock, %function
LOS_IntUnLock:
    MRS     R0, PRIMASK
    CPSIE   I
    BX      LR

    .text
    .thumb
    .type    LOS_IntRestore, %function
LOS_IntRestore:
    MSR     PRIMASK, R0
    BX      LR

    .align
/*    .section .kernel,"x"  */

    .text
    .thumb
    .type    osTaskSchedule, %function
osTaskSchedule:
    LDR     R0, =OS_NVIC_INT_CTRL
    LDR     R1, =OS_NVIC_PENDSVSET
    STR     R1, [R0]
    BX      LR

    .text
    .thumb
    .type    osPendSV, %function
osPendSV:
    MRS     R12, PRIMASK
    CPSID   I

    LDR     R2, =g_pfnTskSwitchHook
    LDR     R2, [R2]
    CBZ     R2, TaskSwitch
    PUSH    {R12, LR}
    BLX     R2
    POP     {R12, LR}

    .text
    .thumb
    .type    TaskSwitch, %function
TaskSwitch:
    MRS     R0, PSP

#endif

    STMFD   R0!, {R4-R12}
    VSTMDB  R0!, {D8-D15}

    LDR     R5, =g_stLosTask
    LDR     R6, [R5]
    STR     R0, [R6]


    LDRH    R7, [R6 , #4]
    MOV     R8,#OS_TASK_STATUS_RUNNING
    BIC     R7, R7, R8
    STRH    R7, [R6 , #4]


    LDR     R0, =g_stLosTask
    LDR     R0, [R0, #4]
    STR     R0, [R5]


    LDRH    R7, [R0 , #4]
    MOV     R8,  #OS_TASK_STATUS_RUNNING
    ORR     R7, R7, R8
    STRH    R7,  [R0 , #4]

    LDR     R1,   [R0]
    VLDMIA  R1!, {D8-D15}
    LDMFD   R1!, {R4-R12}
    MSR     PSP,  R1

    MSR     PRIMASK, R12
    BX      LR

    NOP
    .align

