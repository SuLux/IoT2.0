.syntax unified
.arch armv7-m
.thumb


.section .text,"ax",%progbits

.equ OS_NVIC_INT_CTRL,          0xE000ED04
.equ OS_NVIC_SYSPRI2,           0xE000ED20
.equ OS_NVIC_PENDSV_PRI,        0x00F00000
.equ OS_NVIC_PENDSVSET,         0x10000000
.equ OS_TASK_STATUS_RUNNING,    0x0010

    .type LOS_StartToRun, %function
    .global LOS_StartToRun
LOS_StartToRun:
    .fnstart
    .cantunwind
    LDR R4, =OS_NVIC_SYSPRI2
    LDR R5, =OS_NVIC_PENDSV_PRI
    STR R5, [R4]

    LDR R0, =g_bTaskScheduled
    MOV R1, #1
    STR R1, [R0]

    MOV R0, #2
    MSR CONTROL, R0


    LDR R0, =g_stLosTask
    LDR R2, [R0, #4]
    LDR R0, =g_stLosTask
    STR R2, [R0]

    LDR R3, =g_stLosTask
    LDR R0, [R3]
    LDRH R7, [R0 , #4]
    MOV R8, #OS_TASK_STATUS_RUNNING
    ORR R7, R7, R8
    STRH R7, [R0 , #4]

    LDR R12, [R0]
    ADD R12, R12, #36

    LDMFD R12!, {R0-R7}
    MSR PSP, R12

    MOV LR, R5

    CPSIE I
    BX R6
    .fnend

    .type LOS_GetxPSR, %function
    .global LOS_GetxPSR
LOS_GetxPSR:
    .fnstart
    .cantunwind
    MRS R0, xPSR
    BX LR
    .fnend

    .type LOS_IntLock, %function
    .global LOS_IntLock
LOS_IntLock:
    .fnstart
    .cantunwind
    MRS R0, PRIMASK
    CPSID I
    BX LR
    .fnend

    .type LOS_IntUnLock, %function
    .global LOS_IntUnLock
LOS_IntUnLock:
    .fnstart
    .cantunwind
    MRS R0, PRIMASK
    CPSIE I
    BX LR
    .fnend

    .type LOS_IntRestore, %function
    .global LOS_IntRestore
LOS_IntRestore:
    .fnstart
    .cantunwind
    MSR PRIMASK, R0
    BX LR
    .fnend

    .type osTaskSchedule, %function
    .global osTaskSchedule
osTaskSchedule:
    .fnstart
    .cantunwind
    LDR R0, =OS_NVIC_INT_CTRL
    LDR R1, =OS_NVIC_PENDSVSET
    STR R1, [R0]
    BX LR
    .fnend

    .type osPendSV, %function
    .global osPendSV
osPendSV:
    .fnstart
    .cantunwind
    MRS R12, PRIMASK
    CPSID I

TaskSwitch:
    MRS R0, PSP

    STMFD R0!, {R4-R12}

    LDR R5, =g_stLosTask
    LDR R6, [R5]
    STR R0, [R6]


    LDRH R7, [R6 , #4]
    MOV R8,#OS_TASK_STATUS_RUNNING
    BIC R7, R7, R8
    STRH R7, [R6 , #4]


    LDR R0, =g_stLosTask
    LDR R0, [R0, #4]
    STR R0, [R5]


    LDRH R7, [R0 , #4]
    MOV R8, #OS_TASK_STATUS_RUNNING
    ORR R7, R7, R8
    STRH R7, [R0 , #4]

    LDR R1, [R0]
    LDMFD R1!, {R4-R12}
    MSR PSP, R1

    MSR PRIMASK, R12
    BX LR
    .fnend
