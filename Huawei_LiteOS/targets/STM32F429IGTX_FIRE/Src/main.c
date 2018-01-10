/* Includes LiteOS------------------------------------------------------------------*/
#include "stdlib.h"
#include "string.h"
#include "los_base.h"
#include "los_config.h"
#include "los_typedef.h"
#include "los_hwi.h"
#include "los_task.ph"
#include "los_sem.h"
#include "los_event.h"
#include "los_memory.h"
#include "los_queue.ph"
#include "cmsis_os.h"
#include <stdio.h>

#include "stm32f4xx.h"
#include "stm32f4xx_conf.h"
#include "bsp_led.h" 
#include "bsp_debug_usart.h"
#include "dwt.h"
#include "bsp_key.h"
#include "LAN8742A.h"
#include "ethernetif.h"
#include "netconf.h"
#include "lwip/netif.h"
#include "lwip/sockets.h"
#include "lwip/tcpip.h"
#include "lwip/ip_addr.h"
#include "net.h"
#include "ssl.h"
/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
KEY Key1,Key2;
UINT32 g_TskHandle;
struct netif gnetif;
__IO uint32_t LocalTime = 0; /* this variable is used to create a time reference incremented by 10ms */
/* Private function prototypes -----------------------------------------------*/
static void TIM3_Config(uint16_t period,uint16_t prescaler);
/* Private functions ---------------------------------------------------------*/
void TIM3_IRQHandler(void);
extern void coap_main(coap_context_t  *ctx);
void hardware_init(void)
{
	LED_GPIO_Config();
	Key1_GPIO_Config();
	Key2_GPIO_Config();
	KeyCreate(&Key1,GetPinStateOfKey1);
	KeyCreate(&Key2,GetPinStateOfKey2);
	Debug_USART_Config();
	DelayInit(SystemCoreClock);
	LOS_HwiCreate(TIM3_IRQn, 0,0,TIM3_IRQHandler,NULL);
	TIM3_Config(999,899);
	printf("Sysclock is %d\r\n",SystemCoreClock);
}


static void TIM3_Config(uint16_t period,uint16_t prescaler)
{
	TIM_TimeBaseInitTypeDef TIM_TimeBaseInitStructure;
	NVIC_InitTypeDef NVIC_InitStructure;
	
	RCC_APB1PeriphClockCmd(RCC_APB1Periph_TIM3,ENABLE);  
	
	TIM_TimeBaseInitStructure.TIM_Prescaler=prescaler;  
	TIM_TimeBaseInitStructure.TIM_CounterMode=TIM_CounterMode_Up; 
	TIM_TimeBaseInitStructure.TIM_Period=period;   
	TIM_TimeBaseInitStructure.TIM_ClockDivision=TIM_CKD_DIV1; 
	
	TIM_TimeBaseInit(TIM3,&TIM_TimeBaseInitStructure);
	
	TIM_ITConfig(TIM3,TIM_IT_Update,ENABLE); 
	TIM_Cmd(TIM3,ENABLE); 
	
	NVIC_InitStructure.NVIC_IRQChannel=TIM3_IRQn; 
	NVIC_InitStructure.NVIC_IRQChannelPreemptionPriority=0x01; 
	NVIC_InitStructure.NVIC_IRQChannelSubPriority=0x03; 
	NVIC_InitStructure.NVIC_IRQChannelCmd=ENABLE;
	NVIC_Init(&NVIC_InitStructure);
}


void TIM3_IRQHandler(void)
{
	if(TIM_GetITStatus(TIM3,TIM_IT_Update)==SET) 
	{
		LocalTime+=10;
	}
	TIM_ClearITPendingBit(TIM3,TIM_IT_Update);  
}

VOID task1()
{
		UINT32 count = 0;

		ip_addr_t ipaddr;
		ip_addr_t netmask;
		ip_addr_t gw;

		struct sockaddr_in client_addr;  
		int sock_fd; 			   /* client socked */	
		int err;  

		char udp_msg[] = "this is a UDP test package";
		char udp_recv_msg[100];
		printf("LAN8720A Ethernet Demo\n");

		/* Configure ethernet (GPIOs, clocks, MAC, DMA) */
		ETH_BSP_Config();	
		printf("LAN8720A BSP INIT AND COMFIGURE SUCCESS\n");

		tcpip_init(NULL, NULL);
		IP_ADDR4(&ipaddr,189,239,200,108);
		IP_ADDR4(&netmask,255,255,0,0);
		IP_ADDR4(&gw,189,239,1,1);
		netif_add(&gnetif, &ipaddr, &netmask, &gw, NULL, 
		&ethernetif_init, &tcpip_input);
		netif_set_default(&gnetif);
  
    if (netif_is_link_up(&gnetif))
    {
        gnetif.flags |= NETIF_FLAG_LINK_UP;
        netif_set_up(&gnetif);
    }
    else
    {
        netif_set_down(&gnetif);
    }
		extern int test_dtls(void);
		test_dtls();
#if 0
	coap_address_t listenaddress;
	coap_address_init(&listenaddress);
	/* looks like a server address, but is used as end point for clients too */
	listenaddress.addr = *(IP_ANY_TYPE);
	listenaddress.port = 5684;
	coap_context_t * ctx = coap_new_context(&listenaddress);
	coap_main(ctx);
#endif

#if 0		 
    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);  
    if (sock_fd == -1) {  
        printf("failed to create sock_fd!\n");	
	      return;
    }  
	 	 
    memset(&client_addr, 0, sizeof(client_addr));  
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = inet_addr("192.168.0.102");  
    client_addr.sin_port = htons(60000);	
		 
	
    err = sendto(sock_fd, (char *)udp_msg, sizeof(udp_msg), 0,  
	    (struct sockaddr *)&client_addr, sizeof(client_addr));  
    printf("err is %d\n",err);
		
	while(1)
	{
		printf("This is task 1,count is %d \r\n",count++);
		memset(udp_recv_msg,0,100);
		err = recvfrom(sock_fd,udp_recv_msg,100,0,NULL,NULL);
		printf("len is %d,udp_recv_msg is %s\n",err,udp_recv_msg);
		err = sendto(sock_fd, (char *)udp_msg, sizeof(udp_msg), 0,  
	    (struct sockaddr *)&client_addr, sizeof(client_addr));
		LOS_TaskDelay(500);
	}
#endif
}


UINT32 creat_task1()
{
    UINT32 uwRet = LOS_OK;
    TSK_INIT_PARAM_S task_init_param;

    task_init_param.usTaskPrio = 0;
    task_init_param.pcName = "task1";
    task_init_param.pfnTaskEntry = (TSK_ENTRY_FUNC)task1;
    task_init_param.uwStackSize = 0x8000;

    uwRet = LOS_TaskCreate(&g_TskHandle, &task_init_param);
    if(LOS_OK != uwRet)
    {
        return uwRet;
    }
    return uwRet;
        
}

VOID task2()
{
	UINT32 count = 0;
	while(1)
	{
		printf("This is task 2,count is %d \r\n",count++);
		LOS_TaskDelay(1000);
	}
}


UINT32 creat_task2()
{
    UINT32 uwRet = LOS_OK;
    TSK_INIT_PARAM_S task_init_param;

    task_init_param.usTaskPrio = 1;
    task_init_param.pcName = "task2";
    task_init_param.pfnTaskEntry = (TSK_ENTRY_FUNC)task2;
    task_init_param.uwStackSize = 0x800;

    uwRet = LOS_TaskCreate(&g_TskHandle, &task_init_param);
    if(LOS_OK != uwRet)
    {
        return uwRet;
    }
    return uwRet;
        
}

int main(void)
{
    UINT32 uwRet = LOS_OK;
		LOS_KernelInit();//内核初始化	
    hardware_init();//硬件初始化
		uwRet = creat_task1();
    if(uwRet != LOS_OK)
    {
        return uwRet;
    }
    uwRet = creat_task2();
    if(uwRet != LOS_OK)
    {
        return uwRet;
    }
		
    LOS_Start();//启动LiteOS
}
