#include <string.h>
#include "stm32f4xx.h"
#include "stm32f4xx_conf.h"
#include "los_memory.h"

int mbedtls_hardware_poll(void *data,
							unsigned char *output,size_t len, size_t *olen);
int mbedtls_hardware_poll(void *data,
							unsigned char *output,size_t len, size_t *olen)
{
	uint32_t random_number = 1000;
	RNG_DeInit();
	RNG_Cmd(ENABLE);
	if(RNG_GetFlagStatus(RNG_FLAG_DRDY) == SET)
	{
		random_number = RNG_GetRandomNumber();
	}
	((void) data);
	*olen = 0;
	if((len < sizeof(uint32_t)))
	{
		return 0;
	}
	memcpy(output,&random_number,sizeof(uint32_t));
	*olen = sizeof(uint32_t);
	return 0;							
}
