/*******************************************************************************
 *
 * Copyright (c) 2013, 2014, 2015 Intel Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * The Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    David Navarro, Intel Corporation - initial API and implementation
 *******************************************************************************/

#include <liblwm2m.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
//#include <sys/time.h>
#include "lwip/sockets.h"
#include "internals.h"
#include "los_sys.h"

#ifndef LWM2M_MEMORY_TRACE


char * lwm2m_strdup(const char * str)
{
    int len = strlen(str) + 1;
    void *new = lwm2m_malloc(len);
    if (new == NULL)
        return NULL;
    return (char *)memcpy(new, str, len);

}

#endif

int lwm2m_strncmp(const char * s1,
                     const char * s2,
                     size_t n)
{
    return strncmp(s1, s2, n);
}

time_t lwm2m_gettime(void)
{
    return (u32_t)(LOS_TickCountGet() / LOSCFG_BASE_CORE_TICK_PER_SECOND);
}

void lwm2m_printf(const char * format, ...)
{
    va_list ap;

    va_start(ap, format);

    vfprintf(stderr, format, ap);

    va_end(ap);
}
