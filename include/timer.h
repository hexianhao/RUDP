#ifndef __TIMER_H
#define __TIMER_H

#include <stdint.h>

#include "queue.h"
#include "udp.h"

typedef struct time_wheel {
    int rotation;
    int time_slot;
    
};



#endif