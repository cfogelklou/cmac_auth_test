#ifndef LOCALHANDY_H__
#define LOCALHANDY_H__

#include <string.h>
#include <stdint.h>
#define MIN(x,y) (((x) < (y)) ? (x) : (y))

static inline void mem_clean(volatile void *v, size_t len){
  if (len){
    memset((void *)v, 0, len);
    (void) *((volatile uint8_t *)v);
  }
}

#endif
