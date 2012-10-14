#include "util.h"

//allocate the memory in 0x00000000
int  nullpage_apply()
{
  return alloc_virtual_mem((void*)1, 1024);
}