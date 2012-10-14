#include "util.h"

int heapspray_num = 0;
DWORD heapspray_table1[1000];

void heapspray_apply()
{
    unsigned int i; 

    i = 0;
    if ( heapspray_num ){
        do{
            alloc_virtual_mem((void*)heapspray_table1[i++], 0x400);
        }
        while ( i < heapspray_num );
    }
}