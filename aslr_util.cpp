#include <Windows.h>

DWORD g_new_addr;
extern LPVOID lpAddress;

DWORD alloc_new_addr(DWORD old_base_addr)
{
    DWORD lowest,highest;
    if ( old_base_addr <= 0x7FF80000 )
        lowest = 0x10000;
    else
        lowest = old_base_addr - 0x7FF80000;
    if ( old_base_addr >= 0x80000000 )
        highest = 0xFFF80000;
    else
        highest = old_base_addr + 0x7FF80000;

    LPVOID new_addr;
    new_addr = (LPVOID)g_new_addr;
    if ( g_new_addr ){
        DWORD v2 = *((DWORD *)new_addr + 2);
        if ( v2 && v2 >= lowest && v2 <= highest ) {
        }
    }

    DWORD new_base_addr;
    struct _MEMORY_BASIC_INFORMATION basic_info_buffer;
    if ( new_base_addr <= lowest ){
LABEL_39:
        while ( new_base_addr < highest )
        {
            if ( new_base_addr - 0x70000000u <= 0x10000000 )
                new_base_addr = 0x80010000u;
            memset(&basic_info_buffer, 0, 7);
            if ( !VirtualQuery((LPCVOID)new_base_addr, (PMEMORY_BASIC_INFORMATION)&basic_info_buffer, sizeof(MEMORY_BASIC_INFORMATION )) )
                break;
            if ( basic_info_buffer.State == 0x10000 && basic_info_buffer.RegionSize >= 0x10000 ){
                if ( new_base_addr & 0xFFFF ){
                    basic_info_buffer.RegionSize -= 0x10000 - (new_base_addr & 0xFFFF);
                    basic_info_buffer.BaseAddress += 0x10000 - (new_base_addr & 0xFFFF);// base_info_buffer.BaseAddress
                    new_base_addr = (DWORD)basic_info_buffer.BaseAddress;
                }
                new_addr = VirtualAlloc((LPVOID)new_base_addr, 0x10000u, 0x3000u, PAGE_EXECUTE_READWRITE);
                g_new_addr = (DWORD)new_addr;
                if ( new_addr )
                    goto LABEL_42;
            }
            new_base_addr = (DWORD)basic_info_buffer.BaseAddress + basic_info_buffer.RegionSize;
        }
        return 0;
    }

    struct _MEMORY_BASIC_INFORMATION Buffer;
    while ( 1 ){
        if ( new_base_addr - 0x70000000u <= 0x10000000 )
            new_base_addr = 0x6FFF0000u;
        memset(&Buffer, 0, sizeof(Buffer));
        if ( !VirtualQuery((LPCVOID)new_base_addr, &Buffer, 0x1Cu) )
            goto LABEL_29;
        if ( Buffer.State == 0x10000 && Buffer.RegionSize >= 0x10000 )
            break;
        new_base_addr = (int)((char *)Buffer.AllocationBase - 0x10000);
        if ( (char *)Buffer.AllocationBase - 0x10000 <= (PVOID)lowest )
            goto LABEL_29;
    }
    new_addr = VirtualAlloc((LPVOID)new_base_addr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    g_new_addr = (int)new_addr;
    if ( !new_addr ){
        new_base_addr = old_base_addra;

    }


}

HANDLE refresh_code_inmemory()
{
    DWORD flOldProtect; 

    HANDLE processhd = GetCurrentProcess();
    DWORD baseAddress = (DWORD)lpAddress;
    for ( HANDLE hProcess = processhd; baseAddress; baseAddress = *(DWORD *)(baseAddress + 4) )
    {
        VirtualProtect((LPVOID)baseAddress, 0x10000, PAGE_EXECUTE_READ, &flOldProtect);
        processhd = (void *)FlushInstructionCache(hProcess, (LPCVOID)baseAddress, 0x10000);// let cpu execute the new code
    }
    return processhd;
}


bool  isJmp(PBYTE lpAddress)
{
    char ch = lpAddress[0];
    return  ch == 0xEB
                    || ch == 0xE9
                    || ch == 0xE0
                    || ch == 0xC2
                    || ch == 0xC3
                    || ch == 0xCC
                    || ( ch == 0xFF && lpAddress[1] == 0x25 )
                    || ( ( ch == 0x26 || ch == 0x2E || ch == 0x36 || ch == 0xE3 || ch == 0x64 || ch == 0x65)
                            && lpAddress[1]== 0xFF
                            && lpAddress[2] == 0x25 );
}

void* move_to_end(void* start, void* end)
{
    if ( (DWORD)start < (DWORD)end ){
        memset(start,0xCC,(DWORD)end - (DWORD)start);
        return end;
    }
    return start;

}