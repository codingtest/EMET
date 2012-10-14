#include <Windows.h>
#include "TlHelp32.h"
#include "util.h"

extern HANDLE  thread_lock;

void  enable_aslr(HMODULE hd) {};

int  alloc_virtual_mem(void* address, int size)
{
    HMODULE m_ntdll = LoadLibrary(L"ntdll.dll");
    m_NtAllocateVirtualMemory = (FPTR_NtAllocateVirtualMemory)GetProcAddress(m_ntdll,"NtAllocateVirtualMemory");
    FreeLibrary(m_ntdll);
  return m_NtAllocateVirtualMemory(GetCurrentProcess(), &address, 0, (PULONG)&size,  MEM_COMMIT   , 1);
}

bool find_invalid_execute(PCONTEXT contextrecord, int errorcode)
{
    struct _EXCEPTION_RECORD exception_record;
    exception_record.ExceptionCode = errorcode;
    exception_record.ExceptionFlags = 0;
    exception_record.ExceptionRecord = NULL;
    //v2 = *(_DWORD *)(contextrecord + 184);

    struct _EXCEPTION_POINTERS ExceptionInfo;
    ExceptionInfo.ContextRecord = contextrecord;
    ExceptionInfo.ExceptionRecord = (PEXCEPTION_RECORD)&exception_record;

    UnhandledExceptionFilter(&ExceptionInfo);
    return TerminateProcess(GetCurrentProcess(), 0xC000040Au);
}



static BOOL  save_thread_id(int threadid)
{
  WaitForSingleObject(thread_lock, 0xFFFFFFFF);
  if ( (unsigned int)thread_count < 0x100 )
    threadid_list[thread_count++] = threadid;
  return ReleaseMutex(thread_lock);
}

void * save_current_threadid()
{
  THREADENTRY32 te; // [sp+4h] [bp-1Ch]@2

 HANDLE  hd = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if ( hd )
  {
    te.dwSize = 28;
    for (int  i = Thread32First(hd, &te); i; i = Thread32Next(hd, &te) )
    {
      if ( te.th32OwnerProcessID == GetCurrentProcessId() )
        save_thread_id(te.th32ThreadID);
    }
    hd = (void *)CloseHandle(hd);
  }
  return hd;
}

bool getModuleHandleEx(HMODULE phModule)
{
    return GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN, (LPCWSTR)&enable_aslr,&phModule);
}

bool  isValidAddress(PBYTE lpAddress, DWORD address)
{
    struct _MEMORY_BASIC_INFORMATION Buffer;

    //has __try/__except
    VirtualQuery(lpAddress, &Buffer, 0x1Cu);
    PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(Buffer.AllocationBase);
    // Get pointer to NT header
	PIMAGE_NT_HEADERS pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PCHAR>(dos_header) + dos_header->e_lfanew);
    IMAGE_OPTIONAL_HEADER32 option = (IMAGE_OPTIONAL_HEADER32)(pNtHeader->OptionalHeader);
    if ( dos_header->e_magic != IMAGE_DOS_SIGNATURE
        || pNtHeader->Signature != IMAGE_NT_SIGNATURE
        || address < option.SizeOfImage
        || address > option.SizeOfHeaders ) {
            return false;
    } else {
        return true;
    }
   
}


// Writes code at pbCode that jumps to pbJumpTo. Will attempt to do this
// in as few bytes as possible. Important on x64 where the long jump
// (0xff 0x25 ....) can take up 14 bytes.
char* getNextCommand(PBYTE lpAddress, DWORD a2)
{
    if ( !lpAddress )
        return NULL;
    if ( a2 )
        *(DWORD *)a2 = 0;
    if (lpAddress[0] == 0xff && lpAddress[1] == 0x25) {
        DWORD pbTarget = *(DWORD *)((char *)lpAddress + 2);
        if ( isValidAddress(lpAddress, *(DWORD *)((char *)lpAddress + 2)) )
                return *(char **)pbTarget;
    } 
    if (lpAddress[0] != 0xE8)
        return (char*)lpAddress;
    char *result = (char*)lpAddress + lpAddress[1] + 2;
    if (result[0] == 0xE9)
        result = (char *)lpAddress + lpAddress[1] + *(DWORD *)((char *)lpAddress + lpAddress[1] + 3) + 2;
    return result;
}

bool need_remove(DWORD address)
{
    PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(address);
    PIMAGE_NT_HEADERS pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PCHAR>(dos_header) + dos_header->e_lfanew);
    _IMAGE_OPTIONAL_HEADER optionHeader = pNtHeader->OptionalHeader;
    if ( optionHeader.Magic != 0x10B && optionHeader.Magic != 0x20B )
        return true;
    if ( optionHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE )
        return true;

    return false;
}

int unmap_module(HANDLE processhd, DWORD* address)
{
  NTSTATUS status = 0/*STATUS_SUCCESS*/; 
  struct _MEMORY_BASIC_INFORMATION Buffer; 

  //status = dword_1C408(a1, processhd, address, a4, a5, a6, a7, a8, a9, a10);
  if ( (int)status >= 0 ){
    memset(&Buffer.AllocationBase, 0, sizeof(struct _MEMORY_BASIC_INFORMATION));
    if ( VirtualQuery((LPCVOID)(*address), &Buffer, 0x1C) ){
        if ( Buffer.Type == MEM_IMAGE )  {
            if ( !need_remove((*address)) )    {     // if aslr is enabled , not unmap it
                 HMODULE m_ntdll = LoadLibrary(L"ntdll.dll");
                m_NtUnmapViewOfSection = (FPTR_NtUnmapViewOfSection)GetProcAddress(m_ntdll,"NtUnmapViewOfSection");
                

                status = m_NtUnmapViewOfSection(processhd, (PVOID)(*address));
                FreeLibrary(m_ntdll);
                if ( (int)status >= 0 ){
                    alloc_virtual_mem((void*)*address, 0x400);// set the orignal memory as mem_reserverd
                    *address = 0;
                    //status = dword_1C408(a1, processhd, address, a4, a5, a6, a7, a8, a9, a10);
                }
            }
        }
    }
  }
  return status;
}