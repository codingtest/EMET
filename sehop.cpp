#include <Windows.h>
#include "util.h"
#include "TlHelp32.h"
#include "Winternl.h"

typedef struct EXCEPTION_REGISTRATION { 
 struct EXCEPTION_REGISTRATION* next; 
 PVOID handler; 
}EXCEPTION_REGISTRATION , *PEXCEPTION_REGISTRATION; 

typedef struct _CLIENT_ID {  
    HANDLE   UniqueProcess;  
    HANDLE   UniqueThread;  
} CLIENT_ID; 
typedef   CLIENT_ID   *PCLIENT_ID;  

typedef   struct   _THREAD_BASIC_INFORMATION   {   //   Information   Class   0  
    LONG        ExitStatus;  
    PVOID       TebBaseAddress;  
    CLIENT_ID   ClientId;  
    LONG        AffinityMask;  
    LONG        Priority;  
    LONG        BasePriority;  
}   THREAD_BASIC_INFORMATION,   *PTHREAD_BASIC_INFORMATION;

bool isSEHOP_enable()
{
    //emet will check the register
    return true;
}

static bool set_sehop_hanlder_flag = false;

PEXCEPTION_REGISTRATION end_exception_chain;

int  module_default_handle_flag()
{
  //BOOL threadinfoclass; // esi@1
 // HMODULE hd_ntdll; // eax@1
  //HANDLE handle; // eax@1
  bool suspended; // ebx@4
  HANDLE threadhd; // edi@5
  int v5; // esi@11
  //PVOID  threadinfo; // [sp+4h] [bp-48h]@6
  THREADENTRY32 te; // [sp+20h] [bp-2Ch]@2
  DWORD ExitCode; // [sp+3Ch] [bp-10h]@9

 


  THREAD_BASIC_INFORMATION threadinfo;
  THREADINFOCLASS threadinfoclass = THREADINFOCLASS(0);
  bool ret = false;
  HANDLE hObject = CreateToolhelp32Snapshot(4u, 0);         // TH32CS_SNAPTHREAD
  if ( !hObject )
    return ret;
  te.dwSize = 0x1c;
  bool value = Thread32First(hObject, &te);
  if ( !value ){
      CloseHandle(hObject);
       return ret;
  }
  ret = true;
  while ( 1 )
  {
    suspended = 0;
    if ( te.th32OwnerProcessID == GetCurrentProcessId() )
      break;
    if ( !Thread32Next(hObject, &te) ) {
          CloseHandle(hObject);
            return ret;
    }
  }
  threadhd = OpenThread(THREAD_QUERY_INFORMATION  | THREAD_SUSPEND_RESUME , false, te.th32ThreadID);
  ULONG ReturnLength;
  
    

  if ( threadhd != (HANDLE)threadinfoclass
      && m_NtQueryInformationThread(threadhd,threadinfoclass, &threadinfo,sizeof(THREAD_BASIC_INFORMATION),&ReturnLength) )
  {
    if ( te.th32ThreadID != GetCurrentThreadId() )
       suspended = SuspendThread(threadhd) != -1;
    if ( GetExitCodeThread(threadhd, &ExitCode) && ExitCode == (WAIT_TIMEOUT|0x1) )// still active
    {
      PEXCEPTION_REGISTRATION Exception_header = (PEXCEPTION_REGISTRATION)&(threadinfo.TebBaseAddress);           // threadinfo->TebBaseAddress, get current exceptoin_header
      if ( (DWORD)Exception_header == 0xFFFFFFFF )
      {
        threadinfo.TebBaseAddress = DecodePointer(end_exception_chain);
      }
      else
      {
        while ( (DWORD)Exception_header != 0xFFFFFFFF )           // find the last one
            Exception_header = Exception_header->next;
        Exception_header = (PEXCEPTION_REGISTRATION)DecodePointer(end_exception_chain);
      }
      if ( suspended )
        ResumeThread(threadhd);
      CloseHandle(threadhd);
     // threadinfoclass = 0;
    }
    else
    {
      CloseHandle(threadhd);
    }
    if ( !Thread32Next(hObject, &te) ) {
          CloseHandle(hObject);
            return ret;
    }
  }
//  FreeLibrary(m_ntdll);
  ret = threadinfoclass;                        // threadinfolength
  CloseHandle(hObject);
  return ret;
}


__declspec( naked ) int default_handler()
{
    __asm{
        xor eax, eax
        inc eax
        retn 10h
    }
}

bool get_default_handle_flag()
{
  DWORD v0; 
  LPVOID mem; 
  bool result = false; 
  int random_number;
  DWORD flOldProtect; 
//  DWORD random_value;

 // random_value = GetTickCount() ^ GetCurrentProcessId();
  mem = VirtualAlloc(0, 0x1000u, 0x1000u, 4u);  // MEM_COMMIT PAGE_READWRITE
  if ( mem || (result = malloc(0x1000u), result != NULL ) )
  {
      HMODULE m_ntdll = LoadLibrary(L"ntdll.dll");
   m_RtlRandom = (FPTR_RtlRandom)GetProcAddress(m_ntdll,"RtlRandom");
    ULONG seed =  GetTickCount() ^ GetCurrentProcessId();
    random_number = (unsigned __int8)m_RtlRandom(&seed);
    random_number = random_number & 0xFFF;
    FreeLibrary(m_ntdll);
    if ( (unsigned int)random_number > 8 )
        random_number -= 8;
    end_exception_chain = (PEXCEPTION_REGISTRATION)( (char *)mem + random_number );
    end_exception_chain->next = (PEXCEPTION_REGISTRATION)0xFFFFFFFF;
    end_exception_chain->handler = &default_handler;
    VirtualProtect(end_exception_chain, 1u, 2u, &flOldProtect);// PAGE_READONLY
    end_exception_chain = (PEXCEPTION_REGISTRATION)EncodePointer(end_exception_chain);
    VirtualProtect(&end_exception_chain, 1u, 2u, &flOldProtect);
    result = true;
  }
  return result;
}

bool sehop_checker(PEXCEPTION_POINTERS ExceptionInfo)
{
   void *next_record; 
  struct _MEMORY_BASIC_INFORMATION Buffer; 

  if ( __readfsdword(0x10) < MEM_FREE ) {
      //check it
    PEXCEPTION_REGISTRATION address = (PEXCEPTION_REGISTRATION)__readfsdword(0x0);
    while ( (DWORD)address->next != 0xFFFFFFFF
        && VirtualQuery((LPCVOID )address->next, &Buffer, 0x1C) && Buffer.State != MEM_FREE ) {
        if ( address == DecodePointer(end_exception_chain) )
            return 0;
      address = address->next;
    }
    find_invalid_execute(ExceptionInfo->ContextRecord, 0xC0000409u);
  }
  return 0;
}

int  set_sehop_ceh_handler()
{
  if ( isSEHOP_enable() )
  {
    if ( get_default_handle_flag() )            // change default exception handler flag to random value to avoid use faked chain
    {
      if ( module_default_handle_flag() )
      {
        bool ret = (int)AddVectoredExceptionHandler(0x1, (PVECTORED_EXCEPTION_HANDLER)sehop_checker);
        if ( ret )
          set_sehop_hanlder_flag = 1;
      }
    }
  }
  return set_sehop_hanlder_flag;
}


int  change_default_exception_flag(PEXCEPTION_REGISTRATION exception_header)
{
  int result;

  if ( set_sehop_hanlder_flag ){
        if ( exception_header == (void *)0xFFFFFFFF ){
            DecodePointer(end_exception_chain);
        }else{
            while ( (unsigned int)exception_header->next != (unsigned int)0xFFFFFFFF )
                exception_header = exception_header->next;// get next
            //check it 
            if ( exception_header != DecodePointer(end_exception_chain) )
                exception_header->handler = DecodePointer(end_exception_chain);
        }
        result = 1;
  } else{
    result = 0;
  }
  return result;
}