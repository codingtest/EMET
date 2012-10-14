#include <Windows.h>
#include "util.h"

static int hw_break_count = 0;
#define HW_BREAK_COUNT_MAX 4
static int hw_break_table[HW_BREAK_COUNT_MAX];
extern HANDLE  thread_lock;

void  hook_eat(LPCWSTR lpModuleName)
{
  HMODULE handle; // eax@2
  int v2; // edx@3
  int v3; // ecx@3

  if ( hw_break_count != 4 )
  {
    HMODULE handle = GetModuleHandleW(lpModuleName);
    if ( handle )
    {
        //what is this mean
      v2 = *(DWORD *)((char *)handle + *((DWORD *)handle + 15) + 120);
      v3 = hw_break_count++;
      hw_break_table[v3] = (int)((char *)handle + v2 + 28);
    }
  }
}

void ClearHardwareBPS(HANDLE hThread)
{
    CONTEXT lpcontext;
    memset(&lpcontext, 0, sizeof(CONTEXT));
    lpcontext.ContextFlags =  0x10010;
    if ( GetThreadContext(GetCurrentThread(), (LPCONTEXT)&lpcontext) )
    {
        if ( lpcontext.Dr0 )
            lpcontext.Dr7 &= 0xFFFFFFFE;
        if ( lpcontext.Dr1 )
            lpcontext.Dr7 &= 0xFFFFFFFB;
        if ( lpcontext.Dr2 )
            lpcontext.Dr7 &= 0xFFFFFFEF;
        if ( lpcontext.Dr3 )
            lpcontext.Dr7 &= 0xFFFFFFBF;
        lpcontext.ContextFlags = 0x10010;                       // set ContextFlags
        SetThreadContext(hThread, (const CONTEXT *)&lpcontext);
    }
}

void SetHardwareBPS(HANDLE hThread)
{
    CONTEXT lpcontext;
    memset(&lpcontext, 0, sizeof(CONTEXT));
    lpcontext.ContextFlags =  0x10010;
    if ( GetThreadContext(GetCurrentThread(), (LPCONTEXT)&lpcontext) )
    {
        if ( lpcontext.Dr0 )
            lpcontext.Dr7 |= 0x1;
        if ( lpcontext.Dr1 )
            lpcontext.Dr7 |= 0x4;
        if ( lpcontext.Dr2 )
            lpcontext.Dr7 |= 0x10;
        if ( lpcontext.Dr3 )
            lpcontext.Dr7 |= 0x40;
        lpcontext.ContextFlags = 0x10010;                       // set ContextFlags
        SetThreadContext(hThread, (const CONTEXT *)&lpcontext);
    }
}

int ceh_handler(PEXCEPTION_POINTERS ExceptionInfo)
{
    HMODULE phModule = NULL;
    bool result;
    if ( ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP )
    {
        ClearHardwareBPS(GetCurrentThread());
        PCONTEXT context = ExceptionInfo->ContextRecord;
        if ( context->Dr6 & 0x11 ){
            if ( !GetModuleHandleExW(6u, *(LPCWSTR *)(context->Eip), &phModule) )// check eip should in one of the module
                find_invalid_execute(context, 0xC0000409u);// terminate execution
            if ( !phModule )
                find_invalid_execute(context, 0xC0000409u);
        }
        CONTEXT lpcontext;
        memset(&lpcontext, 0, sizeof(CONTEXT));
        lpcontext.ContextFlags =  0x10010;
        GetThreadContext(GetCurrentThread(), (LPCONTEXT)&lpcontext);
        lpcontext.Dr6 = 0;
        lpcontext.ContextFlags =  0x10010;
        SetThreadContext(GetCurrentThread(), (const CONTEXT *)&lpcontext);
        SetHardwareBPS(GetCurrentThread());
        result = -1;
    } else {
        result = 0;
    }
    return result;
}

PVOID  set_ceh_handler()
{
  return AddVectoredExceptionHandler(0x1, (PVECTORED_EXCEPTION_HANDLER)ceh_handler);
}

BOOL __stdcall set_bp2(void *handle, int index)
{
    int bp_address; 
    bool result; 

    bp_address = hw_break_table[index];
    CONTEXT lpcontext;
    memset(&lpcontext, 0, sizeof(CONTEXT));
    lpcontext.ContextFlags =  0x10010;
    if ( GetThreadContext(handle, (LPCONTEXT)&lpcontext) )
    {
        unsigned int new_Dr7 = lpcontext.Dr7;
        if ( index )
        {
            switch ( index )
            {
            case 1:
                lpcontext.Dr1 = bp_address;
                new_Dr7 = lpcontext.Dr7 & 0xFFFFFFF7 | 0xF00004;
                break;
            case 2:
                lpcontext.Dr2 = bp_address;
                new_Dr7 = lpcontext.Dr7 & 0xFFFFFFDF | 0xF000010;
                break;
            case 3:
                lpcontext.Dr3 = bp_address;
                new_Dr7 = lpcontext.Dr7 & 0xFFFFFF7F | 0xF0000040;
                break;
            }
        }
        else
        {
            lpcontext.Dr0 = bp_address;
            new_Dr7 = lpcontext.Dr7 & 0xFFFFFFFD | 0xF0001;
        }
    lpcontext.Dr7 = new_Dr7 | 0x500;                       // set 4 bit length?
    lpcontext.ContextFlags =  0x10010;
    result = SetThreadContext(handle, (const CONTEXT *)&lpcontext);
    }
  return result;
}

void *set_bp(DWORD dwThreadId)
{
  unsigned int index; 
  void *result;
  void *threadhd; 
  bool suspended;

  index = 0;
  result = OpenThread(THREAD_SUSPEND_RESUME  | THREAD_GET_CONTEXT  | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, false, dwThreadId);
  threadhd = result;
  if ( result ){
    suspended = SuspendThread(result) != -1;
    if ( (unsigned int)hw_break_count > 0 ){
      do
        set_bp2(threadhd, index++);
      while ( index < hw_break_count );
    }
    if ( suspended )
      ResumeThread(threadhd);
    result = (void *)CloseHandle(threadhd);
  }
  return result;
}

void StartAddress()
{
    while ( 1 ){
        Sleep(0x64);
        WaitForSingleObject(thread_lock, 0xFFFFFFFF);
        for (int i = thread_count; i; --i )
        {
            if ( threadid_list[i] != GetCurrentThreadId() )
                set_bp(threadid_list[i]);
        }
        thread_count = 0;
        ReleaseMutex(thread_lock);
    }
}