#include <Windows.h>
#include "util.h"

bool setting_aslr = true;
OSVERSIONINFOW VersionInformation;
#define WINDOWS_VISTA 6

typedef struct _thread_info
{
  struct _thread_info *next;
  void *handler;
}thread_info;
thread_info* module_header = NULL;

static int LastError;

int __stdcall init_thread_info(HANDLE hThread)
{
  int ret; // eax@1
  thread_info *current_thread; // esi@4
  DWORD v3; // edi@5

  ret = LastError;
  if ( !LastError )
  {
    if ( hThread == GetCurrentThread() )
      return 0;
    current_thread = new thread_info();
    if ( !current_thread )                      // new failed
    {
      dword_1C898 = 0;
      LastError = ERROR_NOT_ENOUGH_MEMORY;  //8
      return LastError;
    }
    if ( SuspendThread(hThread) == -1 )
    {
      delete current_thread;
      dword_1C898 = 0;
      LastError = GetLastError();
      return LastError;
    }
    current_thread->next = module_header;// current_module->next = module_header
    current_thread->handler = hThread;          // current_module->handle = hThread
    module_header = current_thread;
    ret = 0;
  }
  return ret;
}

typedef struct _aslr_struct2{
}aslr_struct2;

typedef struct _aslr_struct
{
  struct _aslr_struct *next;
  void *param1;
  void *param2;
  void *new_add;
  aslr_struct2 *aslr_struct2;  //define later
  int old_VP_flag;
}aslr_struct;
aslr_struct* struct_header;

volatile LONG CurrentThreadID;
LPVOID lpAddress;

void* dword_1C88C;
int dword_1C898;

unsigned int  enable_execute()
{
    unsigned int result;
    DWORD flOldProtect;
    if ( CurrentThreadID || InterlockedCompareExchange(&CurrentThreadID, GetCurrentThreadId(), 0) ){
        result = ERROR_INVALID_OPERATION;//0x10DDu;
    }else {
        LPVOID address = lpAddress;
        dword_1C88C = 0;
        struct_header = NULL;
        module_header = NULL;
        LastError = 0;
        dword_1C898 = 0;
        while(address){
            VirtualProtect(address, 0x10000u, PAGE_EXECUTE_READWRITE, &flOldProtect);
            address = (LPVOID)*((DWORD *)address + 1);
        }
    }
    return result;
}

int prepare_new_data2(void* a1, LPCVOID lpAddress, void* addr1, void* addr2, void* addr3)
{
    if ( addr1 )
        *addr1 = 0;
    if (addr2)
        *addr2 = 0;
    if ( addr3)
        *addr3 = 0;
    if ( CurrentThreadID != GetCurrentThreadId() )
        return ERROR_INVALID_OPERATION;//0x10DDu;

}

int  prepare_new_data(void *a1, LPCVOID lpAddress)
{
  return prepare_new_data2(a1, lpAddress, NULL, NULL, NULL);
}

void  enable_aslr(HMODULE hd){

    memset( &VersionInformation, 0, sizeof(VersionInformation) );
    VersionInformation.dwOSVersionInfoSize = 284;
    GetVersionExW((LPOSVERSIONINFOW)&VersionInformation);

    if ( setting_aslr ){
        getModuleHandleEx(hd);
        if ( VersionInformation.dwMajorVersion >= WINDOWS_VISTA ){
            enable_execute();
            init_thread_info(GetCurrentThread());
            prepare_new_data((int)&dword_1C408, lpAddress);
            apply_aslr(NULL);
        }
    }
}


extern HANDLE refresh_code_inmemory();

int  refresh_and_resume(DWORD flOldProtect)
{
    int result = 0;
    if ( CurrentThreadID == GetCurrentThreadId() ){
        //release all struct_header
        if ( struct_header ) {
             aslr_struct* header = (aslr_struct *)struct_header;
             do {
                 VirtualProtect(header->new_add, *((BYTE *)header->aslr_struct2 + 30), header->old_VP_flag, &flOldProtect);
                 if ( header->param1 ){
                     if ( header->aslr_struct2 ){
                         release_struct2(header->aslr_struct2);
                         header->aslr_struct2 = NULL;
                     }
                 }
                 aslr_struct *temp = header->next;
                 delete header;
                 header = temp;
             }while(header);
        }
        struct_header = 0;
        refresh_code_inmemory();

       
        if ( module_header ){
            thread_info* header = (thread_info *)module_header;
            do {
                ResumeThread(header->handler);
                thread_info* temp = header->next;
                delete header;
                header = temp;
            }while(header);
        }
        module_header =  NULL;
        CurrentThreadID = NULL;
        result = 0;
    } else {
        result = ERROR_INVALID_OPERATION;//0x10DD;
    }
    return result;
}

int apply_aslr(void* a1)
{
    DWORD flOldProtect;

    if ( a1 )
        *(DWORD*)a1 = dword_1C898;
    
    if ( CurrentThreadID != GetCurrentThreadId() )
        return 0x10DD;
    if ( !LastError ) {
        for (aslr_struct* i = (aslr_struct *)struct_header; i; i = i->next ){
            aslr_struct2* struct2 = i->aslr_struct2;
            if ( i->param1 ){
                memcpy(i->new_add, (char *)struct2 + 32, *((BYTE *)struct2 + 54));

            }else {
                //TODO : not implement
            }
        }//end of for
        if ( !module_header ){
Cleanup:
            aslr_struct* header = struct_header;
            if ( struct_header != NULL ){
                do{
                    VirtualProtect(header->new_add, *((BYTE *)header->aslr_struct2 + 30), header->old_VP_flag, &flOldProtect);
                    FlushInstructionCache(GetCurrentProcess(), header->new_add, *((BYTE *)header->aslr_struct2 + 30));
                    if ( header->param1 != NULL ){
                        if ( header->aslr_struct2 ){
                            release_struct2(header->aslr_struct2);
                            header->aslr_struct2 = NULL;
                        }
                    }
                    aslr_struct* temp = header->next;
                    delete header;
                    header = temp;
                }while( header );
            }

            struct_header  = NULL;
            refresh_code_inmemory();
            if ( module_header != NULL ){
                thread_info* header = (thread_info *)module_header;
                do {
                    ResumeThread(header->handler);
                    thread_info* temp = header->next;
                    delete header;
                    header = temp;
                }while(header);
            }
            module_header = NULL;
            CurrentThreadID = NULL;
            return LastError;
        }

        
        thread_info* header = (thread_info *)module_header;
        CONTEXT context ;
        while(1){
            HANDLE handler = (HANDLE)header->handler;
            context.ContextFlags = 0x10001;
            if ( GetThreadContext(handler, &context) )
                break;
            header = header->next;
            if ( !header )
                goto Cleanup;
        } //end of while
        for ( aslr_struct* j = (aslr_struct*)struct_header; ; j = j->next ) //adjust eip
        {
            if ( !j ) {
                header = header->next;
                if ( !header )
                    goto Cleanup;
            }
            if ( j->param1 ){
                int addr = (int)j->new_add;
                if ( context.Eip >= (unsigned int)addr && context.Eip < j->aslr_struct2->module_size ){
                    context.Eip -= (DWORD)addr;
                    context.Eip += (DWORD)(j->new_add);
                    SetThreadContext((HANDLE)header->handler, &context);
                    continue;
                } else {
                    int addr = (int)j->new_add;
                    if ( context.Eip >= (unsigned int)addr 
                        && context.Eip < (unsigned int)((char *)addr + *((BYTE *)j->aslr_struct2 + 30)) )
                    {
                        context.Eip -= (DWORD)addr;  //old_base_addr
                        context.Eip += (DWORD)(j->aslr_struct2);
                        SetThreadContext((HANDLE)header->handler, &context);
                        continue;
                    }
                }
            }
        }
    }
}

