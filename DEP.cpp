#include <Windows.h>
//
//typedef bool (*FPTR_SetProcessDEPPolicy)(DWORD dwFlags);
//typedef bool (*FPTR_GetProcessDEPPolicy)(HANDLE hProcess,LPDWORD lpFlags,PBOOL lpPermanent);
// 
void  enableDEP()
{
  HMODULE result; 
  HMODULE v1; 
//  FPTR_SetProcessDEPPolicy func_SetProcessDEPPolicy;
  //FPTR_GetProcessDEPPolicy func_GetProcessDEPPolicy; 
  HANDLE v4; // eax@4
  DWORD lpFlags;
  BOOL lpPermanent;

  HMODULE handle = GetModuleHandleW(L"Kernel32.dll");
  v1 = result;
  if ( handle ){
   
        v4 = GetCurrentProcess();
        DWORD new_setting;
        bool ret = GetProcessDEPPolicy(GetCurrentProcess(), &lpFlags, &lpPermanent);
        if ( ret ){
          if ( lpFlags & 0x1 )                      // // dep is enabled
            new_setting = lpFlags;
          else
            new_setting = true;
          ret = SetProcessDEPPolicy(new_setting);// enableDEP
     
    }
  }
}
