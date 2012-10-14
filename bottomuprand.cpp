#include <Windows.h>
#include "util.h"

int  bottomuprand_apply()
{
  int v2; 
  //DWORD random_value; 

//  random_value = GetTickCount() ^ GetCurrentProcessId();

  HMODULE m_ntdll = LoadLibrary(L"ntdll.dll");
   m_RtlRandom = (FPTR_RtlRandom)GetProcAddress(m_ntdll,"RtlRandom");
   ULONG seed =  GetTickCount() ^ GetCurrentProcessId();
  int result = (unsigned __int8)m_RtlRandom(&seed);
  FreeLibrary(m_ntdll);
  if ( result ){
    v2 = result;
    do{
      result = alloc_virtual_mem(0, 65536);
      --v2;
    }
    while ( v2 );
  }
  return result;
}