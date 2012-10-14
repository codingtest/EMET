#include "emet.h"
#include "util.h"
#include "windows.h"


int main()
{

     HMODULE m_ntdll = LoadLibrary(L"ntdll.dll");
    m_NtQueryInformationThread = (FPTR_NtQueryInformationThread)GetProcAddress(m_ntdll,"NtQueryInformationThread");

    try {

       apply_emet(GetModuleHandle(NULL), false);
    }catch(...){
    }
  return 0;  
}