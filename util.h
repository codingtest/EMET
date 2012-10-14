#include <Windows.h>
#include <winternl.h>

ULONG RtlRandom(
  __inout  PULONG Seed
);

int  alloc_virtual_mem(void* address, int flags);

bool find_invalid_execute(PCONTEXT contextrecord, int errorcode);

static int thread_count = 0;
static DWORD threadid_list[1000];

void * save_current_threadid();
void  enable_aslr(HMODULE hd);
bool getModuleHandleEx(HMODULE phModule);

typedef NTSYSAPI NTSTATUS  (*FPTR_NtAllocateVirtualMemory)(
  IN HANDLE               ProcessHandle,
  IN OUT PVOID            *BaseAddress,
  IN ULONG                ZeroBits,
  IN OUT PULONG           RegionSize,
  IN ULONG                AllocationType,
  IN ULONG                Protect );

typedef NTSYSAPI NTSTATUS  (*FPTR_NtQueryInformationThread)(
         HANDLE ThreadHandle,
         THREADINFOCLASS ThreadInformationClass,
      PVOID ThreadInformation,
         ULONG ThreadInformationLength,
    PULONG ReturnLength
);

 typedef ULONG (*FPTR_RtlRandom)(ULONG *);
 typedef NTSTATUS (*FPTR_NtUnmapViewOfSection)(void *,void *);

 static FPTR_NtUnmapViewOfSection m_NtUnmapViewOfSection;
 static FPTR_RtlRandom m_RtlRandom;
static FPTR_NtAllocateVirtualMemory m_NtAllocateVirtualMemory;
static FPTR_NtQueryInformationThread m_NtQueryInformationThread;

NTSYSAPI 
NTSTATUS
NTAPI
NtUnmapViewOfSection(
  IN HANDLE               ProcessHandle,
  IN PVOID                BaseAddress );
