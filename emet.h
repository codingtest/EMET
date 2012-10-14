#include <Windows.h>

int  bottomuprand_apply();

void  enableDEP();

void heapspray_apply();

int  nullpage_apply();


void  hook_eat(LPCWSTR lpModuleName);

PVOID set_ceh_handler();

int set_sehop_ceh_handler();

void apply_emet(HMODULE pHandle, int a2);