#include <Windows.h>
#include "memprotect.h"

void memprotect::Protectrange(void *Address, const size_t Length, unsigned long Oldprotection)
{
	unsigned long Temp;

	// Set protection
	VirtualProtect(Address, Length, Oldprotection, &Temp);
}

unsigned long memprotect::Unprotectrange(void *Address, const size_t Length)
{
	unsigned long Oldprotection;

	// Allow read and write permission
	VirtualProtect(Address, Length, PAGE_EXECUTE_READWRITE, &Oldprotection);

	return Oldprotection;
}