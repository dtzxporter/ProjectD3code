#pragma once

#include <cstdint>

namespace memprotect
{
	void Protectrange(void *Address, const size_t Length, unsigned long Oldprotection);
	unsigned long Unprotectrange(void *Address, const size_t Length);
}