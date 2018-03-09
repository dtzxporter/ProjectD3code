#include <Windows.h>

#include "memprotect.h"
#include "hooking.h"

// Convery hooks

// Restore the memory where the hook was placed
bool hooking::JmpHook::Removehook()
{
	auto Protection = memprotect::Unprotectrange(Savedlocation, 20);
	{
		std::memcpy(Savedlocation, Savedcode, 20);
	}
	memprotect::Protectrange(Savedlocation, 20, Protection);

	return true;
}

// Restore the memory where the hook was placed
bool hooking::Callhook::Removehook()
{
	auto Protection = memprotect::Unprotectrange(Savedlocation, 20);
	{
		std::memcpy(Savedlocation, Savedcode, 20);
	}
	memprotect::Protectrange(Savedlocation, 20, Protection);

	return true;
}


#if defined (_WIN64)

// 64bit jmp instruction hook
bool hooking::JmpHook::Installhook(void *Location, void *Target)
{
	Savedlocation = Location;
	Savedtarget = Target;

	// Unprotect and inject instructions
	auto Protection = memprotect::Unprotectrange(Savedlocation, 20);
	{
		std::memcpy(Savedcode, Savedlocation, 20);

		*(uint8_t *)(uint64_t(Savedlocation) + 0) = 0x48;
		*(uint8_t *)(uint64_t(Savedlocation) + 1) = 0xB8;
		*(uint64_t *)(uint64_t(Savedlocation) + 2) = uint64_t(Target);
		*(uint8_t *)(uint64_t(Savedlocation) + 10) = 0xFF;
		*(uint8_t *)(uint64_t(Savedlocation) + 11) = 0xE0;
	}
	// Clean up, restore protection
	memprotect::Protectrange(Savedlocation, 20, Protection);

	// Ensure the CPU doesn't cache the old instructions
	FlushInstructionCache(GetCurrentProcess(), Location, 20);

	// Success
	return true;
}

// 64bit call instruction hook
bool hooking::Callhook::Installhook(void *Location, void *Target)
{
	Savedlocation = Location;
	Savedtarget = Target;

	// Unprotect and inject instructions
	auto Protection = memprotect::Unprotectrange(Savedlocation, 20);
	{
		std::memcpy(Savedcode, Savedlocation, 20);

		*(uint8_t *)(uint64_t(Savedlocation) + 0) = 0x48;
		*(uint8_t *)(uint64_t(Savedlocation) + 1) = 0xB8;
		*(uint64_t *)(uint64_t(Savedlocation) + 2) = uint64_t(Target);
		*(uint8_t *)(uint64_t(Savedlocation) + 10) = 0xFF;
		*(uint8_t *)(uint64_t(Savedlocation) + 11) = 0xD0;
	}
	// Clean up, restore protection
	memprotect::Protectrange(Savedlocation, 20, Protection);

	// Ensure the CPU doesn't cache the old instructions
	FlushInstructionCache(GetCurrentProcess(), Location, 20);

	// Success
	return true;
}

#else

// 32bit jmp instruction hook
bool hooking::JmpHook::Installhook(void *Location, void *Target)
{
	Savedlocation = Location;
	Savedtarget = Target;

	auto Protection = memprotect::Unprotectrange(Savedlocation, 20);
	{
		std::memcpy(Savedcode, Savedlocation, 20);

		*(uint8_t *)(uint32_t(Savedlocation) + 0) = 0xE9;
		*(uint32_t *)(uint32_t(Savedlocation) + 1) = uint32_t(Target) - uint32_t(Location) - 5;
	}
	memprotect::Protectrange(Savedlocation, 20, Protection);

	// Ensure the CPU doesn't cache the old instructions
	FlushInstructionCache(GetCurrentProcess(), Location, 20);

	return true;
}

// 32bit call instruction hook
bool hooking::Callhook::Installhook(void *Location, void *Target)
{
	Savedlocation = Location;
	Savedtarget = Target;

	auto Protection = memprotect::Unprotectrange(Savedlocation, 20);
	{
		std::memcpy(Savedcode, Savedlocation, 20);

		*(uint8_t *)(uint32_t(Savedlocation) + 0) = 0xE8;
		*(uint32_t *)(uint32_t(Savedlocation) + 1) = uint32_t(Target) - uint32_t(Location) - 5;
	}
	memprotect::Protectrange(Savedlocation, 20, Protection);

	// Ensure the CPU doesn't cache the old instructions
	FlushInstructionCache(GetCurrentProcess(), Location, 20);

	return true;
}
#endif