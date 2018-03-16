/*
	Initial author: DTZxPorter
	Started: 03-12-2018
	License: MIT
	Notes:
		Provides methods for hooking code in c++
*/

#ifndef PHOOK_AHF_1337
#define PHOOK_AHF_1337

// Platform includes
#include <Windows.h>
#include <memory>
#include <cstdint>
#include <string>

//
// Begin macro definitions
//

// Attempt to patch bytes in the given memory range
#define PatchMemory(Source, Data, Size) MemPatch().Patch((uintptr_t)Source, (const uint8_t*)Data, (uintptr_t)Size);
// Attempt to find the pattern at the given memory range
#define FindPattern(Pattern, Start, Size) PatternScan(Pattern).Scan((uintptr_t)Start, (uintptr_t)Size);

//
// Begin hooking utilities
//

class PatternScan
{
private:
	std::string PatternData;
	std::string PatternMask;

public:
	PatternScan(LPCSTR Pattern)
	{
		// Buffers for temporary processing flags
		uint8_t TempDigit = 0;
		bool TempFlag = false;
		bool LastWasUnknown = false;

		// Iterate over all bytes
		for (size_t i = 0; i < strlen(Pattern); i++)
		{
			auto& ch = Pattern[i];

			// If it's a space, just skip it
			if (ch == ' ')
			{
				// Reset
				LastWasUnknown = false;
				// Skip
				continue;
			}
			else if (ch == '?')
			{
				// This is an unknown instance
				if (LastWasUnknown)
				{
					// This is second one, just disable
					LastWasUnknown = false;
				}
				else
				{
					// Append mask
					PatternData += '\x00';
					PatternMask += '?';
					// Set it
					LastWasUnknown = true;
				}
			}
			else if ((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f'))
			{
				// This is a hex value
				char StrBuffer[] = { ch, 0 };
				// Convert to digit
				int thisDigit = strtol(StrBuffer, nullptr, 16);

				// Check if we need the second digit
				if (!TempFlag)
				{
					// We do
					TempDigit = (thisDigit << 4);
					TempFlag = true;
				}
				else
				{
					// This is the second digit, process
					TempDigit |= thisDigit;
					TempFlag = false;

					// Append data to mask and data string
					PatternData += TempDigit;
					PatternMask += 'x';
				}

				// Reset
				LastWasUnknown = false;
			}
		}
	}

	~PatternScan() { }

	// Scan the given memory range for a pattern
	intptr_t Scan(uintptr_t Source, uintptr_t SourceSize)
	{
		// Scan a block of memory for the given pattern, check for SSE4.2
		bool UseSSE = false;
		
		// Only use SSE on patterns 16 bytes or less
		if (this->PatternMask.size() <= 16)
		{
			// The CPU info buffer
			int cpuid[4]; __cpuid(cpuid, 0);

			// Check for support
			if (cpuid[0] >= 1)
			{
				__cpuidex(cpuid, 1, 0);
				// Whether or not we have support for it
				UseSSE = ((cpuid[2] & (1 << 20)) > 0);
			}
		}

		// If we can't use SSE just check each byte
		if (!UseSSE)
		{
			// Convert
			const char* PatternData = this->PatternData.c_str();
			const char* MaskData = this->PatternMask.c_str();

			// Data to search
			char* DataPtr = (char*)Source;

			// Check each
			for (uint64_t i = 0; i < SourceSize; i++)
			{
				// If we found it
				bool IsMatch = true;
				// Check for a match, if success, return it
				for (size_t c = 0; c < this->PatternData.size(); c++)
				{
					// Check
					if (this->PatternMask[c] == '?')
					{
						// Skip
						continue;
					}

					// Check the data
					if (PatternData[c] != DataPtr[i + c])
					{
						// Not match
						IsMatch = false;
						// Stop
						break;
					}
				}
				// Check
				if (IsMatch)
				{
					// Return result
					return (intptr_t)(i);
				}
			}
		}
		else
		{
			// We can use SSE to speed this up
			__declspec(align(16)) char DesiredMask[16] = { 0 };

			// Build the mask
			for (size_t i = 0; i < this->PatternMask.size(); i++)
			{
				DesiredMask[i / 8] |= ((this->PatternMask[i] == '?') ? 0 : 1) << (i % 8);
			}

			// Load the mask and the data
			__m128i Mask = _mm_load_si128((const __m128i*)DesiredMask);
			__m128i Comparand = _mm_loadu_si128((const __m128i*)this->PatternData.c_str());

			// Loop and compare data in up to 16 byte chunks (SSE4.2)
			for (uint64_t i = Source; i <= (Source + SourceSize); i++)
			{
				// Compare
				__m128i Value = _mm_loadu_si128((const __m128i*)i);
				__m128i Result = _mm_cmpestrm(Value, 16, Comparand, (int)this->PatternData.size(), _SIDD_CMP_EQUAL_EACH);

				// See if we can match with the mask
				__m128i Matches = _mm_and_si128(Mask, Result);
				__m128i Equivalence = _mm_xor_si128(Mask, Matches);

				// Test the result
				if (_mm_test_all_zeros(Equivalence, Equivalence))
				{
					// We got a result here return it
					return (intptr_t)(i - Source);
				}
			}
		}

		// Failed to locate pattern
		return -1;
	}
};

// A class that provides information about the main module
class MainModule
{
private:
	uintptr_t BaseAddress;
	uintptr_t EndAddress;
	std::string ModulePath;

public:
	MainModule()
	{
		this->BaseAddress = NULL;
		this->EndAddress = NULL;

		// Load module information
		auto Mod = (HMODULE)GetModuleHandle(NULL);

		// Load PE information
		auto DOSHeader = (const IMAGE_DOS_HEADER*)(Mod);
		auto NTHeader = (const IMAGE_NT_HEADERS*)((const uint8_t*)(DOSHeader) + DOSHeader->e_lfanew);

		// Calculate addresses
		this->BaseAddress = (uintptr_t)Mod;
		this->EndAddress = (uintptr_t)(this->BaseAddress + NTHeader->OptionalHeader.SizeOfCode);

		// Get module path
		char ModPath[2048] = { 0 };
		GetModuleFileNameA(NULL, ModPath, 2048);

		// Set it
		this->ModulePath = std::string(ModPath);
	}

	~MainModule() { }

	// Gets the module base address
	uintptr_t GetBaseAddress()
	{
		return this->BaseAddress;
	}

	// Gets the size of code reported by the PE header
	uintptr_t GetCodeSize()
	{
		return (this->EndAddress - this->BaseAddress);
	}

	size_t Begin() const
	{
		return (size_t)this->BaseAddress;
	}

	size_t End() const
	{
		return (size_t)this->EndAddress;
	}

	std::string GetModulePath()
	{
		return this->ModulePath;
	}
};

// A class that implements memory patching
class MemPatch
{
private:
	std::unique_ptr<uint8_t[]> Source;
	uintptr_t SourceSize;
	uintptr_t SourceLocation;

public:
	MemPatch() { }
	~MemPatch() { }

	// Install the patch with the given information
	bool Patch(uintptr_t Source, const uint8_t* Data, uintptr_t Size)
	{
		// Attempt to strip protection
		DWORD OldProtect = 0, NewProtect = 0;
		if (!VirtualProtect((LPVOID)Source, Size, PAGE_EXECUTE_READWRITE, &OldProtect))
			return false;

		// Apply the hook
		this->Source = std::make_unique<uint8_t[]>(Size);
		std::memcpy(this->Source.get(), (const void*)Source, Size);
		this->SourceLocation = Source;
		this->SourceSize = Size;

		for (uintptr_t i = 0; i < Size; i++)
			*(volatile uint8_t*)(Source + i) = *Data++;

		// Restore protection & flush cache
		VirtualProtect((LPVOID)Source, Size, OldProtect, &NewProtect);
		FlushInstructionCache(GetCurrentProcess(), (LPCVOID)Source, Size);

		// Success
		return true;
	}

	// Removes the installed patch, if any
	void Unpatch()
	{
		// Ensure installed
		if (this->Source != nullptr)
		{
			// Attempt to strip protection
			DWORD OldProtect = 0, NewProtect = 0;
			if (!VirtualProtect((LPVOID)this->SourceLocation, this->SourceSize, PAGE_EXECUTE_READWRITE, &OldProtect))
				return;

			// Revert the hook
			auto Data = (uint8_t*)this->Source.get();
			for (uintptr_t i = 0; i < this->SourceSize; i++)
				*(volatile uint8_t*)(this->SourceLocation + i) = *Data++;

			this->Source.reset();

			// Restore protection & flush cache
			VirtualProtect((LPVOID)this->SourceLocation, this->SourceSize, OldProtect, &NewProtect);
			FlushInstructionCache(GetCurrentProcess(), (LPCVOID)this->SourceLocation, this->SourceSize);
		}
	}
};

//
// Begin hook definitions
//

// A class that implements a jmp instruction hook
class JumpHook
{
private:
	std::unique_ptr<uint8_t[]> Source;
	uintptr_t SourceLocation;

public:
	JumpHook() { }
	~JumpHook() { }

	// Install the JumpHook with the provided information
	bool Hook(uintptr_t Source, uintptr_t Target)
	{
		if (sizeof(uintptr_t) == 4)	// 32bit
		{
			// Attempt to strip protection
			DWORD OldProtect = 0, NewProtect = 0;
			if (!VirtualProtect((LPVOID)Source, 5, PAGE_EXECUTE_READWRITE, &OldProtect))
				return false;

			// Apply the hook
			this->Source = std::make_unique<uint8_t[]>(5);
			std::memcpy(this->Source.get(), (const void*)Source, 5);
			this->SourceLocation = Source;

			*(volatile uint8_t*)(Source) = 0xE9;
			*(volatile uint32_t*)(Source + 1) = (uint32_t(Target) - uint32_t(Source) - 5);

			// Restore protection & flush cache
			VirtualProtect((LPVOID)Source, 5, OldProtect, &NewProtect);
			FlushInstructionCache(GetCurrentProcess(), (LPCVOID)Source, 5);

			// Success
			return true;
		}
		else if (sizeof(uintptr_t) == 8)	// 64bit 12
		{
			// Attempt to strip protection
			DWORD OldProtect = 0, NewProtect = 0;
			if (!VirtualProtect((LPVOID)Source, 12, PAGE_EXECUTE_READWRITE, &OldProtect))
				return false;

			// Apply the hook
			this->Source = std::make_unique<uint8_t[]>(12);
			std::memcpy(this->Source.get(), (const void*)Source, 12);
			this->SourceLocation = Source;

			*(volatile uint8_t*)(Source) = 0x48;
			*(volatile uint8_t*)(Source + 1) = 0xB8;
			*(volatile uint64_t*)(Source + 2) = uint64_t(Target);
			*(volatile uint8_t*)(Source + 10) = 0xFF;
			*(volatile uint8_t*)(Source + 11) = 0xE0;

			// Restore protection & flush cache
			VirtualProtect((LPVOID)Source, 12, OldProtect, &NewProtect);
			FlushInstructionCache(GetCurrentProcess(), (LPCVOID)Source, 12);

			// Success
			return true;
		}
		else
		{
			// Not supported
			throw new std::exception("Unsupported Platform");
		}

		// Failed
		return false;
	}

	// Removes the installed hook, if any
	void Unhook()
	{
		// Ensure installed
		if (this->Source != nullptr)
		{
			if (sizeof(uintptr_t) == 4)	// 32bit
			{
				// Attempt to strip protection
				DWORD OldProtect = 0, NewProtect = 0;
				if (!VirtualProtect((LPVOID)this->SourceLocation, 5, PAGE_EXECUTE_READWRITE, &OldProtect))
					return;

				// Revert the hook
				std::memcpy((void*)this->SourceLocation, this->Source.get(), 5);

				this->Source.reset();

				// Restore protection & flush cache
				VirtualProtect((LPVOID)this->SourceLocation, 5, OldProtect, &NewProtect);
				FlushInstructionCache(GetCurrentProcess(), (LPCVOID)this->SourceLocation, 5);
			}
			else if (sizeof(uintptr_t) == 8)	// 64bit
			{
				// Attempt to strip protection
				DWORD OldProtect = 0, NewProtect = 0;
				if (!VirtualProtect((LPVOID)this->SourceLocation, 12, PAGE_EXECUTE_READWRITE, &OldProtect))
					return;

				// Revert the hook
				std::memcpy((void*)this->SourceLocation, this->Source.get(), 12);

				this->Source.reset();

				// Restore protection & flush cache
				VirtualProtect((LPVOID)this->SourceLocation, 12, OldProtect, &NewProtect);
				FlushInstructionCache(GetCurrentProcess(), (LPCVOID)this->SourceLocation, 12);
			}
			else
			{
				// Not supported
				throw new std::exception("Unsupported Platform");
			}
		}
	}
};

// A class that implements a call instruction hook
class CallHook
{
private:
	std::unique_ptr<uint8_t[]> Source;
	uintptr_t SourceLocation;

public:
	CallHook() { }
	~CallHook() { }

	// Install the CallHook with the provided information
	bool Hook(uintptr_t Source, uintptr_t Target)
	{
		if (sizeof(uintptr_t) == 4)	// 32bit
		{
			// Attempt to strip protection
			DWORD OldProtect = 0, NewProtect = 0;
			if (!VirtualProtect((LPVOID)Source, 5, PAGE_EXECUTE_READWRITE, &OldProtect))
				return false;

			// Apply the hook
			this->Source = std::make_unique<uint8_t[]>(5);
			std::memcpy(this->Source.get(), (const void*)Source, 5);
			this->SourceLocation = Source;

			*(volatile uint8_t*)(Source) = 0xE8;
			*(volatile uint32_t*)(Source + 1) = (uint32_t(Target) - uint32_t(Source) - 5);

			// Restore protection & flush cache
			VirtualProtect((LPVOID)Source, 5, OldProtect, &NewProtect);
			FlushInstructionCache(GetCurrentProcess(), (LPCVOID)Source, 5);

			// Success
			return true;
		}
		else if (sizeof(uintptr_t) == 8)	// 64bit
		{
			// Attempt to strip protection
			DWORD OldProtect = 0, NewProtect = 0;
			if (!VirtualProtect((LPVOID)Source, 12, PAGE_EXECUTE_READWRITE, &OldProtect))
				return false;

			// Apply the hook
			this->Source = std::make_unique<uint8_t[]>(12);
			std::memcpy(this->Source.get(), (const void*)Source, 12);
			this->SourceLocation = Source;

			*(volatile uint8_t*)(Source) = 0x48;
			*(volatile uint8_t*)(Source + 1) = 0xB8;
			*(volatile uint64_t*)(Source + 2) = uint64_t(Target);
			*(volatile uint8_t*)(Source + 10) = 0xFF;
			*(volatile uint8_t*)(Source + 11) = 0xD0;

			// Restore protection & flush cache
			VirtualProtect((LPVOID)Source, 12, OldProtect, &NewProtect);
			FlushInstructionCache(GetCurrentProcess(), (LPCVOID)Source, 12);

			// Success
			return true;
		}
		else
		{
			// Not supported
			throw new std::exception("Unsupported Platform");
		}

		// Failed
		return false;
	}

	// Removes the installed hook, if any
	void Unhook()
	{
		// Ensure installed
		if (this->Source != nullptr)
		{
			if (sizeof(uintptr_t) == 4)	// 32bit
			{
				// Attempt to strip protection
				DWORD OldProtect = 0, NewProtect = 0;
				if (!VirtualProtect((LPVOID)this->SourceLocation, 5, PAGE_EXECUTE_READWRITE, &OldProtect))
					return;

				// Revert the hook
				std::memcpy((void*)this->SourceLocation, this->Source.get(), 5);

				this->Source.reset();

				// Restore protection & flush cache
				VirtualProtect((LPVOID)this->SourceLocation, 5, OldProtect, &NewProtect);
				FlushInstructionCache(GetCurrentProcess(), (LPCVOID)this->SourceLocation, 5);
			}
			else if (sizeof(uintptr_t) == 8)	// 64bit
			{
				// Attempt to strip protection
				DWORD OldProtect = 0, NewProtect = 0;
				if (!VirtualProtect((LPVOID)this->SourceLocation, 12, PAGE_EXECUTE_READWRITE, &OldProtect))
					return;

				// Revert the hook
				std::memcpy((void*)this->SourceLocation, this->Source.get(), 12);

				this->Source.reset();

				// Restore protection & flush cache
				VirtualProtect((LPVOID)this->SourceLocation, 12, OldProtect, &NewProtect);
				FlushInstructionCache(GetCurrentProcess(), (LPCVOID)this->SourceLocation, 12);
			}
			else
			{
				// Not supported
				throw new std::exception("Unsupported Platform");
			}
		}
	}
};

// A class that assists in hooking a VTable
class VTableHook
{
private:
	uintptr_t SourceFunction;
	uintptr_t SourceLocation;
	bool Installed;

public:
	VTableHook()
	{
		this->Installed = false;
	}

	~VTableHook() { }

	// Installs the VTableHook with provided information
	bool Hook(uintptr_t Source, uintptr_t Target, uint32_t Index = 0)
	{
		// Calculate offset
		auto Offset = (Source + (Index * sizeof(uintptr_t)));
		this->SourceLocation = Offset;

		// Attempt to strip protection
		DWORD OldProtect = 0, NewProtect = 0;
		if (!VirtualProtect((LPVOID)Offset, sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &OldProtect))
			return false;

		// Install hook
		if (sizeof(uintptr_t) == 4)
		{
			this->SourceFunction = (uintptr_t)InterlockedExchange((volatile LONG*)Offset, (LONG)Target);
			this->Installed = true;
		}
		else if (sizeof(uintptr_t) == 8)
		{
			this->SourceFunction = (uintptr_t)InterlockedExchange64((volatile LONG64*)Offset, (LONG64)Target);
			this->Installed = true;
		}
		else
		{
			// Not supported
			throw new std::exception("Unsupported Platform");
		}

		// Restore protection & flush cache
		VirtualProtect((LPVOID)Offset, sizeof(uintptr_t), OldProtect, &NewProtect);
		FlushInstructionCache(GetCurrentProcess(), (LPCVOID)Offset, sizeof(uintptr_t));

		// Success
		return true;
	}

	// Removes the installed hook, if any
	void Unhook()
	{
		// Make sure we have a hook
		if (this->Installed)
		{
			// Attempt to strip protection
			DWORD OldProtect = 0, NewProtect = 0;
			if (!VirtualProtect((LPVOID)this->SourceLocation, sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &OldProtect))
				return;

			// Install hook
			if (sizeof(uintptr_t) == 4)
			{
				InterlockedExchange((volatile LONG*)this->SourceLocation, (LONG)this->SourceFunction);
			}
			else if (sizeof(uintptr_t) == 8)
			{
				InterlockedExchange64((volatile LONG64*)this->SourceLocation, (LONG64)this->SourceFunction);
			}
			else
			{
				// Not supported
				throw new std::exception("Unsupported Platform");
			}

			// Restore protection & flush cache
			VirtualProtect((LPVOID)this->SourceLocation, sizeof(uintptr_t), OldProtect, &NewProtect);
			FlushInstructionCache(GetCurrentProcess(), (LPCVOID)this->SourceLocation, sizeof(uintptr_t));

			// Finished
			this->Installed = false;
		}
	}

	// Get the original function pointer
	uintptr_t GetSourceFunction()
	{
		if (this->Installed)
			return this->SourceFunction;

		return NULL;
	}
};

// A class that handles an API hook
class APIHook
{
private:
	JumpHook InternalHook;

public:
	APIHook() { }
	~APIHook() { }

	// Installs the API based hook
	bool Hook(LPCSTR Module, LPCSTR FuncName, uintptr_t Target)
	{
		// Fetch handle
		HMODULE hModule = GetModuleHandleA(Module);
		if (hModule == NULL)
			return false;

		// Fetch function
		uintptr_t Source = (uintptr_t)GetProcAddress(hModule, FuncName);
		if (Source == NULL)
			return false;

		// We can install the hook
		return this->InternalHook.Hook(Source, Target);
	}

	// Removes the installed hook, if any
	void Unhook()
	{
		this->InternalHook.Unhook();
	}
};

// A class that handles an IAT hook
class IATHook
{
private:
	VTableHook InternalHook;

public:
	IATHook() { }
	~IATHook() { }

	// Installs the IAT based hook
	bool Hook(LPCSTR Module, LPCSTR FuncName, uintptr_t Target)
	{
		// We traverse the IAT for the import, then swap the pointer using a VTable hook
		auto Mod = (HMODULE)GetModuleHandle(NULL);
		auto DOSHeader = (IMAGE_DOS_HEADER*)Mod;
		auto NTHeader = (IMAGE_NT_HEADERS*)((const uint8_t*)(DOSHeader) + DOSHeader->e_lfanew);

		// Resolve import table
		auto ImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)((const uint8_t*)(DOSHeader) + NTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		// Iterate over modules
		while (ImportDesc->FirstThunk)
		{
			const char* ImportDllName = (char*)((const uint8_t*)(DOSHeader) + ImportDesc->Name);

			// Compare the name, case insensitive
			if (_strnicmp(Module, ImportDllName, strlen(Module)) == 0)
			{
				// We found the module, search for the function
				auto ThunkDesc = (IMAGE_THUNK_DATA*)((const uint8_t*)(DOSHeader) + ImportDesc->OriginalFirstThunk);

				uint32_t ThunkIndex = 0;

				// Iterate over functions
				while (ThunkDesc->u1.Function)
				{
					const char* ImportFnName = (char*)((const uint8_t*)(DOSHeader) + ThunkDesc->u1.AddressOfData + 2);

					// Compare the name, case insensitive
					if (_strnicmp(FuncName, ImportFnName, strlen(FuncName)) == 0)
					{
						// We've got it, prepare the hook
						uintptr_t SourceAddress = (uintptr_t)((uintptr_t*)((const uint8_t*)(DOSHeader) + ImportDesc->FirstThunk) + ThunkIndex);

						// Hook the first target
						return this->InternalHook.Hook(SourceAddress, Target);
					}

					// Advance
					ThunkDesc++;
					ThunkIndex++;
				}

				// If we couldn't find the function, end here...
				break;
			}

			// Advance
			ImportDesc++;
		}

		// Failure
		return false;
	}

	// Removes the installed hook, if any
	void Unhook()
	{
		this->InternalHook.Unhook();
	}

	// Get the original function pointer
	uintptr_t GetSourceFunction()
	{
		return this->InternalHook.GetSourceFunction();
	}
};

#endif