#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>

#undef DeleteFile	// Remove built-in windows macro

namespace Utils
{
	// Helps with main module info
	class MainModuleInfo
	{
	public:
		// Loads main module info
		MainModuleInfo();

		// Helper functions
		inline uintptr_t Begin() { return BaseAddress; }
		inline uintptr_t End() { return EndAddress; }

	private:

		// Start and end addresses
		uintptr_t BaseAddress;
		uintptr_t EndAddress;
	};

	// Detours a function located in a VTable
	uint8_t* DetourVirtualFunction(uint8_t* Target, uint8_t* Replacement, uint32_t TableIndex = 0);

	// -- Filesystem utilities

	// Gets the directory name from a file path
	std::string GetDirectoryName(const std::string& Path);
	// Check if the path is rooted (C:\)
	bool IsPathRooted(const std::string& Path);
	// Combine two paths
	std::string CombinePath(const std::string& Path1, const std::string& Path2);
	// Check whether or not a file exists
	bool FileExists(const std::string& File);
	// Deletes a file from the path
	bool DeleteFile(const std::string& File);

	// Format a string
	std::string FormatList(const std::string Format, va_list ArgList);

	// Attampts to scan for a file, on failure, it is logged and closes
	std::string ScanModtoolsAsset(const std::string& ModToolsRoot, const std::string& ModDirectoryBase, const std::string& AssetName);

	// -- String utilities

	// Replace all string substrings
	std::string Replace(std::string Subject, const std::string& Search, const std::string& Replace);

	// Reads a null-term string
	std::string ReadNullString(FILE* Handle);

	// If a string ends with another string
	bool HasEnding(const std::string& fullString, const std::string& ending);

	// String to wide string
	std::wstring s2ws(const std::string& str);
	// Wide string to string
	std::string ws2s(const std::wstring& wstr);

	// Patches memory
	void PatchMemory(ULONG_PTR Address, PBYTE Data, SIZE_T Size);
}