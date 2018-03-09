// Standard includes
#include <Windows.h>
#include <memory>
#include <codecvt>
#include <locale>

// The class we are implementing
#include "utils.h"

Utils::MainModuleInfo::MainModuleInfo() : BaseAddress(0), EndAddress(0)
{
	// Make sure we didn't load
	if (BaseAddress) { return; }

	// Get main module
	auto MainModule = (HMODULE)GetModuleHandle(NULL);

	// Set base
	BaseAddress = (uintptr_t)(MainModule);

	// Read PE headers
	auto dosHeader = (const IMAGE_DOS_HEADER*)(MainModule);
	auto ntHeader = (const IMAGE_NT_HEADERS64*)((const uint8_t*)(dosHeader)+dosHeader->e_lfanew);

	// Calculate end address
	EndAddress = BaseAddress + ntHeader->OptionalHeader.SizeOfCode;
}

uint8_t* Utils::DetourVirtualFunction(uint8_t* Target, uint8_t* Replacement, uint32_t TableIndex)
{
	// If we are starting at the top of the table...
	uint8_t* VirtualTableOffset = (Target + (TableIndex * sizeof(uintptr_t)));

	// Prepare to protect the segment
	DWORD dwOld = NULL;
	// Unprotect it
	if (!VirtualProtect(VirtualTableOffset, sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &dwOld)) { return nullptr; }

	// Safely swap the pointers
	auto Original = (uint8_t*)InterlockedExchange64((volatile LONG64*)VirtualTableOffset, (LONG64)Replacement);

	// Restore protection
	VirtualProtect(VirtualTableOffset, sizeof(uintptr_t), dwOld, &dwOld);

	// Return the original call
	return Original;
}

// Constant platform specific variables
static const char DirectorySeparatorChar = '\\';
static const char AltDirectorySeparatorChar = '/';
static const char VolumeSeparatorChar = ':';

std::string Utils::GetDirectoryName(const std::string& Path)
{
	// Make sure we have an actual path
	if (Path.empty()) { return ""; }

	// Cache full length
	int32_t FullLength = (int32_t)Path.length();

	// Calculate the root length
	int32_t RootLength = (FullLength > 2 && Path[1] == ':' && (Path[2] == DirectorySeparatorChar || Path[2] == AltDirectorySeparatorChar)) ? 3 : 0;

	// The iterator
	int32_t i = FullLength;
	// Check and loop
	if (i > RootLength)
	{
		// Iterate until end
		while (i > RootLength && Path[--i] != DirectorySeparatorChar && Path[i] != AltDirectorySeparatorChar);
		// Return the new dir
		return Path.substr(0, i);
	}

	// Failed to find it
	return "";
}

bool Utils::IsPathRooted(const std::string& Path)
{
	// Fetch length
	auto Length = Path.length();

	// Compare
	if ((Length >= 1 && (Path[0] == DirectorySeparatorChar || Path[0] == AltDirectorySeparatorChar)) || Length >= 2 && Path[1] == VolumeSeparatorChar)
	{
		// We are rooted
		return true;
	}

	// Not rooted
	return false;
}

std::string Utils::CombinePath(const std::string& Path1, const std::string& Path2)
{
	// Check if we have an actual paths for 1 and 2 (If both aren't return nothing)
	if (Path1.empty() && Path2.empty()) { return ""; }

	// Check lengths and combine
	if (Path2.length() == 0) { return Path1; }
	if (Path1.length() == 0) { return Path2; }

	// Check if path 2 is rooted
	if (IsPathRooted(Path2)) { return Path2; }

	// Otherwise merge the two paths
	auto LastChar = Path1[Path1.length() - 1];
	// Check if we have a separator
	if (LastChar != DirectorySeparatorChar && LastChar != AltDirectorySeparatorChar && LastChar != VolumeSeparatorChar)
	{
		// Merge with separator
		return Path1 + DirectorySeparatorChar + Path2;
	}

	// No separator, just merge
	return Path1 + Path2;
}

std::string Utils::Replace(std::string Subject, const std::string& Search, const std::string& Replace)
{
	// Current search path
	size_t CurrentPosition = 0;
	// Loop until we can't find it
	while ((CurrentPosition = Subject.find(Search, CurrentPosition)) != std::string::npos)
	{
		// Replace it
		Subject.replace(CurrentPosition, Search.length(), Replace);
		// Jump ahead
		CurrentPosition += Replace.length();
	}
	// Return result
	return Subject;
}

bool Utils::FileExists(const std::string& File)
{
	// Check if we have an actual path
	if (File.empty()) { return false; }

	// Check whether the last char is a separator
	if (File[File.length()] == DirectorySeparatorChar || File[File.length()] == AltDirectorySeparatorChar)
	{
		// Not a file
		return false;
	}

	// Check the path using the FileAttributes data
	WIN32_FILE_ATTRIBUTE_DATA FileAttrs;
	// Fetch them
	auto Result = GetFileAttributesExA(File.c_str(), GET_FILEEX_INFO_LEVELS::GetFileExInfoStandard, &FileAttrs);

	// Check result
	if (Result)
	{
		// We are a file if the following are met
		return (FileAttrs.dwFileAttributes != -1) && ((FileAttrs.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0);
	}

	// Failed
	return false;
}

bool Utils::DeleteFile(const std::string& File)
{
	// Check if we have an actual path
	if (File.empty()) { return false; }

	// Attempt to delete the file
	auto Result = DeleteFileA(File.c_str());

	// Check if we deleted it
	if (Result && GetLastError() == 0) { return true; }

	// Failed to delete
	return false;
}

std::string Utils::FormatList(const std::string Format, va_list ArgList)
{
	// We must reserve two times as much as the length of the format
	int32_t FinalLength, Length = (int32_t)(Format.size() * 2);
	// A safe buffer of formatted chars
	std::unique_ptr<char[]> Formatted;
	// Loop until finished
	while (true)
	{
		// Set it up
		Formatted.reset(new char[Length]);
		// Copy buffer
		strcpy_s(&Formatted[0], Length, Format.c_str());
		// Set it
#pragma warning (disable:4996)
		FinalLength = vsnprintf(&Formatted[0], Length, Format.c_str(), ArgList);
#pragma warning (default:4996)
		// Calculate
		if (FinalLength < 0 || FinalLength >= Length)
		{
			// Set
			Length += abs(FinalLength - Length + 1);
		}
		else
		{
			// Done
			break;
		}
	}
	// Return result
	return std::string(Formatted.get());
}

std::string Utils::ReadNullString(FILE* Handle)
{
	std::string Result = "";

	char ch = 0;
	fread(&ch, 1, 1, Handle);
	while (ch != 0)
	{
		Result += ch;
		fread(&ch, 1, 1, Handle);
	}

	return Result;
}

bool Utils::HasEnding(const std::string& fullString, const std::string& ending)
{
	// Check length
	if (fullString.length() >= ending.length()) 
	{
		return (0 == fullString.compare(fullString.length() - ending.length(), ending.length(), ending));
	}
	
	// Doesn't end
	return false;
}

void Utils::PatchMemory(ULONG_PTR Address, PBYTE Data, SIZE_T Size)
{
	DWORD d = 0;
	VirtualProtect((LPVOID)Address, Size, PAGE_EXECUTE_READWRITE, &d);

	for (SIZE_T i = 0; i < Size; i++)
		*(volatile BYTE *)(Address + i) = *Data++;

	VirtualProtect((LPVOID)Address, Size, d, &d);

	FlushInstructionCache(GetCurrentProcess(), (LPVOID)Address, Size);
}

std::wstring Utils::s2ws(const std::string& str)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.from_bytes(str);
}

std::string Utils::ws2s(const std::wstring& wstr)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.to_bytes(wstr);
}