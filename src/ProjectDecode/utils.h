#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>

#undef DeleteFile	// Remove built-in windows macro

namespace Utils
{
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

	// -- String utilities

	// Replace all string substrings
	std::string Replace(std::string Subject, const std::string& Search, const std::string& Replace);

	// Reads a null-term string
	std::string ReadNullString(FILE* Handle);

	// If a string ends with another string
	bool HasEnding(const std::string& fullString, const std::string& ending);

	// String to wide string
	std::wstring StringToWideString(const std::string& str);
	// Wide string to string
	std::string WideStringToString(const std::wstring& wstr);
}