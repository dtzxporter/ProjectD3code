// Standard includes
#include <unordered_map>
// Classes we need
#include "utils.h"
#include "hooking.h"

// Log all key requests
#define LOGGER_MODE 1

// The class we are implementing
#include "valk.h"

// Our loaded translation mappings
std::unordered_map<std::string, std::string> TranslationDatabase;

#if LOGGER_MODE
FILE* LoggerHandle = NULL;
#endif

// Our function definitions
typedef BYTE*(__cdecl *GetIString)(const char* pszReference);
typedef BYTE*(__thiscall *GetString)(const char* pszReference);
typedef int(__cdecl *FindLocalize)(int a1, int a2, int a3);
typedef int(__stdcall *LoadTranslateOg)(DWORD *a1);
typedef int(__thiscall *TranslateInfoSetResult)(DWORD* a1, const wchar_t* presultText, int resultLen);

// Our function hooks
BYTE* __cdecl SEH_StringEd_GetString(const char* pszReference)
{
	char* vRef = (char*)pszReference;
	if (*pszReference == '@')
	{
		vRef = (char*)(pszReference + 1);
	}

	// Here, we can perform our translation swapping...
	if (TranslationDatabase.find(vRef) != TranslationDatabase.end())
	{
		// We found it, use this one...
		return (BYTE*)TranslationDatabase[vRef].c_str();
	}

	// Else, find an existing one...
	BYTE* result = (BYTE*)pszReference;

	auto loadString = (GetString)(0x6F30F0);
	auto findLocalize = (FindLocalize)(0x497830);

	result = loadString(vRef);
	if (!result)
	{
		auto header = (BYTE**)findLocalize(0x1B, (int)vRef, 0);
		if (header)
		{
			result = *header;
		}
		else
		{
			result = (BYTE*)pszReference;
		}
	}

	// Logger mode
#if LOGGER_MODE
	if (pszReference && result)
	{
		fprintf(LoggerHandle, "%s : %s\n", pszReference, result);
	}
#endif

	return result;
}

int __stdcall Scaleform_Translate(DWORD* TranslateInfo)
{
	// Just load the normal shit now
	auto loadTrans = (LoadTranslateOg)(0x5CD550);
	auto setResult = (TranslateInfoSetResult)(0x7C9AB0);

	// Convert it
	auto key = std::wstring((const wchar_t*)TranslateInfo[0]);
	auto keyNorm = Utils::ws2s(key);
	auto keyFind = std::string(keyNorm);

	// Check if we can hotswap it
	if (keyNorm.size() > 2 && keyNorm[0] == '@')
	{
		keyFind = keyNorm.substr(1);
	}

	// Check for a match...
	if (TranslationDatabase.find(keyFind) != TranslationDatabase.end())
	{
		try
		{
			// Load this one
			auto resultLoad = Utils::s2ws(TranslationDatabase[keyFind]);

			return setResult(TranslateInfo, resultLoad.c_str(), -1);
		}
		catch (...)
		{
			// Default
			return loadTrans(TranslateInfo);
		}
	}

	// Logger mode
#if LOGGER_MODE
	fprintf(LoggerHandle, "%s\n", keyNorm.c_str());
#endif

	// Default...
	return loadTrans(TranslateInfo);
}

//
// Valkyrie main logic
//

void ValkyrieLoadTranslations()
{
	// Get the main app path, so we can load the database
	char ExePath[MAX_PATH] = { 0 };
	GetModuleFileNameA(NULL, ExePath, _countof(ExePath));

	// Build database path
	auto DbPath = Utils::CombinePath(Utils::GetDirectoryName(ExePath), "TranslationsDB.db");
	// Prepare to load it
	if (Utils::FileExists(DbPath))
	{
		auto Db = fopen(DbPath.c_str(), "rb");

		if (Db)
		{
			uint32_t Entries = 0;
			fread(&Entries, 4, 1, Db);

			for (uint32_t i = 0; i < Entries; i++)
			{
				auto Key = Utils::ReadNullString(Db);
				auto Value = Utils::ReadNullString(Db);

				TranslationDatabase[Key] = Value;
			}
		}

		fclose(Db);
	}
}

void ValkyrieHookFunctions()
{
	// Prepare to hook translation functions...

	// TODO: These should use patterns but lazy af

	// Hook old menu translation service
	hooking::JmpHook().Installhook((void*)(0x6F3490), (void*)&SEH_StringEd_GetString);

	// TODO: Swap out service ptr and save it for use later, since
	// We call it in the hooked function...
	DWORD Addr = (DWORD)&Scaleform_Translate;

	// Patch the scaleform translation service
	Utils::PatchMemory((ULONG_PTR)0x00D89A18, (PBYTE)&Addr, 4);
}

DWORD WINAPI ValkyrieInitialize(LPVOID lpParam)
{
	// Verify that we are inside of the game, not another application...
	char ExePath[MAX_PATH] = { 0 };
	GetModuleFileNameA(NULL, ExePath, _countof(ExePath));

	// Check if the file matches
	if (Utils::HasEnding(ExePath, "codomp_client_shipretail.exe"))
	{
		// Load translation database
		ValkyrieLoadTranslations();

		// Logger mode
#if LOGGER_MODE
		LoggerHandle = fopen("C:\\decodelog.txt", "w");
#endif

		// We must prepare the module, but, apply patches after the window loads (Unpacked)
		while (FindWindow(L"CODO", NULL) == NULL) Sleep(1);

		// It's safe to patch the application
		ValkyrieHookFunctions();
	}

	// Success
	return 0;
}

void WINAPI ValkyrieShutdown()
{
	// Logger mode
#if LOGGER_MODE
	if (LoggerHandle)
		fclose(LoggerHandle);
#endif
}