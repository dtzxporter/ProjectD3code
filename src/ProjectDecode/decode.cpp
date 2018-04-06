#include "decode.h"
#include "utils.h"
#include "phook.h"

// Our loaded translation mappings
std::unordered_map<std::string, std::string> TranslationDatabase;

// Our proc definitions
typedef char*(__thiscall *SE_GetStringProc)(const char* StringReferenceText);
typedef BYTE**(__cdecl *DB_FindXAssetHeaderProc)(int AssetType, const char* AssetName, int WaitTime);
typedef int(__stdcall *TranslateInfoTranslateProc)(DWORD* TranslateInfo);
typedef int(__thiscall *TranslateInfoSetResultProc)(DWORD* TranslateInfo, const wchar_t* ResultText, int ResultTextLength);

// Our functions
SE_GetStringProc SE_GetString;
DB_FindXAssetHeaderProc DB_FindXAssetHeader;
TranslateInfoTranslateProc TranslateInfoTranslate;
TranslateInfoSetResultProc TranslateInfoSetResult;

// Logging instance
#if LOGGER_MODE
FILE* LoggerHandle = NULL;
#endif

// Our function hooks
char* __cdecl SEH_StringEd_GetStringHook(const char* StringReferenceText)
{
	// Strip the @ modifier
	char* StrReference = (char*)StringReferenceText;
	if (*StringReferenceText == '@')
	{
		StrReference = (char*)(StringReferenceText + 1);
	}

	// Here, we can perform our translation swapping...
	if (TranslationDatabase.find(StrReference) != TranslationDatabase.end())
	{
		// We found it, use this one...
		return (char*)TranslationDatabase[StrReference].c_str();
	}

	// Else, find an existing one...
	char* Result = (char*)StringReferenceText;

	// Perform engine localized string overriding first
	Result = SE_GetString(StrReference);
	if (!Result)
	{
		// No override found, locate the localized string asset
		auto Header = (BYTE**)DB_FindXAssetHeader(0x1B, StrReference, 0);
		if (Header)
		{
			Result = (char*)*Header;
		}
		else
		{
			Result = (char*)StringReferenceText;
		}
	}

	// Log the key and value if not read
#if LOGGER_MODE
	if (StringReferenceText && Result)
	{
		fprintf(LoggerHandle, "%s : %s\n", StringReferenceText, Result);
	}
#endif

	// Return the result
	return Result;
}

int __stdcall Scaleform_TranslateSetResultHook(DWORD* TranslateInfo)
{
	// Convert it
	auto WideKeyStr = std::wstring((const wchar_t*)TranslateInfo[0]);
	auto KeyStr = Utils::WideStringToString(WideKeyStr);
	auto KeyFind = std::string(KeyStr);

	// Strip the @ modifier
	if (KeyStr.size() > 2 && KeyStr[0] == '@')
	{
		KeyFind = KeyStr.substr(1);
	}

	// Check for a match...
	if (TranslationDatabase.find(KeyFind) != TranslationDatabase.end())
	{
		try
		{
			// Load this one
			auto ResultLoad = Utils::StringToWideString(TranslationDatabase[KeyFind]);
			// Apply the converted translation
			return TranslateInfoSetResult(TranslateInfo, ResultLoad.c_str(), -1);
		}
		catch (...)
		{
			// Default
			return TranslateInfoTranslate(TranslateInfo);
		}
	}

	// Log the key if we didn't get it
#if LOGGER_MODE
	fprintf(LoggerHandle, "%s\n", KeyStr.c_str());
#endif

	// Default...
	return TranslateInfoTranslate(TranslateInfo);
}

void DecodeLoadTranslations(MainModule& AppModule)
{
	// We load the translations next to the application
	auto DbPath = Utils::CombinePath(Utils::GetDirectoryName(AppModule.GetModulePath()), "TranslationsDB.db");

	// Load the database if the user was smart enough to copy it
	if (Utils::FileExists(DbPath))
	{
		auto Db = fopen(DbPath.c_str(), "rb");

		if (Db)
		{
			//
			// Simple format <uint32_t> entry count X null-term utf8-string KVP
			//

			uint32_t Entries = 0;
			fread(&Entries, 4, 1, Db);

			for (uint32_t i = 0; i < Entries; i++)
			{
				auto Key = Utils::ReadNullString(Db);
				auto Value = Utils::ReadNullString(Db);

				TranslationDatabase[Key] = Value;
			}

			// Log entries loaded
#if LOGGER_MODE
			printf("Loaded: %d translation entries\n", Entries);
#endif
		}

		fclose(Db);
	}
	else
	{
		// Log failure to find database
#if LOGGER_MODE
		printf("No database file found...\n");
#endif
	}
}

void DecodeApplyPatches(MainModule& AppModule)
{
	// We must apply the hooks here, only after the patterns are found
	auto SEHTranslate = FindPattern("55 8B EC 83 E4 ? A1 ? ? ? ? 56 57 85 C0", AppModule.GetBaseAddress(), AppModule.GetCodeSize());
	auto ScaleformTranslate = FindPattern("8B 50 ?? 33 F6 56 6A ?? FF D2 3B C6 74", AppModule.GetBaseAddress(), AppModule.GetCodeSize());
	auto DBFindFAssetHeaderFunc = FindPattern("55 8B EC 83 E4 ? 83 EC ? 53 56 57 C7 44 24 ? ? ? ? ? 80 3D ? ? ? ? ?", AppModule.GetBaseAddress(), AppModule.GetCodeSize());
	auto SEGetStringFunc = FindPattern("55 8B EC 83 EC ? 53 56 BE ? ? ? ? 2B CE", AppModule.GetBaseAddress(), AppModule.GetCodeSize());
	auto ScaleformTranslateSetInfo = FindPattern("55 8B EC 8B 45 ? 56 8B F1 85 C0 74 ? 53", AppModule.GetBaseAddress(), AppModule.GetCodeSize());

	// Log initial patterns
#if LOGGER_MODE
	printf("SEHTranslate: 0x%X\nScaleformTranslate: 0x%X\n", SEHTranslate, ScaleformTranslate);
	printf("DBFindFAssetHeaderFunc: 0x%X\nSEGetStringFunc: 0x%X\n", DBFindFAssetHeaderFunc, SEGetStringFunc);
	printf("ScaleformTranslateSetInfo: 0x%X\n", ScaleformTranslateSetInfo);
#endif

	// Continue if all were found
	if (SEHTranslate > 0 && ScaleformTranslate > 0 && DBFindFAssetHeaderFunc > 0 && SEGetStringFunc > 0 && ScaleformTranslateSetInfo > 0)
	{
		// Traverse SEHTranslate for required procs
		auto SEHTranslateProc = (SEHTranslate + AppModule.GetBaseAddress());
		auto ScaleformTranslateProc = (ScaleformTranslate + AppModule.GetBaseAddress());
		auto DB_FindXAssetHeaderAddr = (DBFindFAssetHeaderFunc + AppModule.GetBaseAddress());
		auto SE_GetStringAddr = (SEGetStringFunc + AppModule.GetBaseAddress());

		// Setup the proc redirects
		SE_GetString = (SE_GetStringProc)SE_GetStringAddr;
		DB_FindXAssetHeader = (DB_FindXAssetHeaderProc)DB_FindXAssetHeaderAddr;

		// ScaleformTranslate = Proc+0x24<uint32_t> = base vtable
		uint32_t ScaleformTranslateVTable = *(uint32_t*)((char*)ScaleformTranslateProc + 0x24);
		uint32_t ScaleformTranslateInfoAddr = *((uint32_t*)ScaleformTranslateVTable + 2);
		
		// Log heuristic info
#if LOGGER_MODE
		printf("SE_GetStringAddr: 0x%X\nDB_FindXAssetHeaderAddr: 0x%X\n", SE_GetStringAddr, DB_FindXAssetHeaderAddr);
		printf("ScaleformTranslateVTable: 0x%X\nScaleformTranslateInfoAddr: 0x%X\n", ScaleformTranslateVTable, ScaleformTranslateInfoAddr);
#endif

		// Resolve info function
		auto TranslateSetInfoProc = (ScaleformTranslateSetInfo + AppModule.GetBaseAddress());

		// Setup the proc redirects
		TranslateInfoTranslate = (TranslateInfoTranslateProc)ScaleformTranslateInfoAddr;
		TranslateInfoSetResult = (TranslateInfoSetResultProc)TranslateSetInfoProc;

		// Log other info
#if LOGGER_MODE
		printf("TranslateSetInfoProc: 0x%X\n", TranslateSetInfoProc);
#endif

		// If we got here, we can apply the hooks
		JumpHook().Hook(SEHTranslateProc, (uintptr_t)&SEH_StringEd_GetStringHook);
		VTableHook().Hook(ScaleformTranslateVTable, (uintptr_t)&Scaleform_TranslateSetResultHook, 2);
	}
}

DWORD WINAPI DecodeInitialize(LPVOID lpParam)
{
	// Load up the module information
	MainModule ApplicationModule;

	// Ensure that we are the main game
	if (Utils::HasEnding(ApplicationModule.GetModulePath(), "codomp_client_shipretail.exe"))
	{
		// Setup logger
#if LOGGER_MODE
		AllocConsole();
		freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
		LoggerHandle = fopen("C:\\decodelog.txt", "w");
#endif

		// Load translation database
		DecodeLoadTranslations(ApplicationModule);

		// We must prepare the module, but, apply patches after the window loads (Unpacked)
		while (FindWindow(L"CODO", NULL) == NULL) Sleep(1);

		// Attempt to apply patches
		DecodeApplyPatches(ApplicationModule);

		// Log end
#if LOGGER_MODE
		printf("Initialize has finished, see decodelog.txt for translating...\n");
#endif
	}

	// Success
	return 0;
}

void WINAPI DecodeShutdown()
{
	// Close logger
#if LOGGER_MODE
	if (LoggerHandle != NULL)
		fclose(LoggerHandle);
	FreeConsole();
#endif
}