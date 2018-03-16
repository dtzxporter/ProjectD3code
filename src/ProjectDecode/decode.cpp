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
			fprintf(LoggerHandle, "Loaded: %d translation entries\n", Entries);
#endif
		}

		fclose(Db);
	}
	else
	{
		// Log failure to find database
#if LOGGER_MODE
		fprintf(LoggerHandle, "No database file found...\n");
#endif
	}
}

void DecodeApplyPatches(MainModule& AppModule)
{
	// We must apply the hooks here, only after the patterns are found
	auto SEHTranslate = FindPattern("55 8B EC 83 E4 ?? 51 A1 ?? ?? ?? ?? 56 85 C0", AppModule.GetBaseAddress(), AppModule.GetCodeSize());
	auto ScaleformTranslate = FindPattern("8B 50 ?? 33 F6 56 6A ?? FF D2 3B C6 74", AppModule.GetBaseAddress(), AppModule.GetCodeSize());

	// Log initial patterns
#if LOGGER_MODE
	fprintf(LoggerHandle, "SEHTranslate: 0x%X\nScaleformTranslate: 0x%X\n", SEHTranslate, ScaleformTranslate);
#endif

	// Continue if both were found
	if (SEHTranslate > 0 && ScaleformTranslate > 0)
	{
		// Traverse SEHTranslate for required procs
		auto SEHTranslateProc = (SEHTranslate + AppModule.GetBaseAddress());
		auto ScaleformTranslateProc = (ScaleformTranslate + AppModule.GetBaseAddress());

		// SE_GetString = Proc+0x33<uint32_t> + Proc+0x32+5
		uint32_t SE_GetStringRelAddr = *(uint32_t*)((char*)SEHTranslateProc + 0x33);
		uint32_t SE_GetStringAddr = SE_GetStringRelAddr + (SEHTranslateProc + 0x32) + 5;

		// DB_FindXAssetHeader = Proc+0x40<uint32_t> + Proc+0x3F+5
		uint32_t DB_FindXAssetHeaderRelAddr = *(uint32_t*)((char*)SEHTranslateProc + 0x40);
		uint32_t DB_FindXAssetHeaderAddr = DB_FindXAssetHeaderRelAddr + (SEHTranslateProc + 0x3F) + 5;

		// Setup the proc redirects
		SE_GetString = (SE_GetStringProc)SE_GetStringAddr;
		DB_FindXAssetHeader = (DB_FindXAssetHeaderProc)DB_FindXAssetHeaderAddr;

		// ScaleformTranslate = Proc+0x24<uint32_t> = base vtable
		uint32_t ScaleformTranslateVTable = *(uint32_t*)((char*)ScaleformTranslateProc + 0x24);
		uint32_t ScaleformTranslateInfoAddr = *((uint32_t*)ScaleformTranslateVTable + 2);

		// ScaleformTranslateSetInfo
		auto ScaleformTranslateSetInfo = FindPattern("E8 ? ? ? ? 83 C4 ? 68 ? ? ? ? 8D 94 24 ? ? ? ? 52 6A ?", ScaleformTranslateInfoAddr, 0x1000);
		
		// Log heuristic info
#if LOGGER_MODE
		fprintf(LoggerHandle, "SE_GetStringAddr: 0x%X\nDB_FindXAssetHeaderAddr: 0x%X\n", SE_GetStringAddr, DB_FindXAssetHeaderAddr);
		fprintf(LoggerHandle, "ScaleformTranslateVTable: 0x%X\nScaleformTranslateInfoAddr: 0x%X\n", ScaleformTranslateVTable, ScaleformTranslateInfoAddr);
#endif

		// Only advance if we found the sub-pattern
		if (ScaleformTranslateSetInfo > 0)
		{
			auto TranslateSetInfoProc = (ScaleformTranslateSetInfo + ScaleformTranslateInfoAddr);

			// ScaleformTranslateSetResult = Proc+0x34<uint32_t> + Proc+0x33+5
			uint32_t ScaleformTranslateSetInfoRelAddr = *(uint32_t*)((char*)TranslateSetInfoProc + 0x34);
			uint32_t ScaleformTranslateSetInfoAddr = ScaleformTranslateSetInfoRelAddr + (TranslateSetInfoProc + 0x33) + 5;

			// Setup the proc redirects
			TranslateInfoTranslate = (TranslateInfoTranslateProc)ScaleformTranslateInfoAddr;
			TranslateInfoSetResult = (TranslateInfoSetResultProc)ScaleformTranslateSetInfoAddr;

			// Log other info
#if LOGGER_MODE
			fprintf(LoggerHandle, "TranslateSetInfoProc: 0x%X\nScaleformTranslateSetInfoAddr: 0x%X\n", TranslateSetInfoProc, ScaleformTranslateSetInfoAddr);
#endif

			// If we got here, we can apply the hooks
			JumpHook().Hook(SEHTranslateProc, (uintptr_t)&SEH_StringEd_GetStringHook);
			VTableHook().Hook(ScaleformTranslateVTable, (uintptr_t)&Scaleform_TranslateSetResultHook, 2);
		}
	}
}

DWORD WINAPI DecodeInitialize(LPVOID lpParam)
{
	// Load up the module information
	MainModule ApplicationModule;

	// Ensure that we are the main game
	if (Utils::HasEnding(ApplicationModule.GetModulePath(), "codomp_client_shipretail.exe"))
	{
		// Load translation database
		DecodeLoadTranslations(ApplicationModule);

		// Setup logger
#if LOGGER_MODE
		LoggerHandle = fopen("C:\\decodelog.txt", "w");
#endif

		// We must prepare the module, but, apply patches after the window loads (Unpacked)
		while (FindWindow(L"CODO", NULL) == NULL) Sleep(1);

		// Attempt to apply patches
		DecodeApplyPatches(ApplicationModule);
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
#endif
}