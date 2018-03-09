#pragma once

// Standard includes
#include <Windows.h>
#include <string>

// The entry point for Valkyrie logic
DWORD WINAPI ValkyrieInitialize(LPVOID lpParam);
// Shutdown the api
void WINAPI ValkyrieShutdown();