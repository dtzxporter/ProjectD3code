#pragma once

// Standard includes
#include <Windows.h>
#include <unordered_map>
#include <string>

// Log all key requests
#define LOGGER_MODE 0

// The entry point for D3code logic
DWORD WINAPI DecodeInitialize(LPVOID lpParam);
// Shutdown the api
void WINAPI DecodeShutdown();