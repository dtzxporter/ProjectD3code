// Standard includes
#include <Windows.h>

// Classes we need
#include "d3d9.h"
#include "valk.h"

// Original function addresses
Direct3DShaderValidatorCreate9Proc m_pDirect3DShaderValidatorCreate9;
PSGPErrorProc m_pPSGPError;
PSGPSampleTextureProc m_pPSGPSampleTexture;
D3DPERF_BeginEventProc m_pD3DPERF_BeginEvent;
D3DPERF_EndEventProc m_pD3DPERF_EndEvent;
D3DPERF_GetStatusProc m_pD3DPERF_GetStatus;
D3DPERF_QueryRepeatFrameProc m_pD3DPERF_QueryRepeatFrame;
D3DPERF_SetMarkerProc m_pD3DPERF_SetMarker;
D3DPERF_SetOptionsProc m_pD3DPERF_SetOptions;
D3DPERF_SetRegionProc m_pD3DPERF_SetRegion;
DebugSetLevelProc m_pDebugSetLevel;
DebugSetMuteProc m_pDebugSetMute;
Direct3D9EnableMaximizedWindowedModeShimProc m_pDirect3D9EnableMaximizedWindowedModeShim;
Direct3DCreate9Proc m_pDirect3DCreate9;
Direct3DCreate9ExProc m_pDirect3DCreate9Ex;

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	// The original directx runtime
	static HMODULE d3d9dll = nullptr;

	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		// Load original dll
		char Sys[MAX_PATH];
		GetSystemDirectoryA(Sys, MAX_PATH);
		strcat_s(Sys, "\\d3d9.dll");
		d3d9dll = LoadLibraryA(Sys);

		// Get original functions
		m_pDirect3DShaderValidatorCreate9 = (Direct3DShaderValidatorCreate9Proc)GetProcAddress(d3d9dll, "Direct3DShaderValidatorCreate9");
		m_pPSGPError = (PSGPErrorProc)GetProcAddress(d3d9dll, "PSGPError");
		m_pPSGPSampleTexture = (PSGPSampleTextureProc)GetProcAddress(d3d9dll, "PSGPSampleTexture");
		m_pD3DPERF_BeginEvent = (D3DPERF_BeginEventProc)GetProcAddress(d3d9dll, "D3DPERF_BeginEvent");
		m_pD3DPERF_EndEvent = (D3DPERF_EndEventProc)GetProcAddress(d3d9dll, "D3DPERF_EndEvent");
		m_pD3DPERF_GetStatus = (D3DPERF_GetStatusProc)GetProcAddress(d3d9dll, "D3DPERF_GetStatus");
		m_pD3DPERF_QueryRepeatFrame = (D3DPERF_QueryRepeatFrameProc)GetProcAddress(d3d9dll, "D3DPERF_QueryRepeatFrame");
		m_pD3DPERF_SetMarker = (D3DPERF_SetMarkerProc)GetProcAddress(d3d9dll, "D3DPERF_SetMarker");
		m_pD3DPERF_SetOptions = (D3DPERF_SetOptionsProc)GetProcAddress(d3d9dll, "D3DPERF_SetOptions");
		m_pD3DPERF_SetRegion = (D3DPERF_SetRegionProc)GetProcAddress(d3d9dll, "D3DPERF_SetRegion");
		m_pDebugSetLevel = (DebugSetLevelProc)GetProcAddress(d3d9dll, "DebugSetLevel");
		m_pDebugSetMute = (DebugSetMuteProc)GetProcAddress(d3d9dll, "DebugSetMute");
		m_pDirect3D9EnableMaximizedWindowedModeShim = (Direct3D9EnableMaximizedWindowedModeShimProc)GetProcAddress(d3d9dll, "Direct3D9EnableMaximizedWindowedModeShim");
		m_pDirect3DCreate9 = (Direct3DCreate9Proc)GetProcAddress(d3d9dll, "Direct3DCreate9");
		m_pDirect3DCreate9Ex = (Direct3DCreate9ExProc)GetProcAddress(d3d9dll, "Direct3DCreate9Ex");

		// Spawn our worker thread
		{
			int NullParam = 0;
			CreateThread(NULL, 0, ValkyrieInitialize, &NullParam, 0, NULL);
		}
		break;
	case DLL_PROCESS_DETACH:
		// Unload original module
		FreeLibrary(d3d9dll);
		// Shutdown valkyrie
		ValkyrieShutdown();
		break;
	}

	// Success
	return TRUE;
}

//
// Begin wrapper DirectX 9 functions
//

HRESULT WINAPI Direct3DShaderValidatorCreate9()
{
	return m_pDirect3DShaderValidatorCreate9();
}

HRESULT WINAPI PSGPError()
{
	return m_pPSGPError();
}

HRESULT WINAPI PSGPSampleTexture()
{
	return m_pPSGPSampleTexture();
}

int WINAPI D3DPERF_BeginEvent(D3DCOLOR col, LPCWSTR wszName)
{
	return m_pD3DPERF_BeginEvent(col, wszName);
}

int WINAPI D3DPERF_EndEvent()
{
	return m_pD3DPERF_EndEvent();
}

DWORD WINAPI D3DPERF_GetStatus()
{
	return m_pD3DPERF_GetStatus();
}

BOOL WINAPI D3DPERF_QueryRepeatFrame()
{
	return m_pD3DPERF_QueryRepeatFrame();
}

void WINAPI D3DPERF_SetMarker(D3DCOLOR col, LPCWSTR wszName)
{
	return m_pD3DPERF_SetMarker(col, wszName);
}

void WINAPI D3DPERF_SetOptions(DWORD dwOptions)
{
	return m_pD3DPERF_SetOptions(dwOptions);
}

void WINAPI D3DPERF_SetRegion(D3DCOLOR col, LPCWSTR wszName)
{
	return m_pD3DPERF_SetRegion(col, wszName);
}

HRESULT WINAPI DebugSetLevel(DWORD dw1)
{
	return m_pDebugSetLevel(dw1);
}

void WINAPI DebugSetMute()
{
	return m_pDebugSetMute();
}

void WINAPI Direct3D9EnableMaximizedWindowedModeShim()
{
	return m_pDirect3D9EnableMaximizedWindowedModeShim();
}

IDirect3D9 *WINAPI Direct3DCreate9(UINT SDKVersion)
{
	return m_pDirect3DCreate9(SDKVersion);
}

HRESULT WINAPI Direct3DCreate9Ex(UINT SDKVersion, IDirect3D9Ex **ppD3D)
{
	return m_pDirect3DCreate9Ex(SDKVersion, ppD3D);
}