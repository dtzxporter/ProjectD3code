#pragma once

#define INITGUID

#include <d3d9.h>

// DirectX 9 function definitions
typedef HRESULT(WINAPI *Direct3DShaderValidatorCreate9Proc)();
typedef HRESULT(WINAPI *PSGPErrorProc)();
typedef HRESULT(WINAPI *PSGPSampleTextureProc)();
typedef int(WINAPI *D3DPERF_BeginEventProc)(D3DCOLOR, LPCWSTR);
typedef int(WINAPI *D3DPERF_EndEventProc)();
typedef DWORD(WINAPI *D3DPERF_GetStatusProc)();
typedef BOOL(WINAPI *D3DPERF_QueryRepeatFrameProc)();
typedef void(WINAPI *D3DPERF_SetMarkerProc)(D3DCOLOR, LPCWSTR);
typedef void(WINAPI *D3DPERF_SetOptionsProc)(DWORD);
typedef void(WINAPI *D3DPERF_SetRegionProc)(D3DCOLOR, LPCWSTR);
typedef HRESULT(WINAPI *DebugSetLevelProc)(DWORD);
typedef void(WINAPI *DebugSetMuteProc)();
typedef void(WINAPI *Direct3D9EnableMaximizedWindowedModeShimProc)();
typedef IDirect3D9 *(WINAPI *Direct3DCreate9Proc)(UINT);
typedef HRESULT(WINAPI *Direct3DCreate9ExProc)(UINT, IDirect3D9Ex **);