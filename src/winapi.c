#include "dr_api.h"
#include "datatypes.h"
#include "drwrap.h"
#include <stddef.h>
#include "hashtable.h"
#include <windows.h>
#include <mmsystem.h>
#include <d3d9.h>
#include <dsound.h>
#include <dinput.h>
#include "winapi.h"
#include "synchro.h"
#include "bbtrace_core.h"

static void sym_info_item_free(void *entry);

static void after_Direct3DCreate9(void *wrapcxt, void *user_data);
static void after_IDirect3D9_CreateDevice(void *wrapcxt, void *user_data);
static void after_IDirect3DDevice9_GetBackBuffer(void *wrapcxt, void *user_data);
static void after_IDirect3DDevice9_CreateTexture(void *wrapcxt, void *user_data);
static void after_IDirect3DDevice9_CreateVertexDeclaration(void *wrapcxt, void *user_data);
static void after_IDirect3DDevice9_CreatePixelShader(void *wrapcxt, void *user_data);
static void after_IDirect3DDevice9_CreateVertexShader(void *wrapcxt, void *user_data);
static void after_IDirect3DDevice9_CreateVertexBuffer(void *wrapcxt, void *user_data);
static void after_IDirect3DDevice9_CreateIndexBuffer(void *wrapcxt, void *user_data);
static void after_IDirect3DDevice9_CreateDepthStencilSurface(void *wrapcxt, void *user_data);
static void after_IDirect3DDevice9_EndStateBlock(void *wrapcxt, void *user_data);

static void before_CreateThread(void *wrapcxt, void *user_data);
static void after_CreateThread(void *wrapcxt, void *user_data);
static void after_ReadFile(void *wrapcxt, void *user_data);
static void after_InitializeCriticalSection(void *wrapcxt, void *user_data);
static void after_EnterCriticalSection(void *wrapcxt, void *user_data);
static void before_LeaveCriticalSection(void *wrapcxt, void *user_data);
static void after_CreateMutex(void *wrapcxt, void *user_data);
static void after_CreateEvent(void *wrapcxt, void *user_data);
static void before_ReleaseMutex(void *wrapcxt, void *user_data);
static void before_ResetEvent(void *wrapcxt, void *user_data);
static void after_WaitForSingleObject(void *wrapcxt, void *user_data);
static void after_CloseHandle(void *wrapcxt, void *user_data);
static void after_VirtualProtect(void *wrapcxt, void *user_data);
static void after_VirtualAlloc(void *wrapcxt, void *user_data);

static void *IDirect3D9_lpVtbl = 0;
static void *IDirect3DDevice9_lpVtbl = 0;
static void *IDirect3DVertexDeclaration9_lpVtbl = 0;
static void *IDirect3DVertexShader9_lpVtbl = 0;
static void *IDirect3DVertexBuffer9_lpVtbl = 0;
static void *IDirect3DIndexBuffer9_lpVtbl = 0;
static void *IDirect3DPixelShader9_lpVtbl = 0;
static void *IDirect3DStateBlock9_lpVtbl = 0;
static void *IDirect3DSurface9_lpVtbl = 0;
static void *IDirect3DTexture9_lpVtbl = 0;

static const winapi_info_t winapi_infos[] = {
    {KERNEL32_DLL, "CreateFileA", 7, {A_LPSTR}, A_HANDLE},
    {KERNEL32_DLL, "CloseHandle", 1, {A_HANDLE}, A_BOOL, NULL, after_CloseHandle},
    {KERNEL32_DLL, "GetFileSize", 2, {A_HANDLE, A_LPDWORD}, A_DWORD},
    {KERNEL32_DLL, "ReadFile", 5, {A_HANDLE, A_LPVOID, A_DWORD, A_LPDWORD}, A_BOOL, NULL, after_ReadFile},
    {KERNEL32_DLL, "WriteFile", 5, {A_HANDLE, A_LPVOID, A_DWORD, A_LPDWORD}, A_BOOL},
    {KERNEL32_DLL, "VirtualProtect", 4, {A_LPVOID, A_DWORD, A_DWORD, A_LPDWORD}, A_BOOL, NULL, after_VirtualProtect},
    {KERNEL32_DLL, "VirtualAlloc", 4, {A_LPVOID, A_DWORD, A_DWORD, A_DWORD}, A_LPVOID, NULL, after_VirtualAlloc},
    {KERNEL32_DLL, "SetEvent", 1, {A_HANDLE}, A_BOOL, before_ResetEvent, NULL},
    {KERNEL32_DLL, "ResetEvent", 1, {A_HANDLE}, A_BOOL, before_ResetEvent, NULL},
    {KERNEL32_DLL, "CreateEventA", 4, {A_LPVOID, A_BOOL, A_BOOL, A_LPSTR}, A_HANDLE, NULL, after_CreateEvent},
    {KERNEL32_DLL, "CreateMutexA", 3, {A_LPVOID, A_BOOL, A_LPSTR}, A_HANDLE, NULL, after_CreateMutex},
    {KERNEL32_DLL, "ReleaseMutex", 1, {A_HANDLE}, A_BOOL, before_ReleaseMutex, NULL},
    {KERNEL32_DLL, "WaitForSingleObject", 2, {A_HANDLE, A_DWORD}, A_DWORD, NULL, after_WaitForSingleObject},
    {KERNEL32_DLL, "HeapCreate", 3, {A_DWORD, A_DWORD, A_DWORD}, A_HANDLE},
    {KERNEL32_DLL, "HeapFree", 3, {A_HANDLE, A_DWORD, A_LPVOID}, A_BOOL},
    {KERNEL32_DLL, "CreateThread", 6, {A_DWORD, A_DWORD, A_DWORD, A_LPVOID, A_DWORD, A_LPDWORD}, A_HANDLE, before_CreateThread, after_CreateThread},
    {KERNEL32_DLL, "ResumeThread", 1, {A_HANDLE}, A_DWORD, NULL, NULL},
    {KERNEL32_DLL, "SuspendThread", 1, {A_HANDLE}, A_DWORD, NULL, NULL},
    {KERNEL32_DLL, "InitializeCriticalSectionAndSpinCount", 2, {A_LPVOID, A_DWORD}, A_BOOL, NULL, after_InitializeCriticalSection},

    {D3D9_DLL, "Direct3DCreate9", 1, {A_DWORD}, A_LPVOID, NULL, after_Direct3DCreate9},
    {D3D9_DLL, "IDirect3D9_QueryInterface", 3, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3D9_AddRef", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3D9_Release", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3D9_RegisterSoftwareDevice", 2, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3D9_GetAdapterCount", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3D9_GetAdapterIdentifier", 4, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3D9_GetAdapterModeCount", 3, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3D9_EnumAdapterModes", 5, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3D9_GetAdapterDisplayMode", 3, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3D9_CheckDeviceType", 6, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3D9_CheckDeviceFormat", 7, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3D9_CheckDeviceMultiSampleType", 7, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3D9_CheckDepthStencilMatch", 6, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3D9_CheckDeviceFormatConversion", 5, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3D9_GetDeviceCaps", 4, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3D9_GetAdapterMonitor", 2, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3D9_CreateDevice", 7, {A_LPVOID, A_DWORD, A_DWORD, A_HANDLE, A_DWORD, A_LPVOID, A_LPPVOID}, A_HRESULT, NULL, after_IDirect3D9_CreateDevice},

    {D3D9_DLL, "IDirect3DDevice9_QueryInterface", 3, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_AddRef", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_Release", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_TestCooperativeLevel", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetAvailableTextureMem", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_EvictManagedResources", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetDirect3D", 2, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetDeviceCaps", 2, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetDisplayMode", 3, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetCreationParameters", 2, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetCursorProperties", 4, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetCursorPosition", 4, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_ShowCursor", 2, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_CreateAdditionalSwapChain", 3, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetSwapChain", 3, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetNumberOfSwapChains", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_Reset", 2, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_Present", 5, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetBackBuffer", 5, {A_LPVOID}, A_HRESULT, NULL, after_IDirect3DDevice9_GetBackBuffer},
    {D3D9_DLL, "IDirect3DDevice9_GetRasterStatus", 3, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetDialogBoxMode", 2, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetGammaRamp", 4, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetGammaRamp", 3, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_CreateTexture", 9, {A_LPVOID}, A_HRESULT, NULL, after_IDirect3DDevice9_CreateTexture},
    {D3D9_DLL, "IDirect3DDevice9_CreateVolumeTexture", 10, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_CreateCubeTexture", 8, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_CreateVertexBuffer", 7, {A_LPVOID}, A_HRESULT, NULL, after_IDirect3DDevice9_CreateVertexBuffer},
    {D3D9_DLL, "IDirect3DDevice9_CreateIndexBuffer", 7, {A_LPVOID}, A_HRESULT, NULL, after_IDirect3DDevice9_CreateIndexBuffer},
    {D3D9_DLL, "IDirect3DDevice9_CreateRenderTarget", 9, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_CreateDepthStencilSurface", 9, {A_LPVOID}, A_HRESULT, NULL, after_IDirect3DDevice9_CreateDepthStencilSurface},
    {D3D9_DLL, "IDirect3DDevice9_UpdateSurface", 5, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_UpdateTexture", 3, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetRenderTargetData", 3, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetFrontBufferData", 3, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_StretchRect", 6, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_ColorFill", 4, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_CreateOffscreenPlainSurface", 7, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetRenderTarget", 3, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetRenderTarget", 3, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetDepthStencilSurface", 2, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetDepthStencilSurface", 2, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_BeginScene", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_EndScene", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_Clear", 7, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetTransform", 3, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetTransform", 3, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_MultiplyTransform", 3, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetViewport", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetViewport", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetMaterial", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetMaterial", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetLight", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetLight", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_LightEnable", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetLightEnable", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetClipPlane", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetClipPlane", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetRenderState", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetRenderState", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_CreateStateBlock", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_BeginStateBlock", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_EndStateBlock", 2, {A_LPVOID}, A_HRESULT, NULL, after_IDirect3DDevice9_EndStateBlock},
    {D3D9_DLL, "IDirect3DDevice9_SetClipStatus", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetClipStatus", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetTexture", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetTexture", 3, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetTextureStageState", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetTextureStageState", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetSamplerState", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetSamplerState", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_ValidateDevice", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetPaletteEntries", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetPaletteEntries", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetCurrentTexturePalette", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetCurrentTexturePalette", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetScissorRect", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetScissorRect", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetSoftwareVertexProcessing", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetSoftwareVertexProcessing", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetNPatchMode", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetNPatchMode", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_DrawPrimitive", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_DrawIndexedPrimitive", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_DrawPrimitiveUP", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_DrawIndexedPrimitiveUP", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_ProcessVertices", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_CreateVertexDeclaration", 3, {A_LPVOID}, A_HRESULT, NULL, after_IDirect3DDevice9_CreateVertexDeclaration},
    {D3D9_DLL, "IDirect3DDevice9_SetVertexDeclaration", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetVertexDeclaration", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetFVF", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetFVF", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_CreateVertexShader", 3, {A_LPVOID}, A_HRESULT, NULL, after_IDirect3DDevice9_CreateVertexShader},
    {D3D9_DLL, "IDirect3DDevice9_SetVertexShader", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetVertexShader", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetVertexShaderConstantF", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetVertexShaderConstantF", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetVertexShaderConstantI", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetVertexShaderConstantI", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetVertexShaderConstantB", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetVertexShaderConstantB", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetStreamSource", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetStreamSource", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetStreamSourceFreq", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetStreamSourceFreq", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetIndices", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetIndices", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_CreatePixelShader", 3, {A_LPVOID}, A_HRESULT, NULL, after_IDirect3DDevice9_CreatePixelShader},
    {D3D9_DLL, "IDirect3DDevice9_SetPixelShader", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetPixelShader", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetPixelShaderConstantF", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetPixelShaderConstantF", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetPixelShaderConstantI", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetPixelShaderConstantI", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_SetPixelShaderConstantB", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_GetPixelShaderConstantB", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_DrawRectPatch", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_DrawTriPatch", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_DeletePatch", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DDevice9_CreateQuery", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},

    {D3D9_DLL, "IDirect3DSurface9_QueryInterface", 3, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DSurface9_AddRef", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DSurface9_Release", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DSurface9_GetDevice", 2, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DSurface9_SetPrivateData", 5, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DSurface9_GetPrivateData", 4, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DSurface9_FreePrivateData", 2, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DSurface9_SetPriority", 2, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DSurface9_GetPriority", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DSurface9_PreLoad", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DSurface9_GetType", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DSurface9_GetContainer", 3, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DSurface9_GetDesc", 2, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DSurface9_LockRect", 4, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DSurface9_UnlockRect", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DSurface9_GetDC", 2, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DSurface9_ReleaseDC", 2, {A_LPVOID}, A_HRESULT, NULL, NULL},

    {D3D9_DLL, "IDirect3DTexture9_QueryInterface", 3, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DTexture9_AddRef", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DTexture9_Release", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DTexture9_GetDevice", 2, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DTexture9_SetPrivateData", 5, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DTexture9_GetPrivateData", 4, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DTexture9_FreePrivateData", 2, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DTexture9_SetPriority", 2, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DTexture9_GetPriority", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DTexture9_PreLoad", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DTexture9_GetType", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DTexture9_SetLOD", 2, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DTexture9_GetLOD", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DTexture9_GetLevelCount", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DTexture9_SetAutoGenFilterType", 2, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DTexture9_GetAutoGenFilterType", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DTexture9_GenerateMipSubLevels", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DTexture9_GetLevelDesc", 3, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DTexture9_GetSurfaceLevel", 3, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DTexture9_LockRect", 5, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DTexture9_UnlockRect", 2, {A_LPVOID}, A_HRESULT, NULL, NULL},
    {D3D9_DLL, "IDirect3DTexture9_AddDirtyRect", 2, {A_LPVOID}, A_HRESULT, NULL, NULL},

    {D3D9_DLL, "IDirect3DVertexDeclaration9_QueryInterface", 3, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DVertexDeclaration9_AddRef", 1, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DVertexDeclaration9_Release", 1, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DVertexDeclaration9_GetDevice", 2, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DVertexDeclaration9_GetDeclaration", 3, {A_LPVOID}, A_HRESULT},

    {D3D9_DLL, "IDirect3DPixelShader9_QueryInterface", 3, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DPixelShader9_AddRef", 1, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DPixelShader9_Release", 1, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DPixelShader9_GetDevice", 2, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DPixelShader9_GetFunction", 3, {A_LPVOID}, A_HRESULT},

    {D3D9_DLL, "IDirect3DVertexShader9_QueryInterface", 3, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DVertexShader9_AddRef", 1, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DVertexShader9_Release", 1, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DVertexShader9_GetDevice", 2, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DVertexShader9_GetFunction", 3, {A_LPVOID}, A_HRESULT},

    {D3D9_DLL, "IDirect3DVertexBuffer9_QueryInterface", 3, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DVertexBuffer9_AddRef", 1, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DVertexBuffer9_Release", 1, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DVertexBuffer9_GetDevice", 2, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DVertexBuffer9_SetPrivateData", 5, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DVertexBuffer9_GetPrivateData", 4, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DVertexBuffer9_FreePrivateData", 2, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DVertexBuffer9_SetPriority", 2, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DVertexBuffer9_GetPriority", 1, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DVertexBuffer9_PreLoad", 1, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DVertexBuffer9_GetType", 1, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DVertexBuffer9_Lock", 5, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DVertexBuffer9_Unlock", 1, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DVertexBuffer9_GetDesc", 2, {A_LPVOID}, A_HRESULT},

    {D3D9_DLL, "IDirect3DIndexBuffer9_QueryInterface", 3, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DIndexBuffer9_AddRef", 1, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DIndexBuffer9_Release", 1, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DIndexBuffer9_GetDevice", 2, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DIndexBuffer9_SetPrivateData", 5, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DIndexBuffer9_GetPrivateData", 4, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DIndexBuffer9_FreePrivateData", 2, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DIndexBuffer9_SetPriority", 2, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DIndexBuffer9_GetPriority", 1, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DIndexBuffer9_PreLoad", 1, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DIndexBuffer9_GetType", 1, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DIndexBuffer9_Lock", 5, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DIndexBuffer9_Unlock", 1, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DIndexBuffer9_GetDesc", 2, {A_LPVOID}, A_HRESULT},

    {D3D9_DLL, "IDirect3DStateBlock9_QueryInterface", 3, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DStateBlock9_AddRef", 1, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DStateBlock9_Release", 1, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DStateBlock9_GetDevice", 2, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DStateBlock9_Capture", 1, {A_LPVOID}, A_HRESULT},
    {D3D9_DLL, "IDirect3DStateBlock9_Apply", 1, {A_LPVOID}, A_HRESULT},

 // {WINMM_DLL, "timeSetEvent", 5, {A_DWORD, A_DWORD, A_LPVOID, A_DWORD, A_DWORD}, A_HRESULT},

 // {D3D9_DLL, "IDirect3DTexture9_", 1, {A_LPVOID}, A_HRESULT, NULL, NULL},

    {NTDLL_DLL, "RtlAllocateHeap", 3, {A_HANDLE, A_DWORD, A_DWORD}, A_LPVOID},
    {NTDLL_DLL, "RtlEnterCriticalSection", 1, {A_LPVOID}, A_VOID, NULL, after_EnterCriticalSection},
    {NTDLL_DLL, "RtlLeaveCriticalSection", 1, {A_LPVOID}, A_VOID, before_LeaveCriticalSection, NULL},
    {NTDLL_DLL, "RtlDeleteCriticalSection", 1, {A_LPVOID}, A_VOID},
    {NTDLL_DLL, "RtlInitializeCriticalSection",  1, {A_LPVOID}, A_VOID, NULL, after_InitializeCriticalSection}
};

static hashtable_t sym_info_table;
static hashtable_t winapi_info_table;

void winapi_init(void)
{
    hashtable_init_ex(&sym_info_table, 6, HASH_INTPTR, false, false, sym_info_item_free, NULL, NULL);

    hashtable_init_ex(&winapi_info_table, 8, HASH_STRING, false, false, NULL, NULL, NULL);
    for (int i = 0; i < (sizeof(winapi_infos)/sizeof(*winapi_infos)); i++) {
        hashtable_add(&winapi_info_table,
            (void*)winapi_infos[i].sym_name, (void*)&winapi_infos[i]);
    }
}

void
winapi_exit(void)
{
    hashtable_delete(&winapi_info_table);
    hashtable_delete(&sym_info_table);
}

winapi_info_t *
winapi_get(const char *sym_name)
{
    return (winapi_info_t*)hashtable_lookup(&winapi_info_table, (void*)sym_name);
}

static void
sym_info_item_free(void *entry)
{
    dr_global_free(entry, sizeof(sym_info_item_t));
}

static void
add_symbol_com(app_pc func, uint shared_dll, const char *sym_name, wrap_lib_user_t *p_data)
{
    sym_info_item_t *sym_info;

    sym_info = syminfo_get(func);
    if (sym_info) return;

    //if (drwrap_is_wrapped(func, lib_entry, lib_exit)) return;

    sym_info = dr_global_alloc(sizeof(sym_info_item_t));
    sym_info->sym.name = sym_name;
    sym_info->sym.addr = func;
    sym_info->sym.ordinal = 0;
    sym_info->shared_dll = shared_dll;
    sym_info->winapi_info = winapi_get(sym_name);

    syminfo_add(func, sym_info);

    drwrap_wrap_ex(func, lib_entry, lib_exit,
        0, DRWRAP_UNWIND_ON_EXCEPTION | DRWRAP_CALLCONV_STDCALL);
}

#define ADD_SYMBOL(SHARED_DLL, P, IFACE_NAME, FUNC_NAME) \
    add_symbol_com((app_pc) P->lpVtbl->FUNC_NAME, \
      SHARED_DLL, \
      #IFACE_NAME "_" #FUNC_NAME, \
      p_data);

static void
after_Direct3DCreate9(void *wrapcxt, void *user_data)
{
    wrap_lib_user_t *p_data = user_data;

    LPDIRECT3D9 d3d = p_data->retval;
    if (!d3d) return;
    if (IDirect3D9_lpVtbl) {
        DR_ASSERT(IDirect3D9_lpVtbl == d3d->lpVtbl);
        return;
    } else
        IDirect3D9_lpVtbl = d3d->lpVtbl;

    ADD_SYMBOL(D3D9_DLL, d3d, IDirect3D9, QueryInterface)
    ADD_SYMBOL(D3D9_DLL, d3d, IDirect3D9, AddRef)
    ADD_SYMBOL(D3D9_DLL, d3d, IDirect3D9, Release)
    ADD_SYMBOL(D3D9_DLL, d3d, IDirect3D9, RegisterSoftwareDevice)
    ADD_SYMBOL(D3D9_DLL, d3d, IDirect3D9, GetAdapterCount)
    ADD_SYMBOL(D3D9_DLL, d3d, IDirect3D9, GetAdapterIdentifier)
    ADD_SYMBOL(D3D9_DLL, d3d, IDirect3D9, GetAdapterModeCount)
    ADD_SYMBOL(D3D9_DLL, d3d, IDirect3D9, EnumAdapterModes)
    ADD_SYMBOL(D3D9_DLL, d3d, IDirect3D9, GetAdapterDisplayMode)
    ADD_SYMBOL(D3D9_DLL, d3d, IDirect3D9, CheckDeviceType)
    ADD_SYMBOL(D3D9_DLL, d3d, IDirect3D9, CheckDeviceFormat)
    ADD_SYMBOL(D3D9_DLL, d3d, IDirect3D9, CheckDeviceMultiSampleType)
    ADD_SYMBOL(D3D9_DLL, d3d, IDirect3D9, CheckDepthStencilMatch)
    ADD_SYMBOL(D3D9_DLL, d3d, IDirect3D9, CheckDeviceFormatConversion)
    ADD_SYMBOL(D3D9_DLL, d3d, IDirect3D9, GetDeviceCaps)
    ADD_SYMBOL(D3D9_DLL, d3d, IDirect3D9, GetAdapterMonitor)
    ADD_SYMBOL(D3D9_DLL, d3d, IDirect3D9, CreateDevice)
}

static void
after_IDirect3D9_CreateDevice(void *wrapcxt, void *user_data)
{
    wrap_lib_user_t *p_data = user_data;

    LPDIRECT3DDEVICE9 d3ddev = *(void **)p_data->args[6];
    if (!d3ddev) return;
    if (IDirect3DDevice9_lpVtbl) {
        DR_ASSERT(IDirect3DDevice9_lpVtbl == d3ddev->lpVtbl);
        return;
    } else
        IDirect3DDevice9_lpVtbl = d3ddev->lpVtbl;

    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, QueryInterface)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, AddRef)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, Release)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, TestCooperativeLevel)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetAvailableTextureMem)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, EvictManagedResources)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetDirect3D)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetDeviceCaps)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetDisplayMode)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetCreationParameters)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetCursorProperties)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetCursorPosition)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, ShowCursor)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, CreateAdditionalSwapChain)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetSwapChain)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetNumberOfSwapChains)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, Reset)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, Present)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetBackBuffer)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetRasterStatus)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetDialogBoxMode)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetGammaRamp)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetGammaRamp)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, CreateTexture)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, CreateVolumeTexture)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, CreateCubeTexture)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, CreateVertexBuffer)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, CreateIndexBuffer)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, CreateRenderTarget)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, CreateDepthStencilSurface)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, UpdateSurface)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, UpdateTexture)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetRenderTargetData)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetFrontBufferData)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, StretchRect)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, ColorFill)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, CreateOffscreenPlainSurface)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetRenderTarget)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetRenderTarget)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetDepthStencilSurface)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetDepthStencilSurface)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, BeginScene)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, EndScene)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, Clear)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetTransform)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetTransform)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, MultiplyTransform)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetViewport)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetViewport)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetMaterial)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetMaterial)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetLight)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetLight)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, LightEnable)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetLightEnable)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetClipPlane)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetClipPlane)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetRenderState)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetRenderState)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, CreateStateBlock)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, BeginStateBlock)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, EndStateBlock)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetClipStatus)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetClipStatus)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetTexture)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetTexture)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetTextureStageState)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetTextureStageState)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetSamplerState)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetSamplerState)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, ValidateDevice)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetPaletteEntries)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetPaletteEntries)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetCurrentTexturePalette)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetCurrentTexturePalette)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetScissorRect)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetScissorRect)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetSoftwareVertexProcessing)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetSoftwareVertexProcessing)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetNPatchMode)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetNPatchMode)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, DrawPrimitive)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, DrawIndexedPrimitive)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, DrawPrimitiveUP)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, DrawIndexedPrimitiveUP)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, ProcessVertices)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, CreateVertexDeclaration)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetVertexDeclaration)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetVertexDeclaration)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetFVF)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetFVF)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, CreateVertexShader)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetVertexShader)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetVertexShader)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetVertexShaderConstantF)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetVertexShaderConstantF)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetVertexShaderConstantI)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetVertexShaderConstantI)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetVertexShaderConstantB)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetVertexShaderConstantB)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetStreamSource)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetStreamSource)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetStreamSourceFreq)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetStreamSourceFreq)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetIndices)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetIndices)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, CreatePixelShader)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetPixelShader)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetPixelShader)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetPixelShaderConstantF)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetPixelShaderConstantF)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetPixelShaderConstantI)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetPixelShaderConstantI)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, SetPixelShaderConstantB)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, GetPixelShaderConstantB)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, DrawRectPatch)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, DrawTriPatch)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, DeletePatch)
    ADD_SYMBOL(D3D9_DLL, d3ddev, IDirect3DDevice9, CreateQuery)
}

static void
after_IDirect3DDevice9_GetBackBuffer(void *wrapcxt, void *user_data)
{
    wrap_lib_user_t *p_data = user_data;

    LPDIRECT3DSURFACE9 d3ds = *(void **)p_data->args[4];
    if (!d3ds) return;
    if (IDirect3DSurface9_lpVtbl) {
        DR_ASSERT(IDirect3DSurface9_lpVtbl == d3ds->lpVtbl);
        return;
    } else
        IDirect3DSurface9_lpVtbl = d3ds->lpVtbl;

    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, QueryInterface)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, AddRef)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, Release)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, GetDevice)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, SetPrivateData)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, GetPrivateData)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, FreePrivateData)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, SetPriority)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, GetPriority)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, PreLoad)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, GetType)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, GetContainer)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, GetDesc)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, LockRect)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, UnlockRect)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, GetDC)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, ReleaseDC)
}

static void
after_IDirect3DDevice9_CreateTexture(void *wrapcxt, void *user_data)
{
    wrap_lib_user_t *p_data = user_data;

    LPDIRECT3DTEXTURE9 d3dtex = *(void **)p_data->args[7];
    if (!d3dtex) return;
    if (IDirect3DTexture9_lpVtbl) {
        DR_ASSERT(IDirect3DTexture9_lpVtbl == d3dtex->lpVtbl);
        return;
    } else
        IDirect3DTexture9_lpVtbl = d3dtex->lpVtbl;

    ADD_SYMBOL(D3D9_DLL, d3dtex, IDirect3DTexture9, QueryInterface)
    ADD_SYMBOL(D3D9_DLL, d3dtex, IDirect3DTexture9, AddRef)
    ADD_SYMBOL(D3D9_DLL, d3dtex, IDirect3DTexture9, Release)
    ADD_SYMBOL(D3D9_DLL, d3dtex, IDirect3DTexture9, GetDevice)
    ADD_SYMBOL(D3D9_DLL, d3dtex, IDirect3DTexture9, SetPrivateData)
    ADD_SYMBOL(D3D9_DLL, d3dtex, IDirect3DTexture9, GetPrivateData)
    ADD_SYMBOL(D3D9_DLL, d3dtex, IDirect3DTexture9, FreePrivateData)
    ADD_SYMBOL(D3D9_DLL, d3dtex, IDirect3DTexture9, SetPriority)
    ADD_SYMBOL(D3D9_DLL, d3dtex, IDirect3DTexture9, GetPriority)
    ADD_SYMBOL(D3D9_DLL, d3dtex, IDirect3DTexture9, PreLoad)
    ADD_SYMBOL(D3D9_DLL, d3dtex, IDirect3DTexture9, GetType)
    ADD_SYMBOL(D3D9_DLL, d3dtex, IDirect3DTexture9, SetLOD)
    ADD_SYMBOL(D3D9_DLL, d3dtex, IDirect3DTexture9, GetLOD)
    ADD_SYMBOL(D3D9_DLL, d3dtex, IDirect3DTexture9, GetLevelCount)
    ADD_SYMBOL(D3D9_DLL, d3dtex, IDirect3DTexture9, SetAutoGenFilterType)
    ADD_SYMBOL(D3D9_DLL, d3dtex, IDirect3DTexture9, GetAutoGenFilterType)
    ADD_SYMBOL(D3D9_DLL, d3dtex, IDirect3DTexture9, GenerateMipSubLevels)
    ADD_SYMBOL(D3D9_DLL, d3dtex, IDirect3DTexture9, GetLevelDesc)
    ADD_SYMBOL(D3D9_DLL, d3dtex, IDirect3DTexture9, GetSurfaceLevel)
    ADD_SYMBOL(D3D9_DLL, d3dtex, IDirect3DTexture9, LockRect)
    ADD_SYMBOL(D3D9_DLL, d3dtex, IDirect3DTexture9, UnlockRect)
    ADD_SYMBOL(D3D9_DLL, d3dtex, IDirect3DTexture9, AddDirtyRect)
}

static void
after_IDirect3DDevice9_CreateVertexDeclaration(void *wrapcxt, void *user_data)
{
    wrap_lib_user_t *p_data = user_data;

    LPDIRECT3DVERTEXDECLARATION9 d3dvexdecl = *(void **)p_data->args[2];
    if (!d3dvexdecl) return;
    if (IDirect3DVertexDeclaration9_lpVtbl) {
        DR_ASSERT(IDirect3DVertexDeclaration9_lpVtbl == d3dvexdecl->lpVtbl);
        return;
    } else
        IDirect3DVertexDeclaration9_lpVtbl = d3dvexdecl->lpVtbl;

    ADD_SYMBOL(D3D9_DLL, d3dvexdecl, IDirect3DVertexDeclaration9, QueryInterface)
    ADD_SYMBOL(D3D9_DLL, d3dvexdecl, IDirect3DVertexDeclaration9, AddRef)
    ADD_SYMBOL(D3D9_DLL, d3dvexdecl, IDirect3DVertexDeclaration9, Release)
    ADD_SYMBOL(D3D9_DLL, d3dvexdecl, IDirect3DVertexDeclaration9, GetDevice)
    ADD_SYMBOL(D3D9_DLL, d3dvexdecl, IDirect3DVertexDeclaration9, GetDeclaration)
}

static void
after_IDirect3DDevice9_CreatePixelShader(void *wrapcxt, void *user_data)
{
    wrap_lib_user_t *p_data = user_data;

    LPDIRECT3DPIXELSHADER9 d3dpixshader = *(void **)p_data->args[2];
    if (!d3dpixshader) return;
    if (IDirect3DPixelShader9_lpVtbl) {
        DR_ASSERT(IDirect3DPixelShader9_lpVtbl == d3dpixshader->lpVtbl);
        return;
    } else
        IDirect3DPixelShader9_lpVtbl = d3dpixshader->lpVtbl;

    ADD_SYMBOL(D3D9_DLL, d3dpixshader, IDirect3DPixelShader9, QueryInterface)
    ADD_SYMBOL(D3D9_DLL, d3dpixshader, IDirect3DPixelShader9, AddRef)
    ADD_SYMBOL(D3D9_DLL, d3dpixshader, IDirect3DPixelShader9, Release)
    ADD_SYMBOL(D3D9_DLL, d3dpixshader, IDirect3DPixelShader9, GetDevice)
    ADD_SYMBOL(D3D9_DLL, d3dpixshader, IDirect3DPixelShader9, GetFunction)
}

static void
after_IDirect3DDevice9_CreateVertexShader(void *wrapcxt, void *user_data)
{
    wrap_lib_user_t *p_data = user_data;

    LPDIRECT3DVERTEXSHADER9 d3dvexshader = *(void **)p_data->args[2];
    if (!d3dvexshader) return;
    if (IDirect3DVertexShader9_lpVtbl) {
        DR_ASSERT(IDirect3DVertexShader9_lpVtbl == d3dvexshader->lpVtbl);
        return;
    } else
        IDirect3DVertexShader9_lpVtbl = d3dvexshader->lpVtbl;

    ADD_SYMBOL(D3D9_DLL, d3dvexshader, IDirect3DVertexShader9, QueryInterface)
    ADD_SYMBOL(D3D9_DLL, d3dvexshader, IDirect3DVertexShader9, AddRef)
    ADD_SYMBOL(D3D9_DLL, d3dvexshader, IDirect3DVertexShader9, Release)
    ADD_SYMBOL(D3D9_DLL, d3dvexshader, IDirect3DVertexShader9, GetDevice)
    ADD_SYMBOL(D3D9_DLL, d3dvexshader, IDirect3DVertexShader9, GetFunction)
}

static void
after_IDirect3DDevice9_CreateVertexBuffer(void *wrapcxt, void *user_data)
{
    wrap_lib_user_t *p_data = user_data;

    LPDIRECT3DVERTEXBUFFER9 d3dvexbuf = *(void **)p_data->args[5];
    if (!d3dvexbuf) return;
    if (IDirect3DVertexBuffer9_lpVtbl) {
        // DR_ASSERT(IDirect3DVertexBuffer9_lpVtbl == d3dvexbuf->lpVtbl);
        // return;
    } else
        IDirect3DVertexBuffer9_lpVtbl = d3dvexbuf->lpVtbl;

    ADD_SYMBOL(D3D9_DLL, d3dvexbuf, IDirect3DVertexBuffer9, QueryInterface)
    ADD_SYMBOL(D3D9_DLL, d3dvexbuf, IDirect3DVertexBuffer9, AddRef)
    ADD_SYMBOL(D3D9_DLL, d3dvexbuf, IDirect3DVertexBuffer9, Release)
    ADD_SYMBOL(D3D9_DLL, d3dvexbuf, IDirect3DVertexBuffer9, GetDevice)
    ADD_SYMBOL(D3D9_DLL, d3dvexbuf, IDirect3DVertexBuffer9, SetPrivateData)
    ADD_SYMBOL(D3D9_DLL, d3dvexbuf, IDirect3DVertexBuffer9, GetPrivateData)
    ADD_SYMBOL(D3D9_DLL, d3dvexbuf, IDirect3DVertexBuffer9, FreePrivateData)
    ADD_SYMBOL(D3D9_DLL, d3dvexbuf, IDirect3DVertexBuffer9, SetPriority)
    ADD_SYMBOL(D3D9_DLL, d3dvexbuf, IDirect3DVertexBuffer9, GetPriority)
    ADD_SYMBOL(D3D9_DLL, d3dvexbuf, IDirect3DVertexBuffer9, PreLoad)
    ADD_SYMBOL(D3D9_DLL, d3dvexbuf, IDirect3DVertexBuffer9, GetType)
    ADD_SYMBOL(D3D9_DLL, d3dvexbuf, IDirect3DVertexBuffer9, Lock)
    ADD_SYMBOL(D3D9_DLL, d3dvexbuf, IDirect3DVertexBuffer9, Unlock)
    ADD_SYMBOL(D3D9_DLL, d3dvexbuf, IDirect3DVertexBuffer9, GetDesc)
}

static void
after_IDirect3DDevice9_CreateIndexBuffer(void *wrapcxt, void *user_data)
{
    wrap_lib_user_t *p_data = user_data;

    LPDIRECT3DINDEXBUFFER9 d3didxbuf = *(void **)p_data->args[5];
    if (!d3didxbuf) return;
    if (IDirect3DIndexBuffer9_lpVtbl) {
        DR_ASSERT(IDirect3DIndexBuffer9_lpVtbl == d3didxbuf->lpVtbl);
        return;
    } else
        IDirect3DIndexBuffer9_lpVtbl = d3didxbuf->lpVtbl;

    ADD_SYMBOL(D3D9_DLL, d3didxbuf, IDirect3DIndexBuffer9, QueryInterface)
    ADD_SYMBOL(D3D9_DLL, d3didxbuf, IDirect3DIndexBuffer9, AddRef)
    ADD_SYMBOL(D3D9_DLL, d3didxbuf, IDirect3DIndexBuffer9, Release)
    ADD_SYMBOL(D3D9_DLL, d3didxbuf, IDirect3DIndexBuffer9, GetDevice)
    ADD_SYMBOL(D3D9_DLL, d3didxbuf, IDirect3DIndexBuffer9, SetPrivateData)
    ADD_SYMBOL(D3D9_DLL, d3didxbuf, IDirect3DIndexBuffer9, GetPrivateData)
    ADD_SYMBOL(D3D9_DLL, d3didxbuf, IDirect3DIndexBuffer9, FreePrivateData)
    ADD_SYMBOL(D3D9_DLL, d3didxbuf, IDirect3DIndexBuffer9, SetPriority)
    ADD_SYMBOL(D3D9_DLL, d3didxbuf, IDirect3DIndexBuffer9, GetPriority)
    ADD_SYMBOL(D3D9_DLL, d3didxbuf, IDirect3DIndexBuffer9, PreLoad)
    ADD_SYMBOL(D3D9_DLL, d3didxbuf, IDirect3DIndexBuffer9, GetType)
    ADD_SYMBOL(D3D9_DLL, d3didxbuf, IDirect3DIndexBuffer9, Lock)
    ADD_SYMBOL(D3D9_DLL, d3didxbuf, IDirect3DIndexBuffer9, Unlock)
    ADD_SYMBOL(D3D9_DLL, d3didxbuf, IDirect3DIndexBuffer9, GetDesc)
}

static void
after_IDirect3DDevice9_CreateDepthStencilSurface(void *wrapcxt, void *user_data)
{
    wrap_lib_user_t *p_data = user_data;

    LPDIRECT3DSURFACE9 d3ds = *(void **)p_data->args[7];
    if (!d3ds) return;
    if (IDirect3DSurface9_lpVtbl) {
        DR_ASSERT(IDirect3DSurface9_lpVtbl == d3ds->lpVtbl);
        return;
    } else
        IDirect3DSurface9_lpVtbl = d3ds->lpVtbl;

    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, QueryInterface)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, AddRef)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, Release)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, GetDevice)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, SetPrivateData)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, GetPrivateData)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, FreePrivateData)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, SetPriority)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, GetPriority)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, PreLoad)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, GetType)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, GetContainer)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, GetDesc)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, LockRect)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, UnlockRect)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, GetDC)
    ADD_SYMBOL(D3D9_DLL, d3ds, IDirect3DSurface9, ReleaseDC)
}

static void
after_IDirect3DDevice9_EndStateBlock(void *wrapcxt, void *user_data)
{
    wrap_lib_user_t *p_data = user_data;

    LPDIRECT3DSTATEBLOCK9 d3dsb = *(void **)p_data->args[1];
    if (!d3dsb) return;
    if (IDirect3DStateBlock9_lpVtbl) {
        DR_ASSERT(IDirect3DStateBlock9_lpVtbl == d3dsb->lpVtbl);
        return;
    } else
        IDirect3DStateBlock9_lpVtbl = d3dsb->lpVtbl;

    ADD_SYMBOL(D3D9_DLL, d3dsb, IDirect3DStateBlock9, QueryInterface)
    ADD_SYMBOL(D3D9_DLL, d3dsb, IDirect3DStateBlock9, AddRef)
    ADD_SYMBOL(D3D9_DLL, d3dsb, IDirect3DStateBlock9, Release)
    ADD_SYMBOL(D3D9_DLL, d3dsb, IDirect3DStateBlock9, GetDevice)
    ADD_SYMBOL(D3D9_DLL, d3dsb, IDirect3DStateBlock9, Capture)
    ADD_SYMBOL(D3D9_DLL, d3dsb, IDirect3DStateBlock9, Apply)
}

bool
syminfo_add(app_pc func, sym_info_item_t *sym_info)
{
    bool result = hashtable_add(&sym_info_table, func, sym_info);

    buf_symbol_t buf_item = {0};
    buf_item.kind = KIND_SYMBOL;
    buf_item.shared_dll = sym_info->shared_dll;
    buf_item.func = func;
    buf_item.ordinal = sym_info->sym.ordinal;
    strncpy(buf_item.name, sym_info->sym.name, sizeof(buf_item.name));

    dump_symbol_data(&buf_item);

    return result;
}

bool
syminfo_remove(app_pc func)
{
    return hashtable_remove(&sym_info_table, func);
}

sym_info_item_t*
syminfo_get(app_pc func)
{
    return hashtable_lookup(&sym_info_table, func);
}

static void
before_CreateThread(void *wrapcxt, void *user_data)
{
    wrap_lib_user_t *p_data = user_data;
    buf_event_t buf_item = {0};
    buf_item.kind = KIND_ARGS;
    // start address
    buf_item.params[0] = (uint) p_data->args[2];
    // parameter
    buf_item.params[1] = (uint) p_data->args[3];
    // creation flags
    buf_item.params[2] = (uint) p_data->args[4];

    dump_event_data(&buf_item);
}

static void
after_CreateThread(void *wrapcxt, void *user_data)
{
    wrap_lib_user_t *p_data = user_data;
    buf_event_t buf_item = {0};
    buf_item.kind = KIND_ARGS;

    HANDLE hThread = p_data->retval;
    // thread id
    if (p_data->args[5]) {
        buf_item.params[0] = *(uint*)p_data->args[5];
    } else {
        buf_item.params[0] = GetThreadId(hThread);
    }

    dr_fprintf(get_info_file(), "CreateThread HANDLE:%x id:%d\n", hThread, buf_item.params[0]);
    dr_printf("CreateThread HANDLE:%x id:%d\n", hThread, buf_item.params[0]);

    dump_event_data(&buf_item);
}

static void after_InitializeCriticalSection(void *wrapcxt, void *user_data)
{
    wrap_lib_user_t *p_data = user_data;
    void *cs = p_data->args[0];
    uint count = synchro_inc_cs(cs);

    buf_event_t buf_item = {0};
    buf_item.kind = KIND_CRITSEC;
    buf_item.params[0] = (uint) cs;
    buf_item.params[1] = count;

    dump_event_data(&buf_item);
}

static void after_EnterCriticalSection(void *wrapcxt, void *user_data)
{
    wrap_lib_user_t *p_data = user_data;
    void *cs = p_data->args[0];
    uint count = synchro_inc_cs(cs);

    buf_event_t buf_item = {0};
    buf_item.kind = KIND_CRITSEC;
    buf_item.params[0] = (uint) cs;
    buf_item.params[1] = count;

    dump_event_data(&buf_item);
}

static void before_LeaveCriticalSection(void *wrapcxt, void *user_data)
{
    wrap_lib_user_t *p_data = user_data;
    void *cs = p_data->args[0];
    uint count = synchro_inc_cs(cs);

    buf_event_t buf_item = {0};
    buf_item.kind = KIND_CRITSEC;
    buf_item.params[0] = (uint) cs;
    buf_item.params[1] = count;

    dump_event_data(&buf_item);
}

static void
after_CreateMutex(void *wrapcxt, void *user_data)
{
    wrap_lib_user_t *p_data = user_data;

    void *hmutex = p_data->retval;
    uint count = synchro_inc_hmutex(hmutex, SYNC_MUTEX);

    buf_event_t buf_item = {0};
    buf_item.kind = KIND_SYNC;
    buf_item.params[0] = (uint) hmutex;
    buf_item.params[1] = count;
    buf_item.params[2] = SYNC_MUTEX;

    dump_event_data(&buf_item);
}

static void
before_ReleaseMutex(void *wrapcxt, void *user_data)
{
    wrap_lib_user_t *p_data = user_data;

    void *hmutex = p_data->args[0];
    uint count = synchro_inc_hmutex(hmutex, SYNC_MUTEX);

    buf_event_t buf_item = {0};
    buf_item.kind = KIND_SYNC;
    buf_item.params[0] = (uint) hmutex;
    buf_item.params[1] = count;
    buf_item.params[2] = SYNC_MUTEX;

    dump_event_data(&buf_item);
}

static void
after_CreateEvent(void *wrapcxt, void *user_data)
{
    wrap_lib_user_t *p_data = user_data;

    void *hevent = p_data->retval;
    uint count = synchro_inc_hmutex(hevent, SYNC_EVENT);

    buf_event_t buf_item = {0};
    buf_item.kind = KIND_SYNC;
    buf_item.params[0] = (uint) hevent;
    buf_item.params[1] = count;
    buf_item.params[2] = SYNC_EVENT;

    dump_event_data(&buf_item);
}

static void
before_ResetEvent(void *wrapcxt, void *user_data)
{
    wrap_lib_user_t *p_data = user_data;

    void *hevent = p_data->args[0];
    uint count = synchro_inc_hmutex(hevent, SYNC_EVENT);

    buf_event_t buf_item = {0};
    buf_item.kind = KIND_SYNC;
    buf_item.params[0] = (uint) hevent;
    buf_item.params[1] = count;
    buf_item.params[2] = SYNC_EVENT;

    dump_event_data(&buf_item);
}

static void
after_WaitForSingleObject(void *wrapcxt, void *user_data)
{
    wrap_lib_user_t *p_data = user_data;

    if (p_data->retval == WAIT_OBJECT_0) {
        void *hmutex = p_data->args[0];
        uint kind = synchro_kind_hmutex(hmutex);
        if (kind) {
            uint count = synchro_inc_hmutex(hmutex, kind);

            buf_event_t buf_item = {0};
            buf_item.kind = KIND_SYNC;
            buf_item.params[0] = (uint) hmutex;
            buf_item.params[1] = count;
            buf_item.params[2] = kind;

            dump_event_data(&buf_item);
        }
    }
}

static void
after_CloseHandle(void *wrapcxt, void *user_data)
{
    wrap_lib_user_t *p_data = user_data;
    void *hmutex = p_data->args[0];

    uint kind = synchro_kind_hmutex(hmutex);
    if (kind) {
        uint count = synchro_inc_hmutex(hmutex, kind);

        buf_event_t buf_item = {0};
        buf_item.kind = KIND_SYNC;
        buf_item.params[0] = (uint) hmutex;
        buf_item.params[1] = count;
        buf_item.params[2] = kind;

        dump_event_data(&buf_item);
    }
}

static void
after_VirtualProtect(void *wrapcxt, void *user_data)
{
  wrap_lib_user_t *p_data = user_data;
  char *ptr = (char*)p_data->args[0];
  uint size = (uint) p_data->args[1];
  uint protect = (uint) p_data->args[2];
  if (protect & 0xF0) { // PAGE_EXECUTE_XXX
    add_dynamic_codes(ptr, ptr + size);

    dr_printf("VirtualProtect: %X %X %X\n",
        (uint) ptr, size, protect);

    if (get_info_file() != INVALID_FILE) {
      dr_fprintf(get_info_file(), "VirtualProtect: %X %X %X\n",
          (uint) ptr, size, protect);
    }
    module_data_t *mod;
    mod = dr_lookup_module((app_pc)ptr);
    if (mod) {
      const char *mod_name = dr_module_preferred_name(mod);
      dr_printf("Module:%X %s\n", mod->start, mod_name);
      dr_free_module_data(mod);
    }
  }
}

static void
after_VirtualAlloc(void *wrapcxt, void *user_data)
{
  wrap_lib_user_t *p_data = user_data;
  char *ptr = (char*)p_data->args[0];
  uint size = (uint) p_data->args[1];
  uint protect = (uint) p_data->args[3];
  if (protect & 0xF0) { // PAGE_EXECUTE_XXX
    add_dynamic_codes(ptr, ptr + size);

    dr_printf("VirtualAlloc: %X %X %X\n",
        (uint) ptr, size, protect);
    if (get_info_file() != INVALID_FILE) {
      dr_fprintf(get_info_file(), "VirtualAlloc: %X %X %X\n",
          (uint) ptr, size, protect);
    }
  }
}

static void
after_ReadFile(void *wrapcxt, void *user_data)
{
    wrap_lib_user_t *p_data = user_data;

    buf_event_t buf_item = {0};
    buf_item.kind = KIND_ARGS;
    // buffer
    buf_item.params[0] = (uint) p_data->args[1];
    // number of bytes to read
    buf_item.params[1] = (uint) p_data->args[2];
    // number of bytes has been read
    buf_item.params[2] = p_data->args[3] ? *(uint*)p_data->args[3]: 0;
    dump_event_data(&buf_item);
}
