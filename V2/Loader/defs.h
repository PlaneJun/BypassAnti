#pragma once

using fnLoadLibraryW = HMODULE(__stdcall*)(LPCWSTR lpLibFileName);
using fnVirtualProtect = bool(__stdcall*)(void* lpAddress, SIZE_T dwSize, uint32_t flNewProtect, uint32_t* lpflOldProtect);
using fnGetProcAddress = void* (__stdcall*)(HMODULE hModule, LPCWSTR lpProcName);
using fnCreateFileW = HANDLE(__stdcall*)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
using fnReadFile = bool(__stdcall*)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
using fnCloseHandle = void(__stdcall*)(HANDLE hHandle);
using fnDeleteFileW = bool(__stdcall*)(LPCWSTR filename);
using fnFindFirstFileW = HANDLE(__stdcall*)(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
using fnFindNextFileW = BOOL(__stdcall*)(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
using fnFindClose = BOOL(__stdcall*)(HANDLE hFindFile);
using fnCreateToolhelp32Snapshot = HANDLE(__stdcall*)(DWORD dwFlags, DWORD th32ProcessID);
using fnProcess32FirstW = BOOL(__stdcall*)(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
using fnProcess32NextW = BOOL(__stdcall*)(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
using fnGetTempPathW = BOOL(__stdcall*)(DWORD nBufferLength, LPCWSTR lpBuffer);
using fnGetCurrentProcessId = DWORD(__stdcall*)();

struct ShadowApi
{
	fnLoadLibraryW lpfnLoadLibraryW;
	fnVirtualProtect lpfnVirtualProtect;
	fnGetProcAddress lpfnGetProcAddress;
	fnCreateFileW lpfnCreateFileW;
	fnReadFile lpfnReadFile;
	fnCloseHandle lpfnCloseHandle;
	fnDeleteFileW lpfnDeleteFileW;
	fnFindFirstFileW lpfnFindFirstFileW;
	fnFindNextFileW lpfnFindNextFileW;
	fnFindClose lpfnFindClose;
	fnCreateToolhelp32Snapshot lpfnCreateToolhelp32Snapshot;
	fnProcess32FirstW lpfnProcess32FirstW;
	fnProcess32NextW lpfnProcess32NextW;
	fnGetTempPathW lpfnGetTempPathW;
	fnGetCurrentProcessId lpfnGetCurrentProcessId;
};


struct packInfo
{
	uint64_t seg_rva;
	uint64_t seg_size;
	uint64_t xor_key;
};

#define MAX_PACK 10

struct TCONFIG
{
	uint64_t		loader_rva;
	uint64_t		loader_size;
	struct packInfo	packs[MAX_PACK];
	uint64_t		oep;
	uint64_t		origin_base;
	uint64_t		arch64;
	wchar_t			parentname[256];
	struct ShadowApi ShadowApiPtr;
};

typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PVOID Ldr;
	PVOID ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	PVOID PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, * PPEB;

typedef struct _PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;

#ifdef _WIN64 

#define ADDRESS uint64_t

typedef struct _ModuleInfoNode {

	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;

} ModuleInfoNode, * pModuleInfoNode;

typedef struct _ProcessModuleInfo {
	/*000*/  ULONG Length;
	/*004*/  BOOLEAN Initialized;
	/*008*/  PVOID SsHandle;
	/*00C*/  LIST_ENTRY ModuleListLoadOrder;
	/*014*/  LIST_ENTRY ModuleListMemoryOrder;
	/*018*/  LIST_ENTRY ModuleListInitOrder;
	/*020*/
} ProcessModuleInfo, * pProcessModuleInfo;

#else

#define ADDRESS uint32_t

typedef struct _ModuleInfoNode {
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	HMODULE BaseAddress;
	unsigned long entryPoint;
	unsigned int size;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	unsigned long flags;
	unsigned short LoadCount;
	unsigned short TlsIndex;
	LIST_ENTRY HashTable;
	unsigned long timestamp;
} ModuleInfoNode, * pModuleInfoNode;

typedef struct _ProcessModuleInfo {
	unsigned int size;
	unsigned int initialized;
	HANDLE SsHandle;
	LIST_ENTRY ModuleListLoadOrder;
	LIST_ENTRY ModuleListMemoryOrder;
	LIST_ENTRY ModuleListInitOrder;
} ProcessModuleInfo, * pProcessModuleInfo;



#endif




