// Loader64.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include<windows.h>
#include<stdlib.h>

#ifdef _WIN64 

#define ADDRESS uint64_t

EXTERN_C  uint32_t  __fastcall HashString(const char* str);
EXTERN_C ADDRESS __fastcall findkernel32();
EXTERN_C ADDRESS __fastcall findkernelbase();
EXTERN_C ADDRESS __fastcall get_ret_address();

#else

#define ADDRESS uint32_t

__declspec(naked) ADDRESS get_ret_address()
{
	__asm {
		pop eax
		push eax
		ret
	}
}

__declspec(naked) uint32_t HashString(const char* str)
{
	__asm {

		push esi
		push edi
		mov esi, [esp + 0xC]
		calc_hash:
		xor edi, edi
			cld
			hash_iter :
		xor eax, eax
			lodsb
			cmp al, ah
			je hash_done
			ror edi, 0xD
			add edi, eax
			jmp hash_iter
			hash_done :
		mov eax, edi
			pop edi
			pop esi
			retn
	}
}

__declspec(naked) ADDRESS findkernelbase()
{
	__asm
	{
		push esi
		xor eax, eax
		mov eax, fs: [0x30]
		mov eax, [eax + 0xC]
		mov esi, [eax + 0x1C]
		mov eax, [esi]
		mov eax, [eax + 8]
		pop esi
		ret

	}
}
__declspec(naked) ADDRESS findkernel32()
{
	__asm {
		mov eax, fs: [30h]
		mov eax, [eax + 0ch]
		mov eax, [eax + 14h]
		mov eax, [eax]
		mov eax, [eax]
		mov eax, [eax + 10h]
		ret
	}
}


#endif

using fnLoadLibraryA = HMODULE(__stdcall*)(LPCSTR lpLibFileName);
using fnVirtualProtect = bool(__stdcall*)(void* lpAddress, uint16_t dwSize, uint32_t flNewProtect, uint32_t* lpflOldProtect);
using fnGetProcAddress = void* (__stdcall*)(HMODULE hModule, LPCSTR lpProcName);
using fnCreateFileA = HANDLE(__stdcall*)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
using fnReadFile = bool(__stdcall*)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
using fnCloseHandle = void(__stdcall*)(HANDLE hHandle);
using fnDeleteFileA = bool(__stdcall*)(LPCSTR filename);



uint32_t ____rotl(int x, int n) {
	return (x << n) | (x >> (32 - n));
}

ADDRESS GetProcAddressByHash(ADDRESS dllbase, uint32_t hash)
{
    PIMAGE_DOS_HEADER pDos = reinterpret_cast<PIMAGE_DOS_HEADER>(dllbase);
    PIMAGE_NT_HEADERS pNt = reinterpret_cast<PIMAGE_NT_HEADERS>(dllbase+pDos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(dllbase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    uint32_t* pAddressOfFunction = (uint32_t*)(dllbase+pImageExportDirectory->AddressOfFunctions);
    uint32_t* pAddressOfNames = (uint32_t*)(dllbase +pImageExportDirectory->AddressOfNames);
    uint32_t dwNumberOfNames = pImageExportDirectory->NumberOfNames;
    uint16_t* pAddressOfNameOrdinals = (uint16_t*)(dllbase+pImageExportDirectory->AddressOfNameOrdinals);
	for (int i = 0; i < dwNumberOfNames; i++)
	{
		char* strFunction = (char*)(pAddressOfNames[i] + dllbase);
        if (HashString(strFunction) == hash)
            return dllbase +pAddressOfFunction[pAddressOfNameOrdinals[i]];
	}
    return 0;
}

ADDRESS  Loader(ADDRESS image_base, uint64_t* keyTable)
{
	uint8_t kernelstr[] = { 0xa3, 0x8f, 0xb7, 0xa3, 0x9b, 0xb3, 0xda, 0xa2,0x8e, 0xa3, 0x8f, 0x8b, 0xc5 };
	//获取代码段地址
	uint8_t* codeBase = reinterpret_cast<uint8_t*>(image_base + keyTable[2]);
	uint32_t codeSize = keyTable[3];
	//修改内存属性
	fnLoadLibraryA lpLoadLibrary = (fnLoadLibraryA)GetProcAddressByHash(findkernelbase(), 0xEC0E4E8E);
	if (!lpLoadLibrary)
		lpLoadLibrary = (fnLoadLibraryA)GetProcAddressByHash(findkernel32(), 0xEC0E4E8E);
	//获取kernel
	for (int m = 0; m < sizeof(kernelstr); ++m)
		kernelstr[m] = (((kernelstr[m] >> 0x2) | (kernelstr[m] << 0x6)) ^ m) - 0x7d;
	ADDRESS kernelBase = (ADDRESS)lpLoadLibrary((char*)kernelstr);
	//读取解密key
	fnCreateFileA lpCreateFileA = (fnCreateFileA)GetProcAddressByHash(kernelBase, 0x7C0017A5);
	uint8_t* keyfile = (uint8_t*)&keyTable[8];
	for (int i = 0; keyfile[i] != 0; i++)
		keyfile[i] = ~keyfile[i];
	HANDLE hFile = lpCreateFileA((char*)keyfile, 0x10000000L, 0x00000001, 0, 3, 0x00000080, 0);
	if (hFile == INVALID_HANDLE_VALUE)
		return 0;
	fnReadFile lpReadFile = (fnReadFile)GetProcAddressByHash(kernelBase, 0x10FA6516);
	char buffer[1024];
	for (int i = 0; i < 1024; i++)
		buffer[i] = 0;
	DWORD bytesRead = 0;
	lpReadFile(hFile, buffer, 1024, &bytesRead, 0);
	fnCloseHandle lpCloseHandle = (fnCloseHandle)GetProcAddressByHash(kernelBase, 0x0FFD97FB);
	lpCloseHandle(hFile);
	//开始解密
	fnVirtualProtect lpVirtualProtect = (fnVirtualProtect)GetProcAddressByHash(kernelBase, 0x7946C61B);
	uint32_t old{};
	lpVirtualProtect(codeBase, codeSize, 64, &old);
	uint32_t codeKey = keyTable[4] ^ *(uint32_t*)buffer;
	for (int i = 0; i < codeSize; i++)
		codeBase[i] = codeBase[i] ^ static_cast<uint8_t>(____rotl(codeKey, i) + i);
	lpVirtualProtect(codeBase, codeSize, old, 0);

	if (keyTable[7])
	{
		fnDeleteFileA lpDeleteFileA = (fnDeleteFileA)GetProcAddressByHash(kernelBase, 0xC2FFB025);
		lpDeleteFileA((char*)keyfile);
	}


	IMAGE_DOS_HEADER* pDos = reinterpret_cast<IMAGE_DOS_HEADER*>(image_base);
	IMAGE_NT_HEADERS* pNt = reinterpret_cast<IMAGE_NT_HEADERS*>(image_base + pDos->e_lfanew);


	//修复重定向
	if (pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress > 0
		&& pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
	{
		uint32_t Delta = (ADDRESS)image_base - keyTable[6];
		ADDRESS* pAddress;
		//注意重定位表的位置可能和硬盘文件中的偏移地址不同，应该使用加载后的地址
		IMAGE_BASE_RELOCATION* pLoc = (IMAGE_BASE_RELOCATION*)(image_base
			+ pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //开始扫描重定位表
		{
			uint16_t* pLocData = (uint16_t*)((ADDRESS)pLoc + sizeof(IMAGE_BASE_RELOCATION));
			//计算本节需要修正的重定位项（地址）的数目
			int NumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
			for (int i = 0; i < NumberOfReloc; i++)
			{
				if ((uint32_t)(pLocData[i] & 0xF000) == 0x00003000 || (uint32_t)(pLocData[i] & 0xF000) == 0x0000A000) //这是一个需要修正的地址
				{
					pAddress = (ADDRESS*)(image_base + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
					*pAddress = image_base + (*pAddress & 0xFFFF);
				}
			}
			//转移到下一个节进行处理
			pLoc = (IMAGE_BASE_RELOCATION*)((ADDRESS)pLoc + pLoc->SizeOfBlock);
		}
	}
	return image_base + keyTable[5];
}

int main()
{
	return  0;

}
