// Loader.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <iostream>

#include "pch.h"
#include "pefile.h"

#define MAX_PACK 10

struct packInfo
{
	uint64_t seg_rva;
	uint64_t seg_size;
	uint64_t xor_key;
};

struct ShadowApi
{
	uint64_t lpfnLoadLibraryW;
	uint64_t lpfnVirtualProtect;
	uint64_t lpfnGetProcAddress;
	uint64_t lpfnCreateFileW;
	uint64_t lpfnReadFile;
	uint64_t lpfnCloseHandle;
	uint64_t lpfnDeleteFileW;
	uint64_t lpfnFindFirstFileW;
	uint64_t lpfnFindNextFileW;
	uint64_t lpfnFindClose;
	uint64_t lpfnCreateToolhelp32Snapshot;
	uint64_t lpfnProcess32FirstW;
	uint64_t lpfnProcess32NextW;
	uint64_t lpfnGetTempPathW;
	uint64_t lpfnGetCurrentProcessId;
};

struct TCONFIG
{
	uint64_t			loader_rva;
	uint64_t			loader_size;
	struct packInfo		packs[MAX_PACK];
	uint64_t			oep;
	uint64_t			origin_base;
	uint64_t			arch64;
	wchar_t				parentname[256];
	struct ShadowApi	ShadowApiPtr;
}LoaderConfig;


uint32_t  crc32 (uint8_t* ptr, uint32_t Size)
{
	uint32_t crcTable[256], crcTmp1;

	// 动态生成CRC-32表
	for (int i = 0; i < 256; i++)
	{
		crcTmp1 = i;
		for (int j = 8; j > 0; j--)
		{
			if (crcTmp1 & 1) crcTmp1 = (crcTmp1 >> 1) ^ 0xEDB88320L;
			else crcTmp1 >>= 1;
		}
		crcTable[i] = crcTmp1;
	}

	// 计算CRC32值
	uint32_t crcTmp2 = 0xFFFFFFFF;
	while (Size--)
	{
		crcTmp2 = ((crcTmp2 >> 8) & 0x00FFFFFF) ^ crcTable[(crcTmp2 ^ (*ptr)) & 0xFF];
		ptr++;
	}
	return (crcTmp2 ^ 0xFFFFFFFF);
}


uint32_t ____rotl(int x, int n) {
	return (x << n) | (x >> (32 - n));
}

int main(int argc,char* argv[])
{
	if (argc < 2)
	{
	help:
		printf("Usage: BypassAnti\n");
		printf("\t-f		(required) filename\n");
		printf("\t-p		(optional) parent process,used to verify whether the sandbox runs.default null\n");
		printf("\t-s		(optional) section name to be encrypted,maximum of 10 section,defaults '.text'\n");
		printf("Example: BypassAnti -f filename -p explorer.exe -s .text .data\n");
		return 0;
	}
	srand(time(0));
	std::vector<std::string> pack_section = { ".text" };
	std::wstring parenname = L"";
	std::string filename = {};
	std::string segname = ".ba";
	try {
		for (int i = 1; i < argc; i++)
		{
			if (!strcmp(argv[i], "-f"))
				filename = argv[i + 1];
			else if (!strcmp(argv[i], "-s"))
			{ 
				pack_section.clear();
				int j = i+1;
				do 
				{
					if (argv[j][0] == '.')
						pack_section.push_back(argv[j++]);
					else
						break;
				} while (j< argc);
				i = j-1;
			}
			else if (!strcmp(argv[i], "-p"))
			{
				std::string tmp = argv[i + 1];
				parenname.assign(tmp.begin(), tmp.end());
			}
		}
	}
	catch (std::exception& e)
	{
		goto help;
	}
	//检查加密段数
	if (pack_section.size() > MAX_PACK)
	{
		printf("! Encrypt a maximum of 10 section\n");
		return 0;
	}
	printf("------------------------------------------------------------------\n");
	//读取目标文件
	PEFile pe(filename.c_str());
	printf("> detect file arch = x%s\n", pe.arch64() ? "64" : "86");
	//读取sdk
	PEFile* sdk=NULL;
	ByteVector shellcode{};
	if (pe.arch64())
	{
		//boot
		shellcode.push_array<uint8_t>({
				0xE8,0x00,0x00,0x00,0x00,							//call $0
				0x58,												//pop rax
				0x48,0x83,0xE8,0x05,								//sub rax,5
				0x48,0x8D,0x90,0x67,0x45,0x23,0x01,					//lea rdx,[rax+offset_data]
				0x48,0x2B,0x02,										//sub rax, qword ptr ds:[rcx]
				0x48,0x8B,0xC8,										//mov rcx, rax
				0xE8,0x16,0x00,0x00,0x00,							//call Loader
				0xFF,0xE0											//jmp rax
			});
		sdk = new PEFile("./Loader64.dll");
		PIMAGE_OPTIONAL_HEADER64 pOptional = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(sdk->GetOptionalHeader());
		*(uint32_t*)&shellcode[24] = pOptional->AddressOfEntryPoint - sdk->GetSectionHeader(".text")->VirtualAddress + 2;
	}
	else
	{
		//boot
		shellcode.push_array<uint8_t>({
			0xE8,0x00,0x00,0x00,0x00,					//call $0
			0x58,										//pop eax
			0x83,0xE8,0x05,								//sub eax,5
			0x8D,0x88,0x1A,0x02,0x00,0x00				//lea ecx,[eax+offset_data]
			,0x2B,0x01,									//sub eax,[ecx]
			0x51,										//push ecx
			0x50,										//push eax
			0xE8,0x12,0x00,0x00,0x00,					//call Loader
			0x83,0xC4,0x08,								//add esp,8
			0xFF,0xE0									//jmp eax
			});
		sdk = new PEFile("./Loader.dll");
		PIMAGE_OPTIONAL_HEADER32 pOptional = reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(sdk->GetOptionalHeader());
		*(uint32_t*)&shellcode[20] = pOptional->AddressOfEntryPoint - sdk->GetSectionHeader(".text")->VirtualAddress+5;
	}
	printf("> load sdk file = Loader%s.dll\n", pe.arch64() ? "64" : "");
	//提取sdk中的代码
	PIMAGE_SECTION_HEADER sdk_code = sdk->GetSectionHeader(".text");
	shellcode.insert_data<uint8_t>(shellcode.size(),(uint8_t*)sdk->stream() + sdk_code->PointerToRawData,sdk_code->SizeOfRawData);
	//修改shellcode偏移
	if (pe.arch64())
		*(uint32_t*)&shellcode[13] = shellcode.size();
	else 
		*(uint32_t*)&shellcode[11] = shellcode.size();
	//加密区段
	for (int i=0;i<pack_section.size();i++)
	{
		PIMAGE_SECTION_HEADER sec = pe.GetSectionHeader(pack_section[i].c_str());
		if (!sec)
		{
			printf("find target file %s error\n", pack_section[i].c_str());
			continue;
		}
		LoaderConfig.packs[i].seg_rva = sec->VirtualAddress;//添加代码段地址
		LoaderConfig.packs[i].seg_size = sec->Misc.VirtualSize;//添加代码段大小
		LoaderConfig.packs[i].xor_key = rand() % time(0)+time(0);//设置key
		for (int j = 0; j < sec->Misc.VirtualSize; j++)
		{
			uint8_t origin_byte = 0;
			pe.Read<uint8_t>(sec->PointerToRawData + j, origin_byte);
			pe.Write<uint8_t>(sec->PointerToRawData + j, origin_byte ^ static_cast<uint8_t>(____rotl(LoaderConfig.packs[i].xor_key, j) + j));
		}
		printf("> enecrypt (%s)[begin:<0x%p>,size:<0x%p>] , xor_key = 0x%p\n", pack_section[i].c_str(), sec->VirtualAddress, sec->Misc.VirtualSize, LoaderConfig.packs[i].xor_key);
	}
	//添加节
	printf("> create new section...\n");
	PIMAGE_SECTION_HEADER pLoaderSection = 0;
	size_t createSize = shellcode.size() + sizeof(LoaderConfig)+8; //计算新节区大小
	pe.AppendSection(segname, createSize, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE, &pLoaderSection);
	if (!pLoaderSection)
	{
		printf("! Add New Section Error!\n");
		return 0;
	}
	//更新config
	uint8_t* pOtionalHeader = pe.GetOptionalHeader();
	LoaderConfig.origin_base = pe.arch64() ? reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(pOtionalHeader)->ImageBase : reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(pOtionalHeader)->ImageBase;
	LoaderConfig.oep = pe.arch64() ? reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(pOtionalHeader)->AddressOfEntryPoint : reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(pOtionalHeader)->AddressOfEntryPoint;
	LoaderConfig.arch64 = pe.arch64();
	LoaderConfig.loader_rva = pLoaderSection->VirtualAddress; //添加新节区地址
	LoaderConfig.loader_size = pLoaderSection->Misc.VirtualSize;//添加新节区大小
	for (int i = 0; i < parenname.length(); i++)
		LoaderConfig.parentname[i] = parenname[i] ^ 0x8f;
	//写入config
	printf("> add config......\n");
	shellcode.insert_data(shellcode.size(), &LoaderConfig, sizeof(LoaderConfig));
	//写入loader
	printf("> writing loader......\n");
	pe.WriteBytes(pLoaderSection->PointerToRawData, shellcode.data(), shellcode.size());
	//更新入口点
	printf("> reset entrypoint = %p\n", pLoaderSection->VirtualAddress);
	pe.SetEntryPoint(pLoaderSection->VirtualAddress);
	//保存
	printf("> rebuild file to %s\n", (filename + ".bypass").c_str());
	pe.WriteToFile(filename + ".bypass");
	printf("> done!\n");
	printf("------------------------------------------------------------------\n");
	return 0;
}

