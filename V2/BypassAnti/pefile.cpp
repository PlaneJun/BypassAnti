#include "pefile.h"

PEFile::PEFile(const char* file_path)
{
	FILE* f = NULL;
	fopen_s(&f, file_path, "rb");
	if (!f)
	{
		printf("fopen (%s) error,%s\n", file_path,__FUNCTION__);
		exit(EXIT_FAILURE);
	}
	//get file size
	fseek(f,0,SEEK_END);
	size_t size = ftell(f);
	fseek(f,0,SEEK_SET);
	//read
	uint8_t* buffer = new uint8_t[size];
	memset(buffer,0,size);
	size_t real =  fread_s(buffer,size,1,size,f);
	fclose(f);
	if (real != size)
	{
		printf("read file imcomplete,%s\n", __FUNCTION__);
		exit(EXIT_FAILURE);
	}
	//append to member
	m_data.insert_data(0, buffer, size);
	delete[] buffer;
	if (!_validate())
	{
		printf("invaild pe file,%s\n", __FUNCTION__);
		exit(EXIT_FAILURE);
	}
	
	PIMAGE_DOS_HEADER pDos = reinterpret_cast<PIMAGE_DOS_HEADER>(m_data.data());
	void* pImage_optional_header = m_data.data() + pDos->e_lfanew + sizeof(IMAGE_FILE_HEADER) + 4;
	m_arch64 = *(uint16_t*)(pImage_optional_header) == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

}

bool PEFile::_validate()
{
	if (m_data.size() <= 0)
		return false;

	PIMAGE_DOS_HEADER pDos = reinterpret_cast<PIMAGE_DOS_HEADER>(m_data.data());
	if (pDos->e_magic != 0x5A4D)
		return false;
	uint16_t sig = *(uint16_t*)(m_data.data() + pDos->e_lfanew);
	if (sig != 0x4550)
		return false;
	return true;
}

PIMAGE_DOS_HEADER PEFile::GetDosHeader()
{
	if (m_data.size() <= 0)
		return NULL;

	return PIMAGE_DOS_HEADER(m_data.data());
}

uint8_t* PEFile::GetNtHeaders()
{
	if (m_data.size() <= 0)
		return NULL;

	auto pDos = GetDosHeader();
	return reinterpret_cast<uint8_t*>(m_data.data() + pDos->e_lfanew);
}

PIMAGE_FILE_HEADER PEFile::GetFileHeader()
{
	if (m_data.size() <= 0)
		return NULL;

	if(m_arch64)
		return (PIMAGE_FILE_HEADER) & reinterpret_cast<PIMAGE_NT_HEADERS64>(GetNtHeaders())->FileHeader;
	else
		return (PIMAGE_FILE_HEADER) & reinterpret_cast<PIMAGE_NT_HEADERS32>(GetNtHeaders())->FileHeader;
}
uint8_t* PEFile::GetOptionalHeader()
{
	if (m_data.size() <= 0)
		return NULL;

	if (m_arch64)
		return (uint8_t*) & reinterpret_cast<PIMAGE_NT_HEADERS64>(GetNtHeaders())->OptionalHeader;
	else
		return (uint8_t*) & reinterpret_cast<PIMAGE_NT_HEADERS32>(GetNtHeaders())->OptionalHeader;
}

PIMAGE_SECTION_HEADER PEFile::GetSectionHeader()
{
	if (m_data.size() <= 0)
		return NULL;
	return  reinterpret_cast<PIMAGE_SECTION_HEADER>(GetOptionalHeader() + GetFileHeader()->SizeOfOptionalHeader);
}

PIMAGE_SECTION_HEADER PEFile::GetSectionHeader(std::string name)
{
	static IMAGE_SECTION_HEADER dummy={ ".dummy" };

	PIMAGE_FILE_HEADER pFileHeader = GetFileHeader();
	PIMAGE_SECTION_HEADER pSectionHeader = GetSectionHeader();

	//check vaild
	if (!pFileHeader || !pSectionHeader)
		return &dummy;

	for (std::uint16_t n = 0; n < pFileHeader->NumberOfSections; n++)
	{
		if (std::string((char*)pSectionHeader[n].Name)._Equal(name))
		{
			return &pSectionHeader[n];
		}
	}
	return &dummy;
}


uint32_t PEFile::Rva2Foa(uint32_t rva)
{
	PIMAGE_FILE_HEADER pFileHeader = GetFileHeader();
	PIMAGE_SECTION_HEADER pSectionHeader = GetSectionHeader();
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		if (rva >= pSectionHeader->VirtualAddress)
		{
			if (rva <= pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize)
				return (rva - pSectionHeader->VirtualAddress) + pSectionHeader->PointerToRawData;
		}
		else
			return 0;
		pSectionHeader++;
	}
	return 0;
}
uint32_t PEFile::Foa2Rva(uint32_t foa)
{
	PIMAGE_FILE_HEADER pFileHeader = GetFileHeader();
	PIMAGE_SECTION_HEADER pSectionHeader = GetSectionHeader();
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		if (foa >= pSectionHeader->PointerToRawData)
		{
			if (foa < pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData)
				return (foa - pSectionHeader->PointerToRawData) + pSectionHeader->VirtualAddress;
		}
		else
			return 0;
		pSectionHeader++;
	}
	return 0;
}

bool PEFile::AppendSection(std::string section_name, uint32_t size, uint32_t chrs, PIMAGE_SECTION_HEADER* newSec)
{
	PIMAGE_FILE_HEADER pFileHeader = GetFileHeader();
	PIMAGE_SECTION_HEADER pSectionHeader = GetSectionHeader();
	uint8_t* pOptionalHeader = GetOptionalHeader();

	if (!pFileHeader || !pSectionHeader || !pOptionalHeader)
		return false;


	//add section header
	size_t segCount = pFileHeader->NumberOfSections;
	memcpy(&pSectionHeader[segCount].Name, section_name.c_str(), section_name.length() + 1);
	pSectionHeader[segCount].Characteristics = chrs;
	pSectionHeader[segCount].PointerToRawData = pSectionHeader[segCount - 1].PointerToRawData + pSectionHeader[segCount - 1].SizeOfRawData;
	pSectionHeader[segCount].VirtualAddress = pSectionHeader[segCount - 1].VirtualAddress + MemAlign(pSectionHeader[segCount - 1].Misc.VirtualSize);
	//set section info
	pSectionHeader[segCount].Misc.VirtualSize = MemAlign(size);
	pSectionHeader[segCount].SizeOfRawData = FileAlign(size);
	pSectionHeader[segCount].PointerToRelocations = 0;
	pSectionHeader[segCount].PointerToLinenumbers = 0;
	pSectionHeader[segCount].NumberOfRelocations = 0;
	pSectionHeader[segCount].PointerToLinenumbers = 0;
	pFileHeader->NumberOfSections = pFileHeader->NumberOfSections + 1;

	//reset image_size
	if (m_arch64)
		reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(pOptionalHeader)->SizeOfImage += MemAlign(size);
	else
		reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(pOptionalHeader)->SizeOfImage += MemAlign(size);


	// Fill in some temp data
	std::vector<std::uint8_t> section_data(pSectionHeader[segCount].SizeOfRawData);
	std::fill(section_data.begin(), section_data.end(), 0);
	m_data.insert_data(Rva2Foa(pSectionHeader[segCount].VirtualAddress), section_data.data(), section_data.size());

	if (newSec)
		*newSec = &GetSectionHeader()[segCount];
	return true;
}

bool PEFile::WriteToFile(std::string filepath)
{
	FILE* f = NULL;
	fopen_s(&f, filepath.c_str(), "wb+");
	if (!f)
	{
		printf("fopen error,%s\n", __FUNCTION__);
		exit(EXIT_FAILURE);
	}

	fwrite(m_data.data(), 1, m_data.size(), f);
	fclose(f);
	return true;
}

void PEFile::SetEntryPoint(uint32_t op)
{
	uint8_t* pOptionalHeader = GetOptionalHeader();
	if (m_arch64)
		reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(pOptionalHeader)->AddressOfEntryPoint = op;
	else
		reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(pOptionalHeader)->AddressOfEntryPoint = op;
}

bool PEFile::WriteBytes(uint32_t pos, void* buf, size_t size)
{
	if (pos > m_data.size())
		return false;

	memcpy(&m_data[pos], buf, size);
	return true;
}

bool PEFile::ReadBytes(uint32_t pos, void* buf, size_t size)
{
	if (pos > m_data.size())
		return false;

	memcpy(buf,&m_data[pos], size);
	return true;
}


