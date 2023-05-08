#ifndef __PEFILE_H__
#define __PEFILE_H__

#include "pch.h"

class PEFile
{
private:	
	bool						m_arch64;
	ByteVector			m_data;


public:
	PEFile(const char* file_path);

	uint32_t MemAlign(uint32_t size)
	{
		return (size & ~0xFFF) + 0x1000;
	}
	uint32_t FileAlign(uint32_t size)
	{
		return (size & ~0xFFF) + 0x200;
	}

	bool _validate();
	bool AppendSection(std::string section_name, uint32_t size,uint32_t chrs, PIMAGE_SECTION_HEADER* newSec);
	PIMAGE_DOS_HEADER GetDosHeader();
	uint8_t* GetNtHeaders();
	PIMAGE_FILE_HEADER GetFileHeader();
	uint8_t* GetOptionalHeader();
	PIMAGE_SECTION_HEADER GetSectionHeader();
	PIMAGE_SECTION_HEADER GetSectionHeader(std::string name);

	uint32_t Rva2Foa(uint32_t rva);
	uint32_t Foa2Rva(uint32_t foa);

	bool WriteToFile(std::string filepath);

	void SetEntryPoint(uint32_t op);
	bool WriteBytes(uint32_t pos,void* buf,size_t size);
	bool ReadBytes(uint32_t pos, void* buf, size_t size);
	
	template<typename T>
	bool Write(uint32_t pos, T val)
	{
		return WriteBytes(pos,(uint8_t*) & val, sizeof(T));
	}
	template<typename T>
	bool Read(uint32_t pos, T& val)
	{
		T v;
		ReadBytes(pos, &v, sizeof(T));
		val = v;
		return true;;
	}
public:

	uint32_t size() const { return m_data.size(); }
	void* stream()  { return m_data.data(); }
	bool arch64() const { return m_arch64; }
};

#endif
