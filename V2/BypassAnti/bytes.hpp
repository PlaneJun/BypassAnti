#ifndef __BYTES_H__
#define __BYTES_H__
#include <vector>

class ByteVector : public std::vector<std::uint8_t>
{
public:
	~ByteVector()
	{
		clear();
	}
	//
	//! Used for pushing a single byte.
	//! Example: push(0x55)
	//
	ByteVector& push_byte(std::uint8_t byte)
	{
		push_back(byte);
		return *this;
	}

	//
	//! Used for pushing raw data
	//! Example: push_raw(data, size)
	//
	template<typename T>
	ByteVector& push_raw(const T* data, std::size_t rsize)
	{
		resize(size() + rsize);
		memcpy(&(*this)[size() - rsize], data, rsize);
		return *this;
	}

	//
	//! Used for pushing a container.
	//! Example: push_container(array/vector/etc)
	//
	template<typename T>
	ByteVector& push_container(const T& container)
	{
		for (auto c : container)
			push_back(static_cast<std::uint8_t>(c));
		return *this;
	}

	//
	//! Used for pushing a raw array.
	//! Example: push_array({0x55, 0x8b, 0xec})
	//
	template<typename T>
	ByteVector& push_array(const std::vector<T>& list) {
		for (auto c : list)
			push_back(static_cast<std::uint8_t>(c));
		return *this;
	}

	//
	//! Used for pushing a iterator range.
	//! Example: push_range(c.begin(), c.end())
	//
	template<typename iterator_t>
	ByteVector& push_range(iterator_t first, iterator_t last)
	{
		while (first != last)
		{
			push_back(static_cast<std::uint8_t>(*first));
			first++;
		}
		return *this;
	}

	//
	//! Used for pushing arguments.
	//! Example: push_args(0x55, 0x8b, 0xec)
	// 


	//
	//! Push a double dword
	//! Example: push_dword(0xdeadbeef) ..
	//
	ByteVector& push_dword(std::uint32_t dword)
	{
		push_back(static_cast<std::uint8_t>(dword & 0xFF));
		push_back(static_cast<std::uint8_t>((dword >> 8) & 0xFF));
		push_back(static_cast<std::uint8_t>((dword >> 16) & 0xFF));
		push_back(static_cast<std::uint8_t>((dword >> 24) & 0xFF));
		return *this;
	}

	//
	//! Push a quad word
	//! Example: push_qword(0x1122334411223344) ..
	//
	ByteVector& push_qword(std::uint64_t qword)
	{
		push_back(static_cast<std::uint8_t>(qword & 0xFF));
		push_back(static_cast<std::uint8_t>((qword >> 8) & 0xFF));
		push_back(static_cast<std::uint8_t>((qword >> 16) & 0xFF));
		push_back(static_cast<std::uint8_t>((qword >> 24) & 0xFF));
		push_back(static_cast<std::uint8_t>((qword >> 32) & 0xFF));
		push_back(static_cast<std::uint8_t>((qword >> 40) & 0xFF));
		push_back(static_cast<std::uint8_t>((qword >> 48) & 0xFF));
		push_back(static_cast<std::uint8_t>((qword >> 56) & 0xFF));
		return *this;
	}

	//
	//! Copy in data at specified index
	//! Example: copy_data(0, data, size)
	//
	template<typename T>
	ByteVector& copy_data(std::size_t idx, const T* data, std::size_t rsize)
	{
		if (size() > idx)
		{
			std::memcpy(&(*this)[idx], data, rsize);
		}
		return *this;
	}

	//
	//! Add/insert in data at specified index
	//! Example: insert_data(0, data, size)
	//
	template<typename T>
	ByteVector& insert_data(std::size_t idx, const T* data, std::size_t rsize)
	{
		if (size() <= idx)
			resize(idx);
		insert(begin() + idx, rsize, 0x0);
		memcpy(&(*this)[idx], data, rsize);
		return *this;
	}

	//
	//! Interpret data as T
	//! Example: as<char*>(0x0/)
	//
	template<typename T>
	T as(std::size_t idx = 0x0) const
	{
		return (T)(&at(idx));
	}
	template<typename T>
	T as(std::size_t idx = 0x0)
	{
		return (T)(&at(idx));
	}

	//
	//! Dereference bytes as T
	//! Example: deref<char*>(0x0/)
	//
	template<typename T>
	T deref(std::size_t idx = 0x0) const
	{
		return *(T*)(&at(idx));
	}
};
#endif