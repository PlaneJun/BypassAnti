#include<stdint.h>
#include "crt.h"

wchar_t __toupper(wchar_t ch) {
	if (ch >= 97 && ch <= 122) {
		return ch - 97 + 65;
	}
	else {
		return ch;
	}
}

wchar_t __tolower(wchar_t ch) {
	if (ch >= 65 && ch <= 90) {
		return ch - 65 + 97;
	}
	else {
		return ch;
	}
}

int __wstrcmp(const wchar_t* str1, const wchar_t* str2)
{
	while (*str1 || *str2) {
		if (*str1 < *str2) {
			return -1;
		}
		else if (*str1 > *str2) {
			return 1;
		}
		str1++;
		str2++;
	}
	return 0;
}

wchar_t* __wstrcpy(wchar_t* dest, const wchar_t* src)
{
	// Copy the source string to the dest string until we reach len or the end of the source string
	while (*src) {
		*dest++ = *src++;
	}

	// Add null terminator to dest
	*dest = 0x0000;

	return dest;
}

wchar_t* __wstrcat(wchar_t* dest, const wchar_t* src)
{
	wchar_t* p = dest;

	// Find the end of dest
	while (*p) {
		++p;
	}

	// Copy the source string to the end of dest
	while (*src) {
		*p++ = *src++;
	}

	// Add null terminator to dest
	*p = 0x0000;

	return dest;
}



wchar_t* __strstrw(const wchar_t* str, const wchar_t* sub, bool nocase)
{
	while (*str)
	{
		const wchar_t* p1 = str, * p2 = sub;
		while (nocase ? (*p1 && *p2 && __tolower(*p1) == __tolower(*p2)) : (*p1 && *p2 && *p1 == *p2)) { p1++; p2++; }
		if (!*p2) return (wchar_t*)str;
		str++;
	}
	return NULL;
}


uint32_t ____rotl(int x, int n) {
	return (x << n) | (x >> (32 - n));
}

uint32_t  ____ror(uint32_t num, uint32_t bits) {
	return (num >> bits) | (num << (32 - bits));
}


