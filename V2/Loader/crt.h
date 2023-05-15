#pragma once

uint32_t ____rotl(int x, int n);
uint32_t  ____ror(uint32_t num, uint32_t bits);
wchar_t __toupper(wchar_t ch);
wchar_t __tolower(wchar_t ch);
int __wstrcmp(const wchar_t* str1, const wchar_t* str2);
wchar_t* __wstrcpy(wchar_t* dest, const wchar_t* src);
wchar_t* __wstrcat(wchar_t* dest, const wchar_t* src);
wchar_t* __strstrw(const wchar_t* str, const wchar_t* sub, bool nocase);
