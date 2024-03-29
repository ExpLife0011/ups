#ifndef STRUTIL_COMSTATIC_H_H_
#define STRUTIL_COMSTATIC_H_H_
#include <list>
#include <string>

std::wstring __stdcall FormatW(const wchar_t *format, ...);
std::string __stdcall FormatA(const char *fmt, ...);

std::string __stdcall AtoU(const std::string &);
std::string __stdcall UtoA(const std::string &);
std::wstring __stdcall AtoW(const std::string &);
std::string _stdcall WtoA(const std::wstring &);
std::wstring __stdcall UtoW(const std::string &);
std::string __stdcall WtoU(const std::wstring &);
#endif //STRUTIL_COMSTATIC_H_H_