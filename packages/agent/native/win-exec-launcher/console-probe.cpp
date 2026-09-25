#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cwchar>
#include <string>

namespace {
void WriteWideAsConsoleBytes(HANDLE stream, const wchar_t* value) {
  const UINT code_page = GetConsoleOutputCP();
  const int chars = static_cast<int>(wcslen(value));
  const int size = WideCharToMultiByte(code_page, 0, value, chars, nullptr, 0, nullptr, nullptr);
  std::string bytes(size, '\0');
  WideCharToMultiByte(code_page, 0, value, chars, bytes.data(), size, nullptr, nullptr);
  DWORD written = 0;
  WriteFile(stream, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr);
}
}  // namespace

int wmain() {
  const UINT code_page = GetConsoleOutputCP();
  const BOOL visible = GetConsoleWindow() && IsWindowVisible(GetConsoleWindow());
  const std::wstring prefix = L"CP=" + std::to_wstring(code_page) +
                              L";VISIBLE=" + std::to_wstring(visible ? 1 : 0) + L"\r\n";
  WriteWideAsConsoleBytes(GetStdHandle(STD_OUTPUT_HANDLE), prefix.c_str());
  WriteWideAsConsoleBytes(GetStdHandle(STD_OUTPUT_HANDLE), L"stdout=zażółć € 漢字\r\n");
  WriteWideAsConsoleBytes(GetStdHandle(STD_ERROR_HANDLE), L"stderr=Łódź Ж\r\n");
  return code_page == CP_UTF8 && !visible ? 0 : 2;
}
