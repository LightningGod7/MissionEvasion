#pragma once

#include <windows.h>
#include <memory>

int RegHide(const char* const strPathToSourceFile, HKEY hRegPath, const char* const strRegKey, std::string strValuePrefix);