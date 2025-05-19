#pragma once

#include <windows.h>
#include <memory>

int RegHide(LPCSTR strPathToSourceFile, HKEY hRegPath, LPCSTR strRegKey, LPCSTR strValuePrefix);