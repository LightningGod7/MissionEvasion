#include "globals.h"

#if defined(_WIN64)
bool is64Bit = true;
#else
bool is64Bit = false;
#endif

ConfigData Config;

InjectionTechnique Technique;
PESource peSource;