#pragma once
#ifndef GLOBAL_H
#define GLOBAL_H

#include <string>
#include <windows.h>

#include "ntapi.h"
#include "PE.h"
#include "PInjection.h"

enum class InjectionTechnique {
    HOLLOW,
    OVERWRITE
};

enum class PESource {
    FILE,
    REGISTRY
};

struct ConfigData 
{
    // PE Paths
    std::string SourcePEPath;
    std::string DestPEPath;
    
    // Registry Settings
    std::string RegKeyName;
    std::string RegValuePrefix;
    std::string strRegGlobalHkey;  // String representation of the HKEY
    HKEY RegGlobalHkey = nullptr;
    
    // Command Line Arguments
    InjectionTechnique technique = InjectionTechnique:: OVERWRITE;
    PESource peSource = PESource::FILE;
    bool useConfig = false;
    bool useInteractive = false;
    std::string configFilePath;  // Path to config file, empty means use default
    bool writeMode = false;      // Whether we're in write-to-registry mode
};

extern bool is64Bit;
extern ConfigData Config;

#endif // GLOBAL_H
