![image](https://github.com/user-attachments/assets/31fc6ce5-6933-4e95-a884-6b5dede70cdb)# Introduction
MissionEvasion is a project that explores advanced techniques for injecting payloads into processes. Initially, the project relied on Process Hollowing, a well-known technique. However, with the release of Windows 11 24H2, significant changes were introduced to the operating system’s process initialization mechanisms, specifically targeting executable memory regions created using VirtualAlloc. To bypass these restrictions, this project introduces Process Overwriting as a novel alternative.

Below, we describe both techniques in detail and provide an explanation of how the Windows 11 24H2 patch impacted traditional Process Hollowing.

# Limitations with Windows 11 24H2

Windows 11 24H2 introduced native support for Hotpatching, which altered how processes initialize and manage memory. These changes include the addition of a new function:

RtlpInsertOrRemoveScpCfgFunctionTable (called during process initialization).

Impact on Process Hollowing

The following chain of function calls is now invoked during process initialization:

LdrpInitializeProcess -> LdrpProcessMappedModule -> RtlpInsertOrRemoveScpCfgFunctionTable -> ZwQueryVirtualMemory

The key function, ZwQueryVirtualMemory, retrieves properties of modules in memory. When invoked with the new argument MemoryImageExtensionInformation, the function verifies that all memory regions are of type MEM_IMAGE. Since traditional Process Hollowing allocates a MEM_PRIVATE region using VirtualAlloc, the function call fails with STATUS_INVALID_ADDRESS, preventing the process from being properly initialized.

# Process Hollowing

## Description

Steps:

1. A benign process is started in a suspended state.

2. The process’s memory region is unmapped.

3. A malicious PE (Portable Executable) payload is written into the newly allocated memory region using VirtualAlloc.

4. The relocation sections of the payload are patched.

5. The process is resumed, executing the injected payload.

This technique, while effective for traditional injection & evasion, injects & resumes the process from a MEM_PRIVATE region. As mentioned above, this is no longer possible in Windows 11 24H2
![image](https://github.com/user-attachments/assets/58a9340a-ee5c-4145-9cbd-f2c2d677c533)


# Process Overwriting

## Description

Process Overwriting was implemented to bypass the new restrictions introduced in Windows 11 24H2. 

Unlike Process Hollowing, this technique injects and resumes the process from a MEM_IMAGE region as opposed to MEM_PRIVATE. 

Process Overwriting also avoids unmapping and allocating new memory regions.  Instead, it overwrites the existing memory regions of a benign process directly.

## Steps:
1. A benign process is started in a suspended state.

2. Using VirtualProtectEx, the memory regions of the target process are configured with appropriate permissions to allow writing.

3. The memory region is overwritten with the malicious payload.

4. The permissions of each section of the payload are patched to match the requirements of the PE.

5. The process is resumed, executing the malicious payload seamlessly.

## Advantages of Process Overwriting

Bypassing MEM_PRIVATE Restrictions: Since this technique does not allocate new memory regions, it avoids triggering ZwQueryVirtualMemory checks for MEM_IMAGE.

Stealth: Overwriting existing memory regions makes the process appear less suspicious to monitoring tools, as no new allocations are created.



# How to Use

TO NOTE:
1. Should only be compiled as x86
2. All files selected should be 32-bit
3. Can only perform process hollowing between same application types (GUI TO GUI or Console to Console)
4. Example executable (MissionEvasion.exe) uses c:\windows\syswow64\notepad.exe for the dummy process. Check if you have this executable, otherwise you may specify another one (refer to point 2) by changing DUMMY_PROCESS_FILE_PATH in config.ini
5. Project was compiled with Visual Studio 2022

1. Apply all your changes to config.ini
2. Compile FilelessMalware.cpp as x86 or simply run MissionEvasion.exe
3. enter 'e' to hide a file in registry
4. enter 'w' to inject PE image hidden in registry to a dummy exe of your choice (will only work if you have existing PE image in the registry key set in config.ini)


References:
https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations
https://www.codereversing.com/archives/261

https://hshrzd.wordpress.com/2025/01/27/process-hollowing-on-windows-11-24h2/

https://ynwarcs.github.io/Win11-24H2-CFG

https://github.com/hasherezade/process_overwriting/tree/master (Used the demo.bin payload from @hasherezade)
