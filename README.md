# Fileless-Malware
Anti-Forensics Malware Evasion Techniques

1. Hiding exe files in registry
2. Process Hollowing / Process Overwriting

# Process Overwriting

Description

Process Overwriting was developed to bypass the new restrictions introduced in Windows 11 24H2. Unlike Process Hollowing, this technique avoids unmapping and allocating new memory regions. Instead, it overwrites the existing memory regions of a benign process directly.

Steps:

A benign process is started in a suspended state.

Using VirtualProtectEx, the memory regions of the target process are configured with appropriate permissions to allow writing.

The memory region is overwritten with the malicious payload.

The permissions of each section of the payload are patched to match the requirements of the PE.

The process is resumed, executing the malicious payload seamlessly.

Advantages of Process Overwriting

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
