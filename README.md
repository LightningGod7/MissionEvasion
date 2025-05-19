# MissionEvasion
Advanced AV Evasion Techniques for Windows

## Overview
MissionEvasion is a sophisticated Windows process injection tool that implements multiple evasion techniques, including registry-based file hiding, process hollowing, and process overwriting. The tool supports both x64 and x86 architectures and provides a flexible interface through CLI, interactive mode, and configuration files.

## Features
- **Multiple Injection Techniques**
  - Process Hollowing
  - Process Overwriting (Windows 11 24H2 compatible)
- **Flexible Input Methods**
  - File-based payload loading
  - Registry-based payload storage and loading
- **Architecture Support**
  - x64 (64-bit) support
  - x86 (32-bit) support
- **User Interface Options**
  - Command-line interface
  - Interactive mode
  - Configuration file support
- **Custom Payload Support**
  - Built-in test payloads for both x64 and x86
  - Support for custom payloads

## Technical Details

### Process Overwriting
Process Overwriting was implemented to bypass the new restrictions introduced in Windows 11 24H2. Unlike Process Hollowing, this technique injects and resumes the process from a MEM_IMAGE region as opposed to MEM_PRIVATE.

#### Implementation Steps:
1. A benign process is started in a suspended state
2. Using VirtualProtectEx, the memory regions are configured with appropriate permissions
3. The memory region is overwritten with the payload
4. Section permissions are patched to match PE requirements
5. The process is resumed, executing the payload seamlessly

#### Advantages:
- Bypasses MEM_PRIVATE restrictions
- Avoids triggering ZwQueryVirtualMemory checks for MEM_IMAGE
- Enhanced stealth through existing memory region utilization

### Registry-based File Hiding
The tool can store PE files in the Windows Registry, split into multiple parts for better management and stealth.

## Usage

### Command Line Interface
```bash
Meva.exe [options]

Options:
    -i, --interactive           Run in interactive mode
    -c, --config     [path]     Use configuration file
    -w, --write      [path]     Write PE file to registry
    -s, --source     <path>     Source PE file path
    -d, --dest       <path>     Destination PE file path
    -r, --reg        <key>      Registry key for source PE
    -p, --prefix     <prefix>   Registry value prefix
    -t, --technique  <type>     Injection technique (Hollow|Overwrite)
    -h, --help                  Show this help message
```

### Examples
1. Write PE to registry using config file:
   ```bash
   Meva.exe -c config.ini -w
   ```

2. Write PE to registry with specific file:
   ```bash
   Meva.exe -w c:\LightningGod\hello.exe
   ```

3. Execute PE from file using process hollowing:
   ```bash
   Meva.exe -s c:\LightningGod\hello.exe -d c:\LightningGod\dest.exe -t Hollow
   ```

4. Execute PE from registry using process overwriting:
   ```bash
   Meva.exe -r \HKEY_CURRENT_USER\LightningGod -p Part -d c:\LightningGod\dest.exe -t Overwrite
   ```

5. Run in interactive mode:
   ```bash
   Meva.exe -i
   ```

## Configuration
The tool uses a configuration file (`config.ini`) for persistent settings. Key configuration options include:
- Source input method `FILE` or `REG`
- Injection technique `Hollow` OR `Overwrite`
- Source and destination PE paths
- Registry settings for PE storing

## Important Notes
1. Architecture matching is required:
   - 32-bit loader for 32-bit to 32-bit injection
   - 64-bit loader for 64-bit to 64-bit injection
2. Process type matching is required:
   - GUI to GUI
   - Console to Console
3. Sizing requirements
   - Source image size must be smaller than Destination image size

## References
- [Process Hollowing and PE Image Relocations](https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations)
- [Code Reversing](https://www.codereversing.com/archives/261)
- [Code Reversing](https://www.codereversing.com/archives/261)
- [Hasherezade's Process Hollowing on Win11 24H2](https://hshrzd.wordpress.com/2025/01/27/process-hollowing-on-windows-11-24h2/)
