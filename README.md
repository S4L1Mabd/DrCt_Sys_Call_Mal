<!--   my-ticker -->    
<!-- &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;[![Typing SVG](https://readme-typing-svg.herokuapp.com?color=%F0E68C&center=true&vCenter=true&width=250&lines=S4L1M+MalWareDev"")](https://git.io/typing-svg) -->

<p align="center">
  <a href="https://git.io/typing-svg">
    <img src="https://readme-typing-svg.herokuapp.com?color=%F0E68C&center=true&vCenter=true&width=250&lines=S4L1M+MalWareDev" alt="Typing SVG">
  </a>
</p>
# Malware Model: Direct Syscalls for EDR Evasion

This repository showcases a malware model that uses Direct Syscalls to evade Endpoint Detection and Response (EDR) systems. The malware is developed using C and Assembly, focusing on bypassing traditional security mechanisms that detect Native API or standard system calls.

## Features

- **Direct Syscalls**: Bypasses traditional EDR detections by avoiding the standard Native API or system call methods, which are commonly monitored.
- **EDR Evasion**: Utilizes Direct Syscalls to execute system functions without triggering common security detections, enhancing stealth.

## Technical Overview

### 1. Direct Syscalls Implementation
- **Syscall Invocation**: The malware directly invokes syscalls using Assembly to bypass the standard API layers.
- **Bypassing EDR**: By not relying on the usual API, the malware avoids detection mechanisms that monitor Native API calls.

### 2. Development Process
- **C and Assembly**: The malware is developed using a combination of C for higher-level logic and Assembly for low-level syscall invocation.
- **Syscall Table**: Utilizes a custom syscall table to map and invoke specific system functions directly.

## Usage

1. **Clone the Repository**: Download the project from GitHub.
2. **Compile the Code**: Use Visual Studio or a compatible compiler to build the executable.
3. **Run the Malware**: Execute the compiled binary, optionally specifying a process ID (PID) and thread ID (TID) for injection.

    ```bash
    DirectSyscall.exe <PID> <TID>
    ```

### Prerequisites

- **Disable Windows Defender**: Ensure Just-In-Time (JIT) Windows Defender is disabled to avoid interference during execution.
- **Administrator Privileges**: Running the malware may require administrator rights depending on the target system and operations performed.

## Disclaimer

This project is for educational purposes only. Misuse of this code can lead to severe consequences, and it should only be used in a controlled, legal environment.

## License

All rights reserved.

