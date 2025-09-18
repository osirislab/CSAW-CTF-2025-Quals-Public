
# CSAW-CTF-2025 QUALS - PWN Challenge: Mooneys_Bookstore

### Category: Pwn  
### Difficulty: Easy 
### Author: ScriptKiddo
## Description

You think it’s just input. Just another binary.  
But this stack? It’s mine.  
Overflow it. Follow the trail. I left a key behind.  
If you’re paying attention, you’ll find it.  
Slip once, and the story ends before it begins.

 ## Concepts Tested

- Basic stack buffer overflow 
- Return-to-function control flow redirection
- Memory leak via unformatted `printf("%lx")`
- Canary bypass
- Little-endian memory layout and interpretation
- Basic reverse engineering with tools like Ghidra, IDA, or Binary Ninja
  
## Tools
- Binary Ninja or IDA to inspect the binary file  
- GDB with gef or pwndbg to debug the binary  
- Python + pwntools to write a solution script  


## Instructions
### 1. Download the required files
Download the binary (overflow_me), docker file and flag.txt. 

### 2. Build the Docker Image
Run the following commands to build and run the Docker image:

```bash
docker build -t overflow_me .
docker run --rm -it -p 5454:5454 overflow_me
```

### 3. Test Remotely - Connect to the Challenge and Play
Use the following command to connect and poke around manually:

```bash
socat - TCP:localhost:5454
```

## Solution
### Steps:
- Leak a memory address and reuse it to pass a hidden check.
- Extract the stack canary, then craft an overflow that preserves it.
- Redirect execution to the flag function by overwriting the return address.
  
```bash
python3 overflow_solver.py
```

