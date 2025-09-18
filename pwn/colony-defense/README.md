# Colony Defense

## Category: Pwn

* A group of colonists have finished colonizing a planet in the universe, but the unknown territory of the universe is extremely dangerous.
* An aggressive alien race has begun an invasion of the colony and the colonists must build weapons with limited resources to defend themselves against the attack.
* The colonists have to try their best to defend their new home, even considering dying with the aliens together.

## Difficulty: Hard

* Players should have a knowledge of how to retrieve necessary information if only the heap area can be read.
* Players should be familiar with **unsafe-unlink** technique from **how2heap**.
* Players should know what is the `pointer_guard` field in the `fs_base` structure, and how the `__run_exit_handlers` function works with the `initial` structure.

## Time Spent

* 3 hours or so: This is a **heap** challenge that involves multiple heap exploitation techniques.

## Tools

* Binary Ninja or IDA to inspect the binary file
* GDB with gef or pwndbg to debug the binary file
* Python pwntools to write a solution script

## Infrastructure

* A docker container with an `linux/amd64` image of `ubuntu@sha256:dbdff34bb41cecdb07c79af373b44bb4c9ccba2520f014221fb95845f14bc6c1` is required to compile C source code of this Pwn challenge to binary.
    ```bash
    gcc -o chal main.c -pie -fPIE -fstack-protector-strong -Wl,-z,relro,-z,now -s
    ```

* A docker container is required to run this Pwn challenge.
    ```bash
    docker build -t colony-defense .
    docker run -p 21001:21001 --privileged colony-defense
    ```

## Artifacts

* Participants must **NOT** have access to `main.c`.
* **Only** `chal`, `ld-linux-x86-64.so.2`, and `libc.so.6` can be provided to participants.
