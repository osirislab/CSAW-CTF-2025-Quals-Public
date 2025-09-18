# Power Up

## Category: Pwn

* Your starship have been wandering for weeks in this derelict orbit, whose core is out of energy.
* You are the last engineer who must ignite the core with energy using proper modules.
* Power up the starship. Or stay stranded forever.

## Difficulty: Easy

* Players should be familiar with **large bin attack** technique from **how2heap**.
* Players should know how glibc's **pseudo-random number generator** works.

## Time Spent

* 1 hours or so: This is a **heap** challenge that involves only one exploitation technique.

## Tools

* Binary Ninja or IDA to inspect the binary file
* GDB with gef or pwndbg to debug the binary file
* Python pwntools to write a solution script

## Infrastructure

* A docker container with an `linux/amd64` image of `ubuntu@sha256:dbdff34bb41cecdb07c79af373b44bb4c9ccba2520f014221fb95845f14bc6c1` is required to compile C source code of this Pwn challenge to binary.
    ```bash
    gcc -o chal main.c -no-pie -fstack-protector-strong -Wl,-z,relro,-z,now
    ```

* A docker container is required to run this Pwn challenge.
    ```bash
    docker build --platform linux/amd64 -t ctf-chal .
    docker run --rm -it -p 21005:21005 ctf-chal
    ```

## Artifacts

* Participants must **NOT** have access to `main.c`.
* **Only** `chal`, `ld-linux-x86-64.so.2`, and `libc.so.6` can be provided to participants.
