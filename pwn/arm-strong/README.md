# Arm Strong

## Category: Pwn

* Neil Armstrong was an American astronaut who, as the commander of the 1969 Apollo 11 mission, became the first person to walk on the Moon on July 20, 1969.
* However, it seems that there was a secret conversation between Commander Neil Armstrong and Houston before that "famous saying".

## Difficulty: Hard

* Players should be familiar with ARM aarch64 instruction set.
* Players should know how to leak information using fmtstr.
* Players should be proficient in collecting right gadgets to perform ROP attack in arm64 architecture.

## Time Spent

* 3 hours or so: Finding gadgets and forming a ROP chain in arm64 architecture can be time-consuming for those who aren't familiar with ARM aarch64 instruction set.

## Tools

* Binary Ninja or IDA to inspect the binary file
* GDB with gef or pwndbg to debug the binary file
* ROPgadget or ropper to find gadgets
* Python pwntools to write a solution script

## Infrastructure

* A docker container with an `linux/arm64` image of `ubuntu@sha256:021ffcf72f04042ab2ca66e678bb614f99c8dc9d5d1c97c6dd8302863078adba` is required to compile C source code of this Pwn challenge to binary.
    ```bash
    gcc -o chal main.c -static -no-pie
    ```

* A docker container is required to run this Pwn challenge.
    ```bash
    docker build -t arm-strong .
    docker run -p 21003:21003 --privileged arm-strong
    ```

## Artifacts

* Participants must **NOT** have access to `main.c`.
* **Only** `chal` can be provided to participants.
