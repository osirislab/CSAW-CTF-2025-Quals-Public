# Celestial Cafeteria

## Category: Pwn

* Long-distance interstellar journey must have made you very starving!
* In Celestial Cafeteria, your can customize whatever food you want!
* Just place an order and enjoy the feast!

## Difficulty: Medium

* Players should be familiar with **house of botcake** technique from **how2heap**.
* Players may need to understand **FSOP** technique.

## Time Spent

* 2 hours or so: This is a **heap** challenge that involves only one exploitation technique.

## Tools

* Binary Ninja or IDA to inspect the binary file
* GDB with gef or pwndbg to debug the binary file
* Python pwntools to write a solution script

## Infrastructure

* A docker container with an `linux/amd64` image of `ubuntu@sha256:dbdff34bb41cecdb07c79af373b44bb4c9ccba2520f014221fb95845f14bc6c1` is required to compile C source code of this Pwn challenge to binary.
    ```bash
    gcc -o chal main.c -pie -fPIE -fstack-protector-strong -Wl,-z,relro,-z,now
    ```

* A docker container is required to run this Pwn challenge.
    ```bash
    docker build -t celestial-cafeteria .
    docker run -p 21008:21008 --privileged celestial-cafeteria
    ```

## Artifacts

* Participants must **NOT** have access to `main.c`.
* **Only** `chal`, `ld-linux-x86-64.so.2`, and `libc.so.6` can be provided to participants.
