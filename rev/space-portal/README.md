# Space Portal

## Category: Rev

* An intelligent portal can automatically transmit a spaceship to its destination, but you have to communicate with it in a special way.
* Once a spaceship enters the portal, unfortunately, a group of aliens invades the portal and traps the spaceship inside, but the portal itself open a wormhole for the spaceship to escape.
* The spaceship should retrieve the wormhole signature correctly, and verify it with the portal, so that the spaceship can escape from the invaded portal and be transported to a space coordinate.

## Difficulty: Medium

* This Rev challenge is inspired by the TDDP protocol.
* Players should have a complete understanding of the provided stripped binary, figuring out what the C structure of the interaction protocol is in detail.
* Players should write a "client" to communicate with the "server" by receiving and sending packets.

## Time Spent

* 2 hours or so: Reading and fully understanding a stripped binary file can be time-consuming.

## Tools

* Binary Ninja or IDA to inspect the binary file
* Python pwntools to write a solution script

## Infrastructure

* A docker container with an `linux/amd64` image of `ubuntu@sha256:dbdff34bb41cecdb07c79af373b44bb4c9ccba2520f014221fb95845f14bc6c1` is required to compile C source code of this Rev challenge to binary.
    ```bash
    sudo apt update
    sudo apt install libssl-dev
    gcc -o chal main.c -Wall -Wextra -fstack-protector -lcrypto -s
    ```

* A docker container is required to run this Rev challenge.
    ```bash
    docker build --platform linux/amd64 -t ctf-chal .
    docker run --rm -it -p 21000:21000 ctf-chal
    ```

## Artifacts

* Participants must **NOT** have access to `main.c`.
* **Only** `chal` can be provided to participants.
