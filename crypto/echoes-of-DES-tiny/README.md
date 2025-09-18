# Echoes of DES-tiny

## Description
Wake up code monkey.

As you know, last week a probe made parking orbit about Earth.
First contact was a dud, the probe's old, thought to be bricked by interstellar radiation.
We scraped off some code and set one of corporate's shiny new Reversing Bots on translating, but the clanker must've activated some defenses and the software got scrambled.
Before scrambling though, we sniffed the probe scraping data from a dorsey archive? Not sparking any of my plugs. 
Since then, the probe's been chirping. Doesn't matter what protocol we shoot it, the response is the same:
`ff988a2b2a0f7310bb85abdeea7f7c2482c767ab7edc8d409e3045fb1fb8e19d18afc7b44d7b1882037715b37a117b62`

You're the only one left on call, time to earn your protein.

## Difficulty
beginner | intermediate: no real knowledge of specific crypto algorithms required, just basic hashing, ECB encryption/decryption, & brute-force understanding/wordlist utilization

## Time Spent
No more than 60 minutes | use strings, get wordlist, brute-force with simple python script, read code, "reverse engineer" decryption

## Tools
- strings
- cyberchef
- pycryptodome
- rockyou.txt or similar

## Infrastructure
- None

## Artifacts
- encrypted python script hinting towards the known plaintext and encryption mechanism

## Fun
- I think it'll be fun and I'll be sure to pick a password that's common across multiple wordlists as that's the most likely source of frustration
