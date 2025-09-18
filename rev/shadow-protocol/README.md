# Shadow Protocol

### Category: Rev

Space explorers have recovered a strange encryption oracle drifting in deep space, originating from an alien civilization in a distant galaxy. The oracle emits encrypted transmissions using an unfamiliar cosmic protocol.
---

## 💢 Difficulty
**Medium/Hard**

---

## 🧠 Fun Factor

This challenge blends several advanced reverse engineering concepts including:
- Custom encryption mechanisms
- Dynamic memory structures
- Side-channel analysis potential
- Thematic alignment with time dilation

It rewards deep binary analysis while also offering room for creative exploitation paths.

---

## ⏱️ Expected Solve Time

- **Solution 1 (Protocol Reversal):** 1–3 hours  
- **Solution 2 (Side-Channel Exploit):** 0.5–1 hours  
---

## 🔧 Solve Tools

Suggested tools:
- Disassembler (Ghidra, IDA, Binary Ninja)
- Debugger (gdb + pwndbg/gef)
- Python for automation and scripting

---

## 🏗️ Infrastructure

- Participants are provided a **Linux handout binary**:  
  `rev/shadow_protocol/handout/shadow_protocol`

- The **remote binary** is containerized and exposed via `socat` on a TCP port:  
  `rev/shadow_protocol/remote/shadow_protocol`

- The remote binary reads the flag from:  
  `rev/shadow_protocol/remote/flag.txt`  
  *(This file is **not** distributed with the handout)*

---

## 📦 Artifacts

- `handout/shadow_protocol`: Participant's binary (for handout)
- `remote/shadow_protocol`: Remote binary
- `remote/flag.txt`: Flag file (used on remote only)

---

## ⚔️ Solve Paths

### Full Protocol Reversal  
Reverse the encryption logic from the handout binary and recover the original message using local analysis.

### Side-Channel Attack  
An alternate approach leverages system behavior to recover the key more quickly, requiring creative setup or exploitation.

---

## 🛰️ Remote Binary Behavior

The **remote binary differs slightly** from the handout:
- It uses a **future-based seed** (`time + 5 years`)
- This enforces use of advanced techniques such as environment manipulation
- The time offset supports the challenge's **space-time distortion** theme

---
