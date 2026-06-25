# Custom x64 Position-Independent Shellcode Engine with API Hashing

## Technical Executive Summary
This repository contains a low-level systems engineering project designed to demonstrate advanced knowledge of **Windows Internals**, **Obfuscation Techniques**, and **Custom Offensive Tooling Development**. 

The objective of this project is to build a fully position-independent x64 assembly payload that bypasses static signature detection mechanisms by implementing a custom API hashing pipeline, eliminating the reliance on obvious string artifacts or brittle, hardcoded virtual memory addresses.

## Core Competencies Demonstrated
* **Low-Level Operating System Architecture:** Direct manipulation of the Process Environment Block (PEB) and parsing of the Export Address Table (EAT).
* **Defensive Evasion & OPSEC:** Implementation of custom runtime hashing routines to strip highly-flagged ASCII string identifiers from compiled binaries.
* **Systems Programming:** Multi-language pipeline integration involving standalone **NASM x64 Assembly** and **C++** automation utilities.
* **Exploit Development Lifecycle:** Adherence to strict x64 calling conventions and memory management rules to ensure exploit stability.
