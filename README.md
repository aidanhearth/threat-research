# Goertzel FSK Acoustic Shellcode Covert Channel — Detection & Analysis

**Researcher**: Aidan Hearth (independent cybersecurity research)
**Subject**: Acoustic FSK shellcode delivery covert channel — defensive analysis
**Original PoC author**: @cocomelonc (cocomelonc.github.io)
**Original PoC publish date**: 2026-05-26
**This analysis ship date**: 2026-05-28
**Scope**: defensive analysis + detection rule development (YARA / Sigma / Falco/eBPF)
**License**: Detection rules and analysis released under [CC BY 4.0](LICENSE) — free to use, modify, and ship with credit. Original PoC referenced under educational use; analysis is original work by Aidan Hearth.

---

## What this is

A defensive analysis of a novel shellcode covert channel published by security researcher @cocomelonc on 2026-05-26. The PoC delivers Linux shellcode through audio between a speaker and microphone using Bell 202 FSK modulation and the Goertzel algorithm — **completely bypassing the network layer**.

This package contains:

1. [`analysis.md`](analysis.md) — Technical breakdown of the FSK protocol, Goertzel algorithm role, frame structure, and execution path
2. [`detection-rules.md`](detection-rules.md) — YARA, Sigma, and Falco/eBPF rules for detection in compiled binaries and process behaviour
3. [`references.md`](references.md) — Links to original PoC + author + related prior work

## Why it matters (defensive perspective)

- **Air-gap bypass**: Traditional network egress controls (firewall, EDR network telemetry, DNS sinkhole) are all irrelevant — the delivery channel is acoustic
- **Trust model break**: Endpoint detection traditionally assumes network-bound C2; an audio-only delivery requires fundamentally different telemetry (audio device access auditing)
- **Low complexity**: ~7 KB of C, ALSA + libm + math.h, compiles with one `gcc` command — accessible to mid-skill threat actors
- **Public PoC**: GitHub repo is public, source is well-commented, attackers will copy and modify rapidly

## Attribution + ethical scope

- Original PoC author @cocomelonc published this as educational research under his "malware-tricks" series (post #57)
- This is defensive analysis for blue teams and EDR vendors
- No third-party systems tested. No offensive use. The PoC was not modified or weaponized.

## Contact

- security@aidanhearth.com (general)
- disclosure@aidanhearth.com (vulnerability disclosure)
- PGP: `1964 9029 B47B 3411 910C 0D68 E8AA ABB8 4060 140F` (keys.openpgp.org VKS)

---

_Independent threat research — Aidan Hearth_
