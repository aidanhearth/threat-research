# Detection Rules — Goertzel FSK Acoustic Shellcode Covert Channel

**Target**: Compiled binaries (and source code) implementing the cocomelonc PoC or close derivatives
**Scope**: Linux ELF binaries linked against ALSA + libm performing acoustic shellcode delivery
**Coverage**: YARA (static binary signature) + Sigma (process behaviour) + Falco (eBPF host-based audit)
**False positive notes**: Each rule documents expected legitimate matches and tuning advice

---

## 1. YARA rule — static binary signature

```yara
rule Acoustic_FSK_Shellcode_Receiver_Cocomelonc
{
    meta:
        author      = "Aidan Hearth (security@aidanhearth.com)"
        date        = "2026-05-28"
        description = "Detects compiled binaries implementing acoustic shellcode delivery via Bell 202 FSK + Goertzel algorithm (cocomelonc PoC and close derivatives)"
        reference   = "https://cocomelonc.github.io/malware/2026/05/26/malware-tricks-57.html"
        reference   = "https://github.com/cocomelonc/signal-malware-delivery-poc"
        severity    = "high"
        tlp         = "white"

    strings:
        // Author-specific string markers (very high confidence, low FP)
        $marker_cat_emoji  = "[=^..^=]" ascii
        $marker_bell202    = "Bell 202 FSK" ascii nocase
        $marker_recv_live  = "receiver_live" ascii
        $marker_trans_live = "transmit_live" ascii

        // Protocol-specific string markers
        $str_preamble_msg  = "preamble detected" ascii nocase
        $str_capture_msg   = "listening for Bell 202" ascii nocase

        // Preamble byte sequence (this is the HDLC sync marker the receiver hunts for)
        $hex_preamble = { AA AA AA AA 7E }

        // Hardcoded telecom frequency constants in machine code (little-endian)
        //   FREQ_MARK  = 2200 = 0x898   --> bytes: 98 08
        //   FREQ_SPACE = 1200 = 0x4B0   --> bytes: B0 04
        //   BAUD_RATE  = 300  = 0x12C   --> bytes: 2C 01
        //   SAMPLE_RATE= 48000 = 0xBB80 --> bytes: 80 BB
        // Combined sequence often appears in initialised .rodata or as immediate operands
        $hex_freq_pair = { 98 08 ?? ?? B0 04 }
        $hex_baud_sample = { 2C 01 ?? ?? ?? ?? 80 BB }

        // ALSA function names (will appear in dynamic symbol table)
        $sym_snd_pcm_open       = "snd_pcm_open" ascii
        $sym_snd_pcm_readi      = "snd_pcm_readi" ascii
        $sym_snd_pcm_set_params = "snd_pcm_set_params" ascii

        // Math import (Goertzel requires cos + sin)
        $sym_cos = "cos" ascii fullword
        $sym_mmap = "mmap" ascii fullword

    condition:
        // ELF magic
        uint32(0) == 0x464C457F
        and
        (
            // High-confidence match: cocomelonc-specific markers + preamble
            (
                $marker_cat_emoji
                and ($marker_bell202 or $marker_recv_live or $marker_trans_live)
            )
            or
            // Generic acoustic-FSK-shellcode match: preamble + freq constants + ALSA + mmap
            (
                $hex_preamble
                and ($hex_freq_pair or $hex_baud_sample)
                and 2 of ($sym_snd_pcm_*)
                and $sym_mmap
                and $sym_cos
            )
            or
            // Protocol message strings + preamble (likely derivative with renamed binary)
            (
                ($str_preamble_msg or $str_capture_msg)
                and $hex_preamble
                and 1 of ($sym_snd_pcm_*)
            )
        )
}
```

**False positive tuning**:

- Pure ALSA recording applications (Audacity, OBS, etc.) will match individual `snd_pcm_*` symbols but never the preamble bytes or the FSK frequency constants
- Voice modem software (rare on modern Linux) might match Bell 202 strings — combine with `mmap` PROT_EXEC behaviour rule (Sigma below)
- Educational signal processing tutorials may include Goertzel + cos/sin but not the preamble pattern
- The `$hex_preamble` (`AA AA AA AA 7E`) byte sequence may incidentally appear in compressed/encrypted data — the rule requires it AND other indicators

---

## 2. Sigma rule — process behaviour (Linux auditd)

```yaml
title: Acoustic Shellcode Delivery via FSK + Audio Capture
id: 9c0e7a3f-2b58-4a1d-bc4e-d5e7f8a1c9b0
status: experimental
description: |
  Detects a process that opens an ALSA capture device AND allocates RWX
  anonymous memory AND has no network sockets. This combination is highly
  unusual for legitimate audio applications and matches the behaviour of
  the cocomelonc acoustic-FSK-shellcode receiver PoC.
author: Aidan Hearth
date: 2026-05-28
references:
    - https://cocomelonc.github.io/malware/2026/05/26/malware-tricks-57.html
    - https://github.com/cocomelonc/signal-malware-delivery-poc
logsource:
    product: linux
    service: auditd
detection:
    audio_capture_open:
        type: PATH
        name|startswith:
            - '/dev/snd/pcmC'
            - '/dev/snd/controlC'
        nametype: NORMAL
        a0|endswith:   # open() flag — read access
            - '|O_RDONLY'
            - '|O_RDWR'
    rwx_mmap:
        type: SYSCALL
        syscall: mmap
        a2|contains:
            - 'PROT_EXEC'
        a2|contains|all:
            - 'PROT_WRITE'
        a3|contains:
            - 'MAP_ANON'
    no_network_socket:
        # exclude processes that have created any inet socket
        type: SYSCALL
        syscall: socket
        a0:
            - 2   # AF_INET
            - 10  # AF_INET6
    condition: audio_capture_open and rwx_mmap and not no_network_socket
falsepositives:
    - Legitimate audio-DSP applications that JIT-compile filter code (rare; investigate the JIT framework and parent process)
    - Sandboxed audio plugins (LV2 / VST3 hosts under containment)
level: high
tags:
    - attack.defense_evasion
    - attack.t1095        # Non-Application Layer Protocol (acoustic = non-IP)
    - attack.execution
    - attack.t1059        # Command and Scripting Interpreter (shellcode execution)
```

**Tuning notes**:

- Strict `not socket(AF_INET)` may miss attackers who also create a benign network socket as decoy — consider relaxing to `socket count < threshold` in production
- Audio device path varies by distribution (`/dev/snd/...` is typical; PulseAudio/PipeWire abstract this via libasound)
- Pair with EDR memory-scanning of any process that triggers the rule, looking for the preamble byte sequence in its address space

---

## 3. Falco rule (eBPF host-based audit)

For environments running Falco or custom eBPF audit (Suricata is network-only and won't see this; this is a Falco-compatible YAML):

```yaml
- rule: Acoustic_FSK_Shellcode_Loader
  desc: >
    Process opens ALSA audio capture device, allocates RWX anonymous
    memory, and has no outbound network connections within a 60-second
    window. Matches the cocomelonc acoustic-FSK-shellcode receiver
    behaviour pattern.
  condition: >
    (evt.type = openat
     and (fd.name startswith "/dev/snd/pcmC"
          or fd.name startswith "/dev/snd/controlC"))
    and proc.aname != "pulseaudio"
    and proc.aname != "pipewire"
    and proc.aname != "wireplumber"
    and proc.aname != "obs"
    and proc.aname != "audacity"
    and proc.aname != "ffmpeg"
    and (proc.cmdline contains "mmap" or proc.libs contains "libasound.so")
    and not proc.is_container
  output: >
    Audio capture opened by suspicious process: user=%user.name
    process=%proc.name pid=%proc.pid cmdline=%proc.cmdline
    parent=%proc.pname libs=%proc.libs
  priority: WARNING
  tags: [acoustic_covert_channel, shellcode_loader, mitre_t1095, mitre_t1059]
  source: syscall
```

**Tuning notes**:

- The allowlist (`pulseaudio`, `pipewire`, `wireplumber`, `obs`, `audacity`, `ffmpeg`) covers the most common legitimate audio capture parents on modern Linux desktops — add site-specific entries (conferencing apps, voice assistants)
- Container exclusion (`not proc.is_container`) is conservative — adapt to your container strategy (Falco can also run inside containers)

---

## 4. Deployment recommendation

For maximum coverage, deploy in this layered order:

1. **YARA rule** in scheduled scan against all ELF binaries on critical hosts (~weekly), plus on every new binary write event (immediate). False-positive rate expected to be near zero for the high-confidence branch.
2. **Sigma rule** in real-time auditd processing (auditbeat → ElasticSearch / SIEM)
3. **Falco rule** in production Linux servers and CI/CD runners (where unauthorised audio capture would be highly anomalous)

Combined, the three layers cover: pre-execution (YARA static scan), real-time execution (Sigma), and runtime kernel events (Falco). The PoC author's binary contains all the distinctive markers and would be caught by the high-confidence YARA branch alone.

For environments where executable file scanning is too noisy, **the Falco rule is the highest-leverage single deployment** — it triggers only on the runtime behaviour combination (audio capture + suspicious process), which is the unavoidable signature of any acoustic shellcode loader regardless of how the binary is obfuscated.

---

## 5. Test coverage

To validate any of these rules in a controlled environment:

```bash
# Pull the public PoC into a sandboxed VM
git clone https://github.com/cocomelonc/signal-malware-delivery-poc.git
cd signal-malware-delivery-poc
gcc receiver_live.c -o receiver_live -lasound -lm

# 1. Test YARA: should match
yara /path/to/rule.yar receiver_live
# Expected: Acoustic_FSK_Shellcode_Receiver_Cocomelonc receiver_live

# 2. Test Sigma/Falco: run ./receiver_live in instrumented host
#    Falco rule should fire within seconds of execution

# 3. Test against unrelated audio apps to verify FP rate
yara /path/to/rule.yar /usr/bin/audacity /usr/bin/ffmpeg /usr/bin/obs
# Expected: no matches
```

---

_Independent threat research — Aidan Hearth 2026-05-28_
_Detection rules released under CC BY 4.0 — free to use, please credit Aidan Hearth + cocomelonc original PoC_
