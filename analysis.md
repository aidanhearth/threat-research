# Technical Analysis — Goertzel FSK Acoustic Shellcode Covert Channel

## 1. Architecture overview

The PoC implements an acoustic covert channel that delivers executable shellcode from a transmitter (speaker) to a receiver (microphone) on the same or adjacent machine. The delivery completely bypasses the network stack — no TCP, no UDP, no DNS, no IP traffic.

```
[ Attacker host ]                            [ Victim host ]
  shellcode bytes                              microphone (ALSA capture)
       |                                              |
       v                                              v
  transmit_live.c / transmit_live.py            receiver_live.c
       |                                              |
       v                                              v
  FSK modulator (Bell 202)                      Goertzel demodulator
  - 2200 Hz = bit 1                             - per-bit FFT-lite freq detect
  - 1200 Hz = bit 0                             - 40-bit preamble hunter
  - 300 baud, 48 kHz sample rate                - byte assembler + checksum
       |                                              |
       v                                              v
  ALSA playback (libasound)                     mmap(PROT_EXEC) + jump
                                                      |
                                                      v
                                                shellcode runs
```

## 2. Modulation: Bell 202 FSK

**Frequency-Shift Keying (FSK)** is one of the oldest digital modulation techniques. Bell 202 is a standard telephony modem protocol from the 1970s that defines:

- **Mark frequency** (binary `1`) = 2200 Hz
- **Space frequency** (binary `0`) = 1200 Hz
- **Baud rate** = 300 (each bit takes ~3.3 ms)

At a sample rate of 48 kHz, this gives **160 samples per bit period** (SPB = SAMPLE_RATE / BAUD_RATE).

The transmitter encodes each bit as a sine wave at the corresponding frequency:

```c
buf[(*pos)++] = (int16_t)(32767.0 * sin(2.0 * PI * freq * i / SAMPLE_RATE));
```

## 3. The Goertzel algorithm — why it's used here

The receiver needs to determine: "in this 160-sample window, is there more energy at 2200 Hz or at 1200 Hz?"

A full FFT would compute energy at all frequencies — unnecessary and slow. The **Goertzel algorithm** computes the energy at a *single target frequency* in O(N) time without complex number arithmetic:

```c
static double goertzel(const int16_t *s, int n, double freq) {
  double omega = 2.0 * PI * freq / (double)SAMPLE_RATE;
  double coeff = 2.0 * cos(omega);
  double q1 = 0.0, q2 = 0.0, q0;
  for (int i = 0; i < n; i++) {
    q0 = coeff * q1 - q2 + (double)s[i] / 32768.0;
    q2 = q1;
    q1 = q0;
  }
  return q1 * q1 + q2 * q2 - coeff * q1 * q2;
}
```

The receiver calls this twice per bit period — once for FREQ_MARK (2200 Hz), once for FREQ_SPACE (1200 Hz) — and compares:

```c
double pm  = goertzel(chunk, SPB, FREQ_MARK);
double ps  = goertzel(chunk, SPB, FREQ_SPACE);
uint8_t bit = (pm > ps) ? 1 : 0;
```

Goertzel is the same algorithm DTMF (touch-tone) detectors use for telephone keypad decoding. Its use here is entirely standard signal processing — no novelty in the algorithm itself, only in its application to malware delivery.

## 4. Frame structure

```
[ 0.5 s lead-in silence ] [ preamble 5 B ] [ length 2 B big-endian ] [ payload N B ] [ XOR checksum 1 B ] [ 0.3 s tail silence ]
```

Where:

| Field | Bytes | Value / purpose |
|---|---|---|
| Lead-in silence | (0.5 s of zeros) | Microphone settling + AGC stabilisation |
| Preamble | 5 | `0xAA 0xAA 0xAA 0xAA 0x7E` — sync pattern (40-bit rolling window match) |
| Length | 2 | Payload size in bytes, big-endian |
| Payload | N | Raw shellcode bytes |
| Checksum | 1 | XOR of all payload bytes |
| Tail silence | (0.3 s of zeros) | Capture buffer flush margin |

The preamble `0xAA AA AA AA 7E` is a classic HDLC/Bell-era sync marker — `0xAA` is alternating 1010 bits (excellent for clock recovery on FSK), and `0x7E` (01111110) is the HDLC frame-delimiter byte.

## 5. Receiver state machine

```
[HUNT] --(preamble match in 40-bit rolling window)--> [LENGTH]
[LENGTH] --(2 bytes received)--> [PAYLOAD]
[PAYLOAD] --(pay_len bytes received)--> [CHECKSUM]
[CHECKSUM] --(XOR validates)--> [EXECUTE]
                |
                +--(checksum fails)--> back to [HUNT], reset window
```

The HUNT state pushes each demodulated bit into a circular 40-bit buffer and checks every iteration whether the buffer content matches the preamble — robust to misalignment without requiring explicit synchronisation.

## 6. Execution path (the critical defensive surface)

After successful frame reception and checksum validation:

```c
void *mem = mmap(NULL, pay_len,
                 PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_ANON | MAP_PRIVATE, -1, 0);
memcpy(mem, payload, pay_len);
((void(*)())mem)();
```

This is **standard shellcode execution** — anonymous RWX memory mapping, copy payload, cast to function pointer, jump. The novelty is entirely in the delivery; the execution path is identical to any classic shellcode loader.

**Defensive opportunity**: A process that (a) opens ALSA capture device AND (b) calls `mmap(PROT_EXEC | PROT_WRITE | MAP_ANON)` AND (c) has zero network sockets is an extremely high-fidelity signal of acoustic shellcode loading.

## 7. Operational constraints (from author's README)

The author documents real-world constraints that limit attacker viability:

| Constraint | Impact |
|---|---|
| Distance: 30–50 cm speaker-to-mic | Requires close physical proximity (insider scenario or compromised peripheral) |
| Volume: 60–70% recommended | Audible to humans nearby (not stealth in occupied space) |
| Background noise sensitivity | Open-plan office or HVAC noise degrades reliability |
| Echo / multipath (ISI) | Hard surfaces cause inter-symbol interference |
| Baud rate 300 bps | A typical 4 KB shellcode takes ~110 seconds to transmit |
| Brute-force alignment (16× shifts × 10 samples) | Slow recovery from sync loss |

These constraints make the channel **impractical for typical remote-attack scenarios**, but viable for:

- **Insider exfil/delivery**: trusted device co-located with target
- **Air-gap bridging**: when network is fully isolated but room has computers
- **Compromised peripheral**: malicious USB speaker / Bluetooth device near target
- **TEMPEST-style covert channels**: when other side-channels are blocked

## 8. Prior work + context

Acoustic covert channels are a well-studied research area:

- **Hanspach & Goetz (2013)**: "On Covert Acoustical Mesh Networks in Air" — first major peer-reviewed academic demonstration of acoustic data exfiltration using laptop speakers/microphones at ultrasonic frequencies (up to 20 m range)
- **Carrara & Adams (2014)**: Surveys of acoustic covert channels including audible-frequency techniques
- **BadBIOS (2013, contested)**: Dragos Ruiu's reported (and disputed) firmware that allegedly used ultrasonic acoustic communication
- **GSMem / AirHopper / Ben-Gurion research group**: Multi-year program demonstrating various electromagnetic + acoustic air-gap bridging

The cocomelonc PoC's contribution is **engineering accessibility** — a small, well-documented, reproducible C codebase using off-the-shelf ALSA, not academic specialty hardware. This lowers the barrier for threat actor adoption.

## 9. Defensive coverage gap

Most EDR products focus on:

- Process tree anomalies (parent/child unusual relationships)
- Network indicators (C2 traffic, DNS exfiltration)
- File system anomalies (suspicious file writes, persistence)
- Memory injection patterns (process hollowing, reflective DLL)

**Acoustic delivery defeats network indicators entirely**. A process that has no network sockets is often given less scrutiny — exactly the wrong assumption when audio device access can be a delivery channel.

EDR vendors should add to their telemetry/heuristics:

1. **Audio capture device access auditing** for non-conferencing/non-recording applications
2. **mmap PROT_EXEC + audio capture** as a high-fidelity combined indicator
3. **Process linkage analysis**: ELF binary dynamically linked against `libasound.so.2` + `libm.so` but no network libraries
4. **Hardcoded telecom constant detection**: 2200/1200 Hz + 48000 sample rate + 300 baud in static binary analysis

See [`detection-rules.md`](detection-rules.md) for concrete YARA / Sigma / Falco rules implementing these heuristics.

---

_Independent threat research — Aidan Hearth 2026-05-28_
