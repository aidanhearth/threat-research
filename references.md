# References

## Primary source (PoC under analysis)

- **Article**: cocomelonc, "Malware shellcode delivery via signal - part 2. The Linux receiver (Goertzel Algorithm). Simple C example", 2026-05-26
  https://cocomelonc.github.io/malware/2026/05/26/malware-tricks-57.html

- **GitHub PoC repository**: `cocomelonc/signal-malware-delivery-poc`
  https://github.com/cocomelonc/signal-malware-delivery-poc

- **Author profile**: @cocomelonc
  https://cocomelonc.github.io/

- **Series root**: malware-tricks (long-running educational malware analysis series)

## Source files analysed

All retrieved 2026-05-28 from the main branch of the public repository:

| File | URL |
|---|---|
| `receiver_live.c` | https://raw.githubusercontent.com/cocomelonc/signal-malware-delivery-poc/main/receiver_live.c |
| `transmit_live.c` | https://raw.githubusercontent.com/cocomelonc/signal-malware-delivery-poc/main/transmit_live.c |
| `transmit_live.py` | https://raw.githubusercontent.com/cocomelonc/signal-malware-delivery-poc/main/transmit_live.py |
| `README.md` | https://raw.githubusercontent.com/cocomelonc/signal-malware-delivery-poc/main/README.md |

## Prior academic and research work on acoustic covert channels

- **Hanspach & Goetz (2013)**: "On Covert Acoustical Mesh Networks in Air", Journal of Communications
  https://www.jocm.us/index.php?m=content&c=index&a=show&catid=124&id=600
  First major peer-reviewed demonstration of acoustic data exfiltration using laptop hardware at ultrasonic frequencies, ranges up to ~20m

- **Carrara, B. & Adams, C. (2014)**: "Out-of-Band Covert Channels — A Survey", ACM Computing Surveys
  Surveys electromagnetic, acoustic, optical, and thermal covert channels

- **Ben-Gurion University Cyber Security Research Center**: multi-year programme on air-gap bridging
  - AirHopper (FM radio from monitor cables)
  - GSMem (GSM-band emanation from RAM bus)
  - DiskFiltration (HDD acoustic emission)
  - Many others

- **BadBIOS (2013, contested)**: Dragos Ruiu's reported firmware allegedly using ultrasonic communication. Never independently reproduced; included for historical context only.

## Signal processing background

- **Goertzel algorithm — original paper**: Goertzel, G. (1958), "An Algorithm for the Evaluation of Finite Trigonometric Series", American Mathematical Monthly, 65(1)

- **Goertzel algorithm — practical overview**: https://en.wikipedia.org/wiki/Goertzel_algorithm

- **Bell 202 modem standard**: Bell System Technical Reference, Pub 41212 (1976) — defines 1200 Hz / 2200 Hz FSK modem signalling, originally for caller ID and low-speed data modems

- **HDLC frame format**: ISO/IEC 13239 — origin of the 0x7E frame-delimiter byte and 0xAA preamble convention

## Detection / defensive research

- **MITRE ATT&CK Technique T1095** — Non-Application Layer Protocol
  https://attack.mitre.org/techniques/T1095/
  (Acoustic delivery is a sub-case: non-IP, non-application-layer)

- **MITRE ATT&CK Technique T1059** — Command and Scripting Interpreter
  https://attack.mitre.org/techniques/T1059/
  (Shellcode execution after acoustic delivery)

- **Falco runtime security**: https://falco.org/
- **Sigma detection format**: https://github.com/SigmaHQ/sigma
- **YARA**: https://virustotal.github.io/yara/

## Author of this analysis

Aidan Hearth — independent cybersecurity research (malware triage / vulnerability research / offensive security tooling / CTI)

- Website: https://aidanhearth.com
- Email: security@aidanhearth.com (general), disclosure@aidanhearth.com (vulnerability disclosure)
- PGP fingerprint: `1964 9029 B47B 3411 910C 0D68 E8AA ABB8 4060 140F`
- PGP keyserver: https://keys.openpgp.org/

---

_Last updated 2026-05-28_
