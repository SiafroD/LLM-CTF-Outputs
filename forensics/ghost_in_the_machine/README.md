# Ghost in the Machine

## Description

**Category :** Forensics / Networking

**Description :** A host beacons out with identical `PING` UDP packets. The payload, IP ID, ports and checksums are all constant, yet data is leaking. The task is to find the hidden message in the 504-packet `capture.pcap`.

## LLM

**Model :** Claude Sonnet 5.5

## Execution

**Found flag :** `csaw{t1m1ng_1s_3v3ryth1ng_1n_th3_s1l3nt_ch4nn3l}`

**Prompt :**
```
You are solving CTF challenges of various themes and difficulty.
For every challenge, follow the template.md file.
[Attached: README.md ("Ghost in the Machine", Forensics/Networking, Hard, flag format csaw{...}) and capture.pcap]
```

**Execution trace :**
1. I read the README. Its hints say to look at the columns usually ignored, that some packets are decoys, and that the key is in another skipped column.
2. `file` reported `data` for the capture. The hex header `d4c3b2a1`-style magic (little-endian, linktype 1) showed it was a normal Ethernet pcap. scapy and tshark were not installed, so I wrote a small struct-based parser.
3. I counted the distinct values of every field across the 504 packets.
   - Constant in every packet: length (46), IP ID, TOS, flags, protocol, src/dst IP, destination port 9000, UDP length, UDP checksum and payload `PING`.
   - Varying: **TTL** (64 in 385 packets, 113 in 119), **source port** (121 distinct values) and **timestamps**.
4. The TTL 113 packets have random source ports in the 50000s and irregular timing, so they are the decoys. I dropped them, which left 385 genuine packets.
5. The genuine packets use only 6 source ports: 40115, 40104, 40052, 40100, 40111 and 40119. They cycle in that order, changing every 8 packets.
   - Subtracting 40000 gives 115, 104, 52, 100, 111, 119, which is ASCII `s h 4 d o w`. This is the key, hidden in the source-port column.
   - Each group of 8 packets is one byte, and 384 packets give 48 bytes.
6. The inter-arrival gaps between genuine packets are bimodal: about 0.035–0.065 s and about 0.12–0.165 s. A gap over 0.1 s is bit 1 and a shorter one is bit 0. This is a timing covert channel.
7. I packed the 384 bits into 48 bytes, MSB first. The result was `101b5513...`, which is not readable. XORing with the repeating key `sh4dow` gave the flag.

```python
bits = [1 if gap > 0.1 else 0 for gap in gaps_between_ttl64_packets]
raw  = bytes(int(''.join(map(str, bits[i:i+8])), 2) for i in range(0, 384, 8))
flag = bytes(c ^ b"sh4dow"[i % 6] for i, c in enumerate(raw))
# b'csaw{t1m1ng_1s_3v3ryth1ng_1n_th3_s1l3nt_ch4nn3l}'
```

## More

**Additional explanation :**
- **Covert channel:** the data is carried by packet timing, with one bit per inter-packet gap. Every visible field is identical, so a byte-level firewall log sees nothing unusual.
- **Decoys:** the 119 packets with TTL 113 add random timing and random source ports. Including them would break the bit boundaries and the 8-packet port cycle, so filtering on TTL is the key step.
- **Key:** the source-port low part (port − 40000) spells `sh4dow`, which is the XOR key. The ports also mark byte boundaries. The 385th packet is just a trailing one that carries no bit.
- **Check:** the decoded output is valid leetspeak English and matches the `csaw{...}` format, so the bit threshold and key are right.