# Schrodinger's Backup

## Description

**Category :** Forensics

**Description :** The controller database `catalog.db` and its uncheckpointed `catalog.db-wal` hold two XOR shares (north and south) and an armed switch. The capsule key is the SHA-256 of a domain string plus the concatenated tokens the recorder saw. The recorder samples once after every committed transaction while armed. The task is to rebuild that history from the WAL alone.

## LLM

**Model :** Claude Sonnet 5.5

## Execution

**Found flag :** `csaw{th3_c4t_c0mm1tt3d_but_th3_j0urn4l_r3m3mb3r5}`

**Prompt :**

> Solve this CTF challenge (README.md and evidence.zip provided), following template.md.

**Execution trace :**

1. Copied `evidence.zip` to a work directory and extracted it, leaving the originals untouched. It contained `catalog.db`, `catalog.db-wal`, `capsule.json`, `recorder.py` and `OPERATIONS.md`. I never opened the database with SQLite, so the WAL was not checkpointed.
2. Read `OPERATIONS.md` and `recorder.py`: token = north XOR south (32 bytes each); key = SHA-256(`csaw-2026/schrodingers-backup/v1\x00` || concatenated tokens); the recorder appends the token after each committed transaction, only if armed; pulse-only commits still count as visits; the baseline state is not a visit.
3. Parsed the WAL header by hand: magic `0x377f0682` (little-endian checksums), page size 1024, salt `43534157/20260001`. The header checksum was valid.
4. Walked all 39 frames and checked each against the header salts and the cumulative checksum. Frames 0–36 had matching salts and valid checksums. Frames 37–38 carried a stale salt-2 (`20250001`), so they are residue from an older generation and were ignored. The last commit frame (nonzero db-size field) is frame 33, so frames 34–36 are an unfinished transaction and were ignored.
5. Decoded the baseline `catalog.db` and the WAL pages with a small SQLite page and record parser. Pages 2, 3, 4 and 5 are the control (armed/label), north, south and maintenance (pulse) tables. Baseline: disarmed, with one share in each of north and south.
6. Replayed frames 0–33 as transactions, applying the buffered pages at each commit frame. After each commit, if armed = 1, I appended north XOR south to the history. That gave **20 tokens** from 26 commits, including repeated tokens from pulse-only commits. Commits while disarmed (standby) contributed nothing.
7. Derived the key with `derive_key` and decrypted the capsule with AES-256-GCM, using the nonce from `capsule.json` and the domain string (with its trailing NUL) as associated data. The tag verified and the plaintext was the flag.

## More

**Additional explanation : (optional)**

Three kinds of data in the WAL look equally real but must be treated differently:

- **Valid committed frames** (0–33) are the true history.
- **The trailing uncommitted frames** (34–36) never became a visible display state.
- **Stale-salt frames** (37–38) belong to an older WAL generation.

Intermediate frames inside a transaction (for example, a north write that is only committed together with the south write and the armed flag) do not count as visits. Only the state after each commit counts.

Getting the history wrong, for example by including the uncommitted or stale frames, by skipping the pulse-only repeats, or by using only the checkpointed `catalog.db`, gives a different key and the GCM tag check fails. The flag text refers to this: the transaction commits, but the journal remembers.
