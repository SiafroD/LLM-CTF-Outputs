# Machine Head

## Description

**Category :** Reverse Engineering (Hard)

**Description :** `masterkey` is a stripped x86-64 PIE that takes the flag as `argv[1]` and prints either `Wrong.` or `Correct! That's the master key.`. The hint says the x86 code is only an interpreter for a custom bytecode, and that each character's check depends on a running state built from the characters before it. The flag format is `csaw{...}`.

## LLM

**Model :** Claude Sonnet 5.5

## Execution

**Found flag :** `csaw{cl1mb1ng_th3_v1rtu4l_st4ck_0n3_0pc0d3_4t_4_t1m3}`

**Prompt :**
```
You are solving CTF challenges of various themes and difficulty.
For every challenge, follow the template.md file.
[uploaded: masterkey, README.md]
New RE challenge.
```

**Execution trace :**

1. **Triage.** `file` shows a stripped PIE. `strings` shows only `usage`, `Wrong.` and `Correct!`. The `.text` section is only 0x259 bytes, which is too small for a real checker. The binary was not executable in the uploads folder, so I copied it to the working directory and ran `chmod +x`.

2. **Interpreter.** I disassembled `.text` with `objdump`. The `main` function does the following:
   - It requires `strlen(argv[1]) == 0x35` (53 characters).
   - It walks bytecode at `.rodata+0x40` (file offset `0x2040`) in 3-byte instructions `(op, a, b)`.
   - It keeps an 8-byte register file on the stack, initialised to zero.
   - It keeps a flag `r8d` that is set to 1 at the start and cleared by any failed compare.
   - It prints `Correct!` only if the flag is still 1 when it reaches the halt opcode.

3. **Opcode table.** All arithmetic is mod 256 and `m` is the register file.

   | op | mnemonic | semantics |
   |---|---|---|
   | `0x24` | ADDI | `m[a] += b` |
   | `0x1d` | MULI | `m[a] *= b` |
   | `0x4e` | XORR | `m[a] ^= m[b]` |
   | `0x6d` | ADDR | `m[a] += m[b]` |
   | `0x7a` | XORI | `m[a] ^= b` |
   | `0x91` | LOAD | `m[a] = argv[1][b]` |
   | `0xa7` | CMPI | if `m[a] != b`, flag = 0 |
   | `0xb2` | ROLI | `m[a] = rol8(m[a], b)` |
   | `0xe0` | HALT | stop, print result |

4. **Bytecode structure.** My Python decoder found 638 instructions: one prelude (`XORI r1, 60`), then 53 identical-shaped 12-instruction blocks, then `HALT`. Each block does the following:
   ```
   r0 = flag[i]; r0 ^= k1; r0 += k2; r0 = rol(r0, k3); r0 ^= 195; r0 *= 27
   r0 ^= r1;  CMPI r0, target_i          # check using the accumulator
   r2 = flag[i]; r1 += r2; r1 = rol(r1, 3); r1 ^= 158   # fold char into accumulator
   ```
   This matches the "running memory" hint: `r1` carries every previously accepted character, so the characters have to be recovered in order.

5. **Solver.** I wrote a Python emulator of the VM. For position `i` it tries every printable byte, runs the whole program, and accepts a candidate whose first failed `CMPI` comes after this block's `CMPI` (pc `8+12*i`). Because the earlier characters are already fixed, exactly one byte survives per position. My first attempt used the wrong block size (9 instead of 12) and gave ambiguous candidates, so I corrected it. The run then produced a unique byte at all 53 positions.

6. **Verification.**
   ```
   $ ./masterkey 'csaw{cl1mb1ng_th3_v1rtu4l_st4ck_0n3_0pc0d3_4t_4_t1m3}'
   Correct! That's the master key.
   ```

## More

**Additional explanation :**
The flag reads "climbing the virtual stack one opcode at a time" in leetspeak. The prefix and the final `}` were also recovered by the solver, not assumed, which is a good sanity check on the emulator.

The per-character transform is invertible, so I could have inverted the program backwards. Brute-forcing against the emulator is simpler and less error-prone, since it reuses the exact semantics of the binary. The one subtlety is `rol` on an 8-bit register with a `cl` count. x86 masks the count to 5 bits, which is equivalent to `count mod 8` for a byte rotate, and the emulator does the same.