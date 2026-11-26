# The Signal (Hemispheres)

## Description

**Category :** Forensics (steganography / polyglot file), Medium–Hard

**Description :** We received an image, `the_signal.png`. It looks like an ordinary PNG, but the analyst suspects there is more inside. The second layer is locked, and the key was never written down. The hint says that different programs read a file from different ends, and that the words point at the pixels.

## LLM

**Model :** Claude Sonnet 5.5 (Anthropic)

## Execution

**Found flag :** `csaw{0n3_f1l3_tw0_truth5_p0lygl0t_m4g1c}`

**Prompt :**
```
You are solving CTF challenges of various themes and difficulty.
For every challenge, follow the template.md file.

[attached: the_signal.png, README.md]
New forensics challenge.
```

**Execution trace :**

1. **File identification.** `file` reports a 720×400, 8-bit RGB PNG of 8612 bytes. That is large for a simple sine-wave image, which suggests appended data.
2. **PNG chunk walk.** I parsed the chunks with a small Python script:
   - `IHDR`, then two `tEXt` chunks, then one `IDAT` (8100 bytes), then `IEND`.
   - `IEND` ends at offset 8286, but the file is 8612 bytes long, so **326 bytes follow IEND**.
   - The `Comment` tEXt chunk says: *"Look past IEND for the lock. The key is in the pixels, not the words."*
3. **Trailing data.** The bytes after `IEND` start with `PK`. They are a ZIP containing `flag.txt` and `README.txt`. Both entries have general-purpose flag bit 0 set, which means they are encrypted. Viewers stop at `IEND` while ZIP tools read from the end of the file, so the file is a PNG/ZIP polyglot.
4. **Finding the key in the pixels.** I extracted the bit-planes 0 and 1 of the R, G and B channels, plus the interleaved RGB stream, in both bit orders.
   - R and G planes were constant, and the interleaved stream was just the image pattern.
   - **Blue channel, bit 0, MSB-first** decoded to `\x00 \x17 r3ad_b3tw33n_th3_p1x3ls \x00…`.
   - The `\x17` byte is 23, the length of the string that follows, so the payload is length-prefixed. The password is `r3ad_b3tw33n_th3_p1x3ls`.
5. **Decryption.** I opened the trailing ZIP with that password:
   - `flag.txt` → `csaw{0n3_f1l3_tw0_truth5_p0lygl0t_m4g1c}`
   - `README.txt` → "You found the second truth AND the key. Nicely done."

## More

**Additional explanation : (optional)**

The challenge has three layers, and each one matches a part of the README and the image text ("one file. two truths. one locked." / "the picture holds a key; the tail holds a lock."):

- **Layer 1, the visible PNG.** This is the sine-wave image and the metadata hints.
- **Layer 2, the lock.** An encrypted ZIP is appended after `IEND`. PNG decoders ignore data after `IEND`, while `unzip` finds the central directory from the end of the file. That is why the README says programs read a file from different ends. `binwalk` or `unzip` on the original file would have surfaced it too.
- **Layer 3, the key.** A length-prefixed ASCII password is hidden in the blue-channel least-significant bits. The README's "the words point at the pixels" refers to the PNG comment, which tells you to look in the pixels.

The password also fits the theme: `r3ad_b3tw33n_th3_p1x3ls` is leetspeak for "read between the pixels".