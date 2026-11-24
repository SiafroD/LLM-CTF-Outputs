# Finders keepers
## Description
**Category :** Crypto

**Description :** Find the hidden message in the attached video. Submit the decoded plaintext without a flag wrapper.

## LLM

**Model :** Claude Sonnet 5.5

## Execution

**Found flag :** csaw{y0u_@lw@ys_kn0w_wh3r3_t0_l00k} ; cantfindit

**Prompt :** 

This is a crypto CTF challenge. There should be a hidden flag in this video. Find it, return it in plaintext without a flag wrapper and document your process in a human-readable fashion.

**Execution trace :** 

I'll start by reading the file-handling guidance, then inspect the video.

Ten seconds, 300 frames, no audio track. Next I'll check the container for trailing data or odd atoms, then pull out frames.

A `uuid` atom (3,483 bytes) sits between `moov` and `mdat`. That's unusual, so I'll look at it and the frames.

The XMP metadata has a `dc:subject` value that looks like base64. I'll decode it.

Faint tiny text starting with "Y2…" shows up in a few frames around seconds 6–9 (it looks like base64). I'll go through full-resolution frames and enhance the contrast to read it.

The rectangles make pixel-level detection too noisy. I'll just look at full-resolution frames directly, at 6–9 seconds, where the text appeared.

That's tiny, slightly rotated text starting "Y2FudGZpb…", which is base64 for "cantfi…". It seems to appear in pieces across frames, so I'll locate it in every frame and reassemble it.

The frame is full of faint small text, probably many fragments or decoys. I'll crop and enlarge a few areas of one frame to see what they are.

Those blobs were just rectangle edges. The real text is in the frame near (860–1060, 85–170), so I'll enlarge that region.

The text has a gradient mask, so only parts of it are bright in any one frame, and it moves around. I'll track it with a better mask that separates thin strokes from the solid rectangles.

The text sits around x≈840–1100, y≈85–200 across frames ~190–280, rotating slowly. I'll make a montage of that region over time.

The full string ends with `==`, so it reads `Y2FudGZpbmRpdA==`. I'll decode it, then try it as a Vigenère key on the first string.

The flag is:

csaw{y0u_@lw@ys_kn0w_wh3r3_t0_l00k}

### How I found it

**1. Triage of the file.** `finderskeepers.mp4` is a 10-second, 1920×1080, 30 fps H.264 video with no audio track. Its metadata had nothing unusual, and `strings` only showed the x264 encoder settings.

**2. Container structure.** I walked the MP4 atoms and found `ftyp`, `free`, `moov`, **`uuid`** (3,483 bytes), then `mdat`. A `uuid` box between `moov` and `mdat` isn't normal for a plain encode, so I dumped it.

**3. Hidden XMP metadata.** The `uuid` box held an XMP packet written by ExifTool, with Canva attribution junk as decoy. One field, `dc:subject`, held a lone base64 string:
`ZXNucHtkMGNfQHl6QGdsX21uMGpfcG0zejNfZzBfbzAwc30=`

**4. First decode.** Base64-decoding it gives `esnp{d0c_@yz@gl_mn0j_pm3z3_g0_o00s}`. It has flag-style braces and leetspeak but a scrambled prefix. A Caesar shift didn't fit, because the letter shifts between `esnp` and a plausible prefix aren't constant. That pointed to a polyalphabetic cipher, which needs a key.

**5. Finding the key in the video.** The video is drifting pastel rectangles on a dark background. In roughly seconds 6.3 to 9.3 (frames ~190–285) a faint, rotated line of text appears, revealed gradually behind a fading mask. I located it, cropped and enlarged it, and read it across several frames as `Y2FudGZpbmRpdA==`. That is base64 for **`cantfindit`**.

**6. Decryption.** I applied the key as a Vigenère cipher to the first decoded string, shifting letters back and leaving digits and symbols alone. The result is `csaw{...}`, which is a valid flag prefix, so the key was right.

**Chain:** MP4 `uuid`/XMP metadata → base64 → Vigenère ciphertext, with the key (`cantfindit`) hidden as base64 text in the video frames.

## More

**Additional explanation : (optional)** The original challenge asked only for the "cantfindit" flag, although there seems to be a second flag hidden inside the video metadata. Whether this was intended or not is unknown, but the intended flag was found (**Step #5**).