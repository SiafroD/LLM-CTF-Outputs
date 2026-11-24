# Secret Treaties
## Description
**Category :** Crypto

**Description :** We built a "quantum-resistant" public-key scheme from the good old subset-sum problem. Subset-sum is NP-complete, so surely nobody can read our messages without the private key... right?

We encrypted the flag nine bytes at a time. Each 72-bit block became a single number: the sum of the public-key entries selected by that block's bits.

Recover the flag.

## LLM

**Model :** Claude Sonnet 5.5

## Execution

**Found flag :** csaw{LLL_turns_kn4ps4cks_1nt0_p4nc4k3s_wh3n_d3ns1ty_1s_l0w}

**Prompt :**  Crypto challenge. See attached README for challenge info. Both txt files are part of the challenge. Keep outputting a human-readable trace of your work.

**Execution trace :** 

This is a Merkle–Hellman knapsack, so the plan is a low-density subset-sum attack with a lattice (LLL). The density is about 72 / 96 bits ≈ 0.75, which is workable for CJLOSS. First I'll check what tooling is available.

Sympy's LLL hit an internal assertion, probably a bug on this input. I'll write my own exact-integer LLL (Cohen's Algorithm 2.6.7, which has no floating-point error) and use that instead.

The LLL sanity test gives the correct reduced basis for the textbook example. The `time` wrapper failed, so I'll rerun without it.

The flag is:

csaw{LLL_turns_kn4ps4cks_1nt0_p4nc4k3s_wh3n_d3ns1ty_1s_l0w}

### Process

**1. Reading the challenge.** The scheme is a Merkle–Hellman-style knapsack: each 72-bit block is encrypted as the sum of the public-key entries picked out by its bits. Decrypting means solving subset-sum, with no private key needed.

**2. Checking the density.** The public key has 72 entries of up to 96 bits, so the density is 72 / 96 = 0.75. That is below the ~0.94 threshold where the CJLOSS lattice attack works, so the "unbreakable" knapsack is actually low-density. The README's hint about a "much prettier" path points the same way.

**3. Building the lattice.** For each ciphertext S, I built a 73×73 basis with rows `(2·eᵢ, N·aᵢ)` for each key entry aᵢ, plus a last row `(1,…,1, N·S)`. If x is the secret bit vector, then (last row − Σ xᵢ·rowᵢ) equals `(1−2x₁, …, 1−2x₇₂, 0)`. That is a vector of ±1 entries with a zero final coordinate, so it is unusually short, and LLL should find it. The large weight N on the last column forces the sum to cancel to exactly 0.

**4. Tooling hiccups.** There was no fpylll or Sage, and the sandbox has no network. Sympy's built-in LLL crashed with an assertion error. I wrote an exact-integer LLL (Cohen's algorithm), tested it on a small lattice, and used that.

**5. First pass.** Blocks 1, 2, 4 and 5 fell out immediately, each in about 0.1 s, giving `turns_kn4`, `ps4cks_1n`, `3s_wh3n_d` and `3ns1ty_1s`. Blocks 0, 3 and 6 failed because LLL's output didn't contain the target vector.

**6. Fixing the failures.** I retried with shuffled column order, varied N, and a tighter reduction parameter (δ=0.999). All three succeeded within a few attempts:
- Block 0: `csaw{LLL_`
- Block 3: `t0_p4nc4k`
- Block 6: `_l0w}` followed by four null bytes of padding

**7. Verification.** I re-encrypted every recovered block with the public key and confirmed that each sum equals its ciphertext exactly (7/7 matches). Concatenating the blocks and stripping the null padding gives the flag above.

## More

**Additional explanation : (optional)**