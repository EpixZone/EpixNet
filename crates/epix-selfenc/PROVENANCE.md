# Provenance — clean-room statement

This crate is a from-scratch implementation of the *published
self-encryption algorithm idea* (split a file into chunks; derive each
chunk's encryption key from content hashes so encryption is convergent;
address ciphertext by its own hash), extended with EpixNet-specific
changes: an owner salt folded into chunk derivation, a second
random-envelope mode, an AEAD (XChaCha20-Poly1305), BLAKE3 hashing
throughout, and a symmetric-outer data-map.

**No source code of the GPLv3 `self_encryption` crate (or any other GPL
implementation) was read, consulted, or referenced while designing or
writing this crate.** The design was produced from public algorithm
descriptions and this repository's own EDX design only.

Rules for contributors, effective from the first line of code in this
crate:

1. Do not read the `self_encryption` crate's source (or vendored copies,
   forks, or decompiled artifacts) while working on this crate.
2. If you have previously studied that source in depth, do not author
   code here; review-only participation is fine.
3. Interoperability with that crate's output format is a NON-goal. The
   formats are deliberately different (different KDF, different AEAD,
   different chunking constants, added salt), so there is no reason to
   consult it.
4. Changes to this crate should cite the EDX design document section they
   implement in the commit message.

This statement exists so the MIT licensing of this repository is
defensible without depending on anyone's memory. If the rules above were
ever violated, say so in a commit touching this file — silently breaking
the clean room is the only unforgivable option.
