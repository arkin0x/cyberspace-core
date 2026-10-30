# Fixtures

## hop-residue-vectors.json

Copied unchanged from the spec repository, arkin0x/cyberspace at commit
`06c287332651f99b75e609b7b098e165993750fd` (`hop-residue-vectors.json`, written
from `hop-residue-reference.py` by `hop-residue-vectors.py`). Never edit it here;
to update it, copy the file again from a newer spec commit and change the commit
and the hash below and in `test/residue.test.ts`, which asserts the hash.

- size: 422,489 bytes
- sha256: `29b2222d3768b173b82887d9fb992cda23044ef84cfcfca48dd049766c7c4d33`

Its own `provenance.spec_commit` field reads `8b45430af330f6e93ee763716d33868706cc2879`.
That is the commit of `hop-residue-reference.py`, the reference the vectors were
written from, not the commit the file was copied from (`06c2873`, where the
file was added). The test asserts both.

The file is not normative (CYBERSPACE_V2.md section 14): where it disagrees with
the spec text, the text is right and the file is a bug.
