# Test dependency lock provenance

`requirements.lock` is a copy of the hash-locked runtime dependency set from
the VibeFactory Release 1 candidate at commit
`6d78c0b736fe0b191934dbbb26384571b3984a0e`. It provides
`jsonschema==4.26.0` and its pinned dependencies for the offline SARIF schema
test; the scanner runtime itself still uses the Python standard library.

SHA-256 of this lock file:
`7a88049612c64b221ed4dfaa83f24aac8f3f1a2fca7725d1779c540d21d6a4fb`.
