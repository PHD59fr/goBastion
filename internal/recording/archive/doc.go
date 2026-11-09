// Package archive implements a versioned encrypted and signed recording stream.
// It does not capture sessions, open files, load environment variables, or change
// the existing plaintext recording pipeline.
//
// Each archive has a new random AES-256 data key. RSA-OAEP with SHA-256 wraps it
// independently for 1-32 recipients with RSA keys of 3072-8192 bits. Ed25519
// signing keys are independent of both recipient keys and EGRESS_ENC_KEY. Callers
// supply trusted signing public keys out of band; embedded identities are never
// treated as trust roots. Public key IDs are SHA-256 fingerprints.
//
// V1 is: magic "GOBREC01", big-endian uint32 header length, canonical JSON
// header, data frames, then a final manifest frame. A data frame is byte 1,
// big-endian uint64 index, big-endian uint32 ciphertext length, and AES-GCM
// output including its random 12-byte nonce and 16-byte tag. The standard
// library generates the nonces. A data key is limited to 2^20 frames, well below
// NewGCMWithRandomNonce's 2^32 limit. Chunks are at most 1 MiB, and only the last
// chunk may be short. AAD binds the complete header hash, index, and length.
// The manifest frame is byte 2, big-endian uint32 manifest length, canonical
// JSON manifest, and a 64-byte Ed25519 signature. Trailing bytes are rejected.
//
// The signed manifest binds the provenance, public key IDs, complete header
// hash, SHA-256 of all ordered data frames, counts, capture outcome, and a
// finalization timestamp. Close uses "unspecified"; CloseWithOutcome lets a
// trusted finalizer attest "imported", "complete", or "interrupted-prefix".
// Capture outcome is independent of stream framing completeness.
// Canonical JSON is schema-specific: all fields in declared order, no omitted
// fields or whitespace, and the string/integer encoding produced by json.Marshal.
// Unknown fields, duplicate members, alternative encodings, or reordered members
// are rejected by decoding and byte-for-byte re-encoding. This is not RFC 8785.
//
// Verify authenticates a complete ciphertext stream without recipient private
// keys. Decrypt verifies the complete archive before releasing any plaintext,
// then authenticates and hashes every frame again during its second read. Its
// ReaderAt should represent an immutable file. Callers must write to a private,
// transactional destination and discard it on any error: source mutation or a
// late I/O failure can leave an authenticated plaintext prefix in that output.
// Neither Verify nor Decrypt accepts a truncated or unfinalized recording.
//
// Provenance and timestamps are assertions by the signing service, not trusted
// timestamps or proof that capture was complete or truthful. Compromise of a
// signing key permits forged recordings; compromise of a recipient private key
// exposes archives addressed to it. Recipient removal cannot revoke copies or
// previously unwrapped data keys. Keep historical signing public keys and the
// required recipient private keys under an independent retention/recovery policy.
// Private keys, runtime plaintext, and any existing plaintext spools remain the
// caller's responsibility. Memory clearing here is best effort, not a Go memory
// erasure guarantee.
//
// NewWriter retains its signing private key until finalization: never pass that
// key to an unprivileged SSH capture process. Live capture and crash recovery
// need a separately reviewed trusted recorder protocol. Header-bound signer IDs
// mean unfinished streams cannot simply be signed with a new key after rotation.
// Retain the matching signing private key while pending streams need finalizing,
// or use a separately designed recovery attestation. Caller-supplied gzip may be
// incomplete after a crash; this format does not make it replayable or recover it.
package archive
