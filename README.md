# .onion WEBCAT ZK enrollment PoC

Forked from [nova-eddsa](https://github.com/zk-bankai/nova-eddsa).

**Proof-of-concept** for privacy-preserving `.onion` enrollment in WEBCAT. It is agnostic of the underlying WEBCAT infrastructure, whether centralized or distributed.

## Problem
- Publishing a global list of enrolled `.onion` services leaks which domains are active.  
- Operators may not want a public registry of their hidden services.
- WEBCAT operators better not know what is being enrolled to prevent censorship and liability.

## Solution
Onion Service owners sign an enrollment statement and build a Nova ZK proof; only `hash(pubkey)`, the signed message and the SNARK proof are sent to the enrollment service. The signed message contains the trust material for WEBCAT: authorized signers, associated transparency log, etc. They do so using the Ed25519 private key associated with their `.onion` domain.

When a user visits the onion site, a WebCAT plugin:

1. Fetches the service’s public key  
2. Computes `hash(pubkey)`  
3. Looks up the associated trust material in the list 

_No central list of plaintext .onion domains → WEBCAT operators or auditors cannot enumerate enrolled services._

## Workflow

### 1. Enroll  
Run as prover, where `msg` is the WEBCAT stament (eg: a policy hash) and `sk` is the `.onion` private key:

    onion-cmd prove --msg <32-byte-hex> --sk <32-byte-hex>

Outputs:  
- Writes `proof.bin`
- Prints `hash(pubkey)`

### 2. Publish  
Send `msg`, `hash(pubkey)`, and the content of `proof.bin` to the WEBCAT enrollment service.

### 3. Verify  
Client or CLI:

    onion-cmd verify --msg <32-byte-hex> --pk-hash <64-byte-hex> --proof proof.bin



## Limitations & Spam
- **No liveness checks**: fake or dead-site enrollments can flood the registry  
- Out of scope: proof-of-work, or token-based staking as anti-spam measures.