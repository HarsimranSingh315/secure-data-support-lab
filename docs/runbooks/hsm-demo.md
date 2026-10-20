# HSM demo (PKCS#11)

`make toolbox`, then `hsm-demo`. It uses SoftHSM, a software HSM that speaks PKCS#11, the same
standard interface Thales Luna HSMs expose to applications.

What it shows, step by step:
1. Initialise a token with a security-officer PIN and a user PIN.
2. Generate an RSA-2048 key pair **inside** the token. The private key is created
   `sensitive, never extractable`.
3. Sign a document inside the HSM.
4. Export only the public key and verify the signature with plain OpenSSL.
5. Change one character of the document: verification fails.
6. Attempt to export the private key: nothing comes out.

Interview angle: what an HSM is for (keys are used, never seen), PKCS#11 as the API, and how a
KMS can use an HSM to protect its own master key (auto-unseal).
