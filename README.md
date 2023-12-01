# HMAC-SHA-512
Implementing HMAC using SHA-512.

Code provides a simple HMAC implementation using `sha512` from `hashlib` library.

Use a randomly generated key based on default key size, and a default message to generate hex digest. Then uses the `hmac` library to generate hex digest given the same key, message and hashing algorithm, to compare how our implementation compares.
