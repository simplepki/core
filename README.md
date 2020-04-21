Core Components
================

The `core` library includes both standard key-pairs and standard types to use for certain events.

The key-pair library/interfaces currently supports the following actions:

   - creation of a new key
   - create of CSR's
   - the ability to sign CSR's
   - the ability to import key, certificates, and chain (not available with yubikey)
   - the ability to export key, certificates, and chain (not available with yubikey)
   - the ability to provide a Golang tls.Certificate for use in an http client or server

Yubikey support only supports actions that are possible and/or safe for use with a hardware token.