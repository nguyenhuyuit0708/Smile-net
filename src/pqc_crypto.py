#!/usr/bin/env python3
"""
PQC Crypto & OpenSSL 3 OQS-Provider integration module for Smile-Net.
Provides:
1. OpenSSL 3 OQS-Provider loader & SSL_CTX group configuration (X25519MLKEM768 / mlkem768)
2. Native liboqs ML-DSA-65 (Dilithium3) signing & verification wrapper
"""

import ctypes
import ssl
import time

libcrypto = ctypes.CDLL("/lib/x86_64-linux-gnu/libcrypto.so.3", mode=ctypes.RTLD_GLOBAL)
libssl = ctypes.CDLL("/lib/x86_64-linux-gnu/libssl.so.3", mode=ctypes.RTLD_GLOBAL)
liboqs = ctypes.CDLL("/usr/local/lib/liboqs.so.9", mode=ctypes.RTLD_GLOBAL)

# OpenSSL Provider API
libcrypto.OSSL_PROVIDER_load.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
libcrypto.OSSL_PROVIDER_load.restype = ctypes.c_void_p

# OpenSSL SSL_CTX_ctrl API
libssl.SSL_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_long, ctypes.c_char_p]
libssl.SSL_CTX_ctrl.restype = ctypes.c_long

SSL_CTRL_SET_GROUPS_LIST = 92

# liboqs OQS_SIG API
liboqs.OQS_SIG_new.argtypes = [ctypes.c_char_p]
liboqs.OQS_SIG_new.restype = ctypes.c_void_p

liboqs.OQS_SIG_keypair.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
liboqs.OQS_SIG_keypair.restype = ctypes.c_int

liboqs.OQS_SIG_sign.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_char_p,
]
liboqs.OQS_SIG_sign.restype = ctypes.c_int

liboqs.OQS_SIG_verify.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_char_p,
]
liboqs.OQS_SIG_verify.restype = ctypes.c_int

liboqs.OQS_SIG_free.argtypes = [ctypes.c_void_p]
liboqs.OQS_SIG_free.restype = None

# Load providers once at import
_prov_default = libcrypto.OSSL_PROVIDER_load(None, b"default")
_prov_oqs = libcrypto.OSSL_PROVIDER_load(None, b"oqsprovider")


def configure_ssl_context_groups(ctx: ssl.SSLContext, groups: str = "X25519MLKEM768:mlkem768") -> bool:
    """
    Configures an existing Python ssl.SSLContext to use the specified TLS 1.3 KEM groups
    (e.g., 'X25519MLKEM768:mlkem768' for PQC or 'X25519:P-256' for Classical).
    """
    ctx_ptr = ctypes.c_void_p.from_address(id(ctx) + 16).value
    res = libssl.SSL_CTX_ctrl(ctx_ptr, SSL_CTRL_SET_GROUPS_LIST, 0, groups.encode("ascii"))
    return res == 1


class MLDSA65Auth:
    """
    NIST FIPS 204 ML-DSA-65 (Dilithium3) Signer & Verifier using native liboqs.
    Public Key: 1952 bytes
    Secret Key: 4032 bytes
    Signature : 3309 bytes
    """
    PUBKEY_LEN = 1952
    SECKEY_LEN = 4032
    SIG_LEN = 3309

    def __init__(self):
        self._sig = liboqs.OQS_SIG_new(b"ML-DSA-65")
        if not self._sig:
            raise RuntimeError("Failed to initialize OQS_SIG ML-DSA-65")
        self.public_key = ctypes.create_string_buffer(self.PUBKEY_LEN)
        self.secret_key = ctypes.create_string_buffer(self.SECKEY_LEN)

    def generate_keypair(self):
        rc = liboqs.OQS_SIG_keypair(self._sig, self.public_key, self.secret_key)
        if rc != 0:
            raise RuntimeError("ML-DSA-65 keypair generation failed")
        return self.public_key.raw, self.secret_key.raw

    def sign(self, message: bytes) -> tuple[bytes, float]:
        sig_buf = ctypes.create_string_buffer(self.SIG_LEN)
        sig_len = ctypes.c_size_t(0)
        t0 = time.perf_counter()
        rc = liboqs.OQS_SIG_sign(
            self._sig, sig_buf, ctypes.byref(sig_len), message, len(message), self.secret_key
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        if rc != 0:
            raise RuntimeError("ML-DSA-65 sign failed")
        return sig_buf.raw[: sig_len.value], elapsed_ms

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> tuple[bool, float]:
        t0 = time.perf_counter()
        rc = liboqs.OQS_SIG_verify(
            self._sig, message, len(message), signature, len(signature), public_key
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return (rc == 0), elapsed_ms

    def __del__(self):
        if getattr(self, "_sig", None):
            liboqs.OQS_SIG_free(self._sig)
            self._sig = None


if __name__ == "__main__":
    # Self-test
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ok = configure_ssl_context_groups(ctx, "X25519MLKEM768:mlkem768")
    print(f"[Self-Test] OpenSSL OQS-Provider Group X25519MLKEM768 configured: {ok}")
    mldsa = MLDSA65Auth()
    pk, sk = mldsa.generate_keypair()
    msg = b"Smile-Net TLS 1.3 PQC Handshake Transcript Test"
    sig, sign_ms = mldsa.sign(msg)
    valid, ver_ms = mldsa.verify(msg, sig, pk)
    print(
        f"[Self-Test] ML-DSA-65 (Dilithium3): pubkey={len(pk)}B, sig={len(sig)}B, "
        f"sign={sign_ms:.3f}ms, verify={ver_ms:.3f}ms, valid={valid}"
    )

