"""Pure-Python RFC 8032 Ed25519, using only the Python standard library.

Only verification is needed by the server; :func:`sign` exists so tests stay
dependency-free as well.  Points use projective coordinates (X, Y, Z) with
x = X/Z, y = Y/Z, so a full scalar multiplication needs a single inversion.
"""

from __future__ import annotations

import hashlib

Q = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, Q - 2, Q)) % Q
I = pow(2, (Q - 1) // 4, Q)


class InvalidSignature(Exception):
    """Raised when a signature or public key is malformed or does not verify."""


def _invert(value: int) -> int:
    return pow(value, Q - 2, Q)


def _x_recover(y: int) -> int:
    xx = (y * y - 1) * _invert(D * y * y + 1) % Q
    x = pow(xx, (Q + 3) // 8, Q)
    if (x * x - xx) % Q != 0:
        x = x * I % Q
    if (x * x - xx) % Q != 0:
        raise InvalidSignature("point is not on the curve")
    if x & 1:
        x = Q - x
    return x


_BY = 4 * _invert(5) % Q
_B = (_x_recover(_BY), _BY, 1)


def _add(p: tuple[int, int, int], q: tuple[int, int, int]) -> tuple[int, int, int]:
    # Projective addition for -x^2 + y^2 = 1 + d x^2 y^2 (a = -1).
    x1, y1, z1 = p
    x2, y2, z2 = q
    a = z1 * z2 % Q
    b = a * a % Q
    c = x1 * x2 % Q
    d = y1 * y2 % Q
    e = D * c % Q * d % Q
    f = (b - e) % Q
    g = (b + e) % Q
    x3 = a * f % Q * ((x1 + y1) * (x2 + y2) - c - d) % Q
    y3 = a * g % Q * (d + c) % Q
    z3 = f * g % Q
    return x3, y3, z3


def _multiply(point: tuple[int, int, int], scalar: int) -> tuple[int, int, int]:
    result = (0, 1, 1)
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _encode(point: tuple[int, int, int]) -> bytes:
    x, y, z = point
    zi = _invert(z)
    x = x * zi % Q
    y = y * zi % Q
    encoded = y | ((x & 1) << 255)
    return encoded.to_bytes(32, "little")


def _decode(encoded: bytes) -> tuple[int, int, int]:
    if len(encoded) != 32:
        raise InvalidSignature("malformed point")
    point_int = int.from_bytes(encoded, "little")
    sign = point_int >> 255
    y = point_int & ((1 << 255) - 1)
    if y >= Q:
        raise InvalidSignature("non-canonical point encoding")
    x = _x_recover(y)
    if (x & 1) != sign:
        x = Q - x
    return x, y, 1


def _equal(
    p: tuple[int, int, int], q: tuple[int, int, int]
) -> bool:
    x1, y1, z1 = p
    x2, y2, z2 = q
    return x1 * z2 % Q == x2 * z1 % Q and y1 * z2 % Q == y2 * z1 % Q


def _clamp(digest: bytes) -> int:
    scalar = bytearray(digest[:32])
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    return int.from_bytes(scalar, "little")


def public_key(secret: bytes) -> bytes:
    """Return the 32-byte Ed25519 public key for a 32-byte secret seed."""
    if len(secret) != 32:
        raise ValueError("secret seed must be 32 bytes")
    scalar = _clamp(hashlib.sha512(secret).digest())
    return _encode(_multiply(_B, scalar))


def sign(message: bytes, secret: bytes) -> bytes:
    """Return the 64-byte Ed25519 signature over message for secret seed."""
    if len(secret) != 32:
        raise ValueError("secret seed must be 32 bytes")
    digest = hashlib.sha512(secret).digest()
    scalar = _clamp(digest)
    encoded_public = _encode(_multiply(_B, scalar))
    r = int.from_bytes(
        hashlib.sha512(digest[32:] + message).digest(), "little"
    ) % L
    encoded_r = _encode(_multiply(_B, r))
    k = int.from_bytes(
        hashlib.sha512(encoded_r + encoded_public + message).digest(), "little"
    ) % L
    s = (r + k * scalar) % L
    return encoded_r + s.to_bytes(32, "little")


def verify(signature: bytes, message: bytes, encoded_public: bytes) -> None:
    """Verify an Ed25519 signature; raise InvalidSignature on any failure."""
    if len(signature) != 64 or len(encoded_public) != 32:
        raise InvalidSignature("malformed signature or public key")
    r_point = _decode(signature[:32])
    public_point = _decode(encoded_public)
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        raise InvalidSignature("scalar out of range")
    k = int.from_bytes(
        hashlib.sha512(signature[:32] + encoded_public + message).digest(),
        "little",
    ) % L
    if not _equal(_multiply(_B, s), _add(r_point, _multiply(public_point, k))):
        raise InvalidSignature("signature does not verify")
