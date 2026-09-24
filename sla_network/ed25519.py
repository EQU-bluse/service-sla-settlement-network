"""Ed25519 签名验证（RFC 8032），仅使用 Python 标准库。

服务只需验证既有公钥下的签名，不涉及私钥与签名生成，因此这里实现
RFC 8032 5.1.7 节的验证算法：解码公钥与签名、按共模方程校验 R。

标量乘法内部使用扩展扭曲爱德华坐标 (X:Y:Z:T)，整轮数乘只在最后做一次
求逆转回仿射，避免每步加法都付出模逆开销（纯 Python 大整数下尤为关键）。
"""

from __future__ import annotations

import hashlib

__all__ = ["InvalidSignature", "verify"]

# Ed25519 曲线与群参数（RFC 8032 5.1）。
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_D2 = (2 * _D) % _P
# 2^((p-1)/4)：p ≡ 1 (mod 4) 时平方根指数。
_I = pow(2, (_P - 1) // 4, _P)
_BASEPOINT = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202,
    46316835694926478169428394003475163141307993866256225615783033603165251855960,
)
# 扩展坐标下的单位元与基点。
_IDENTITY = (0, 1, 1, 0)


class InvalidSignature(Exception):
    """签名或公钥不满足 RFC 8032 验证方程。"""


def _x_recover(y: int) -> int:
    # x^2 = (y^2 - 1) / (d*y^2 + 1) mod p；p ≡ 5 (mod 8)。
    y2 = (y * y) % _P
    xx = ((y2 - 1) * pow(_D * y2 + 1, _P - 2, _P)) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


def _point_decompress(encoded: bytes) -> tuple[int, int]:
    if len(encoded) != 32:
        raise InvalidSignature("point must be 32 bytes")
    y = int.from_bytes(encoded, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        raise InvalidSignature("y coordinate out of field")
    x = _x_recover(y)
    if (x & 1) != sign:
        x = _P - x
    point = (x, y)
    # 非扭点即拒绝：显式做一次群成员校验。
    if not _point_on_curve(point):
        raise InvalidSignature("point not on curve")
    return point


def _point_on_curve(point: tuple[int, int]) -> bool:
    x, y = point
    # -x^2 + y^2 = 1 + d*x^2*y^2 mod p。
    left = (y * y - x * x) % _P
    right = (1 + _D * x * x * y * y) % _P
    return left == right


def _to_extended(point: tuple[int, int]) -> tuple[int, int, int, int]:
    x, y = point
    return (x, y, 1, (x * y) % _P)


def _to_affine(point: tuple[int, int, int, int]) -> tuple[int, int]:
    x, y, z, _ = point
    inverse = pow(z, _P - 2, _P)
    return (x * inverse) % _P, (y * inverse) % _P


def _extended_add(
    a: tuple[int, int, int, int], b: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    # Hisil–Wong–Carter–Dawson 扩展坐标加法（a = -1）。
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    aa = ((y1 - x1) * (y2 - x2)) % _P
    bb = ((y1 + x1) * (y2 + x2)) % _P
    cc = (_D2 * t1 * t2) % _P
    dd = (2 * z1 * z2) % _P
    ee = (bb - aa) % _P
    ff = (dd - cc) % _P
    gg = (dd + cc) % _P
    hh = (bb + aa) % _P
    return (
        (ee * ff) % _P,
        (gg * hh) % _P,
        (ff * gg) % _P,
        (ee * hh) % _P,
    )


def _extended_double(
    point: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    x, y, z, _ = point
    aa = (x * x) % _P
    bb = (y * y) % _P
    cc = (2 * z * z) % _P
    dd = (-aa) % _P  # a = -1
    ee = ((x + y) * (x + y) - aa - bb) % _P
    gg = (dd + bb) % _P
    ff = (gg - cc) % _P
    hh = (dd - bb) % _P
    return (
        (ee * ff) % _P,
        (gg * hh) % _P,
        (ff * gg) % _P,
        (ee * hh) % _P,
    )


def _scalar_multiply(
    scalar: int, point: tuple[int, int]
) -> tuple[int, int]:
    result = _IDENTITY
    addend = _to_extended(point)
    while scalar:
        if scalar & 1:
            result = _extended_add(result, addend)
        addend = _extended_double(addend)
        scalar >>= 1
    return _to_affine(result)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """验证一条 Ed25519 签名。合法返回 True，任何编码/方程失败返回 False。"""
    try:
        if len(signature) != 64:
            return False
        r_bytes = signature[:32]
        s_bytes = signature[32:]
        s = int.from_bytes(s_bytes, "little")
        if s >= _L:
            return False
        r_point = _point_decompress(r_bytes)
        public_point = _point_decompress(public_key)
        # 拒绝单位元公钥（其签名验证没有意义）。
        if public_point == (0, 1):
            return False
        # 先乘余因子把两点压进素数阶子群，再按共模方程
        # （RFC 8032 式 1.1）校验 [8]R + [8k]A == [8s]B。
        r8 = _scalar_multiply(8, r_point)
        a8 = _scalar_multiply(8, public_point)
        digest = hashlib.sha512(r_bytes + public_key + message).digest()
        k = int.from_bytes(digest, "little")
        expected = _affine_add(r8, _scalar_multiply(k % _L, a8))
        computed = _scalar_multiply((8 * s) % _L, _BASEPOINT)
        return expected == computed
    except InvalidSignature:
        return False


def _affine_add(
    a: tuple[int, int], b: tuple[int, int]
) -> tuple[int, int]:
    # 仅用于共模方程末端相加两个仿射点。
    return _to_affine(_extended_add(_to_extended(a), _to_extended(b)))
