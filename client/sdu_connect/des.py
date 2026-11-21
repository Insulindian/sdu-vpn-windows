"""Faithful port of the ``strEnc()`` routine SDU CAS uses client-side.

The login page ships ``/cas/comm/sdu/js/des.js`` (Guapo, 2006).  It is *not*
standard DES: the permutations are interleaved in a non-standard way, so a
normal DES/3DES library produces the wrong ciphertext.  We therefore port the
bit-array implementation literally and fuzz it against the original JS.

Encryption is: split the input into 4-character blocks, map each block to 64
bits (four UTF-16 code units, big endian, zero padded), then apply ``enc()``
with key1, key2 and key3 in sequence.  Output is uppercase hex.
"""

from __future__ import annotations

__all__ = ["str_enc"]

_S1 = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
]
_S2 = [
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
    [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
    [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
    [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
]
_S3 = [
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
    [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
    [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
    [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
]
_S4 = [
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
    [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
    [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
    [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
]
_S5 = [
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
    [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
    [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
    [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
]
_S6 = [
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
    [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
    [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
    [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
]
_S7 = [
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
    [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
    [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
    [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
]
_S8 = [
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
    [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
    [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
    [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]
_SBOXES = [_S1, _S2, _S3, _S4, _S5, _S6, _S7, _S8]

_P_IDX = [
    15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9,
    1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24,
]

_FP_IDX = [
    39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24,
]

_TEMP_KEY_IDX = [
    13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3,
    25, 7, 15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39,
    50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31,
]

_LOOP = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

_HEX = "0123456789ABCDEF"


def _str_to_bt(text: str) -> list[int]:
    """Up to 4 UTF-16 code units -> 64 bits, zero padded (see strToBt)."""
    bits: list[int] = [0] * 64
    for i, ch in enumerate(text[:4]):
        code = ord(ch)
        for j in range(16):
            bits[16 * i + j] = (code >> (15 - j)) & 1
    return bits


def _get_key_bytes(key: str) -> list[list[int]]:
    return [_str_to_bt(key[i : i + 4]) for i in range(0, len(key), 4)]


def _bt64_to_hex(bits: list[int]) -> str:
    out = []
    for i in range(16):
        value = 0
        for j in range(4):
            value = (value << 1) | bits[i * 4 + j]
        out.append(_HEX[value])
    return "".join(out)


def _init_permute(data: list[int]) -> list[int]:
    out = [0] * 64
    for i in range(4):
        m = 1 + 2 * i
        n = 2 * i
        for j in range(7, -1, -1):
            k = 7 - j
            out[i * 8 + k] = data[j * 8 + m]
            out[i * 8 + k + 32] = data[j * 8 + n]
    return out


def _expand_permute(right: list[int]) -> list[int]:
    out = [0] * 48
    for i in range(8):
        out[i * 6 + 0] = right[31] if i == 0 else right[i * 4 - 1]
        out[i * 6 + 1] = right[i * 4 + 0]
        out[i * 6 + 2] = right[i * 4 + 1]
        out[i * 6 + 3] = right[i * 4 + 2]
        out[i * 6 + 4] = right[i * 4 + 3]
        out[i * 6 + 5] = right[0] if i == 7 else right[i * 4 + 4]
    return out


def _xor(a: list[int], b: list[int]) -> list[int]:
    return [x ^ y for x, y in zip(a, b)]


def _s_box_permute(expanded: list[int]) -> list[int]:
    out = [0] * 32
    for m in range(8):
        row = expanded[m * 6 + 0] * 2 + expanded[m * 6 + 5]
        col = (
            expanded[m * 6 + 1] * 8
            + expanded[m * 6 + 2] * 4
            + expanded[m * 6 + 3] * 2
            + expanded[m * 6 + 4]
        )
        value = _SBOXES[m][row][col]
        for b in range(4):
            out[m * 4 + b] = (value >> (3 - b)) & 1
    return out


def _p_permute(bits: list[int]) -> list[int]:
    return [bits[i] for i in _P_IDX]


def _finally_permute(bits: list[int]) -> list[int]:
    return [bits[i] for i in _FP_IDX]


def _generate_keys(key: list[int]) -> list[list[int]]:
    shuffled = [0] * 56
    for i in range(7):
        for j in range(8):
            k = 7 - j
            shuffled[i * 8 + j] = key[8 * k + i]

    keys: list[list[int]] = []
    for i in range(16):
        for _ in range(_LOOP[i]):
            temp_left = shuffled[0]
            temp_right = shuffled[28]
            for k in range(27):
                shuffled[k] = shuffled[k + 1]
                shuffled[28 + k] = shuffled[29 + k]
            shuffled[27] = temp_left
            shuffled[55] = temp_right
        keys.append([shuffled[i] for i in _TEMP_KEY_IDX])
    return keys


def _enc(data: list[int], key: list[int]) -> list[int]:
    keys = _generate_keys(key)
    ip = _init_permute(data)
    left, right = ip[:32], ip[32:]

    for i in range(16):
        temp_left = left
        left = right
        right = _xor(
            _p_permute(_s_box_permute(_xor(_expand_permute(right), keys[i]))),
            temp_left,
        )

    return _finally_permute(right + left)


def str_enc(data: str, first_key: str = "1", second_key: str = "2", third_key: str = "3") -> str:
    """Reproduce ``strEnc(data, firstKey, secondKey, thirdKey)`` from des.js."""
    if not data:
        return ""

    key_sets = [k for k in (_get_key_bytes(first_key), _get_key_bytes(second_key), _get_key_bytes(third_key)) if k]

    out: list[str] = []
    for start in range(0, len(data), 4):
        block = _str_to_bt(data[start : start + 4])
        for key_set in key_sets:
            for key in key_set:
                block = _enc(block, key)
        out.append(_bt64_to_hex(block))
    return "".join(out)
