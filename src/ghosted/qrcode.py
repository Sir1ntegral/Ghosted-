"""
Ghosted — sovereign QR code generator (pure-Python, zero deps).

Encodes a string (e.g. an otpauth:// authenticator URI, or a one-time sign-in code)
as a QR Code (Model 2, byte mode, ECC level M) and renders it as inline SVG that any
browser displays and any phone camera scans. No third-party library and nothing leaves
the machine — a TOTP secret must never be sent to a cloud QR service.

Supports versions 1–10 (enough for otpauth URIs). Implements the full pipeline:
byte-mode bitstream → Reed-Solomon ECC over GF(256) → block interleaving → matrix with
finder/alignment/timing patterns → mask selection by penalty → format-info. Always
paired with the human-readable secret/URI as the guaranteed fallback.
"""

from __future__ import annotations

# ── GF(256) for Reed-Solomon ────────────────────────────────────────────────────
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _rs_gen_poly(n: int) -> list[int]:
    poly = [1]
    for i in range(n):
        poly2 = [0] * (len(poly) + 1)
        for j in range(len(poly)):
            poly2[j] ^= _gf_mul(poly[j], 1)
            poly2[j + 1] ^= _gf_mul(poly[j], _EXP[i])
        poly = poly2
    return poly


def _rs_ec(data: list[int], n: int) -> list[int]:
    gen = _rs_gen_poly(n)
    res = list(data) + [0] * n
    for i in range(len(data)):
        coef = res[i]
        if coef != 0:
            for j in range(len(gen)):
                res[i + j] ^= _gf_mul(gen[j], coef)
    return res[len(data):]


# ── ECC level M tables, versions 1–10 ───────────────────────────────────────────
# version: (ec_per_block, [(num_blocks, data_per_block), ...])
_ECC_M = {
    1: (10, [(1, 16)]),
    2: (16, [(1, 28)]),
    3: (26, [(1, 44)]),
    4: (18, [(2, 32)]),
    5: (24, [(2, 43)]),
    6: (16, [(4, 27)]),
    7: (18, [(4, 31)]),
    8: (22, [(2, 38), (2, 39)]),
    9: (22, [(3, 36), (2, 37)]),
    10: (26, [(4, 43), (1, 44)]),
}
_ALIGN = {
    1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30],
    6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
}


def _data_capacity(ver: int) -> int:
    ecpb, groups = _ECC_M[ver]
    return sum(nb * dpb for nb, dpb in groups)


def _choose_version(n_bytes: int) -> int:
    for ver in range(1, 11):
        # byte-mode: 4-bit mode + length (8 bits v1-9, 16 bits v10) + 8*n + terminator
        count_bits = 16 if ver >= 10 else 8
        need_bits = 4 + count_bits + 8 * n_bytes
        if need_bits <= _data_capacity(ver) * 8:
            return ver
    raise ValueError("data too long for QR versions 1–10")


# ── bitstream ────────────────────────────────────────────────────────────────────
def _make_data_codewords(data: bytes, ver: int) -> list[int]:
    bits: list[int] = []

    def put(val: int, n: int) -> None:
        for i in range(n - 1, -1, -1):
            bits.append((val >> i) & 1)

    put(0b0100, 4)  # byte mode
    put(len(data), 16 if ver >= 10 else 8)
    for b in data:
        put(b, 8)
    cap_bits = _data_capacity(ver) * 8
    put(0, min(4, cap_bits - len(bits)))  # terminator
    while len(bits) % 8:
        bits.append(0)
    codewords = [int("".join(str(b) for b in bits[i:i + 8]), 2) for i in range(0, len(bits), 8)]
    pad = [0xEC, 0x11]
    i = 0
    while len(codewords) < _data_capacity(ver):
        codewords.append(pad[i % 2])
        i += 1
    return codewords


def _interleave(codewords: list[int], ver: int) -> list[int]:
    ecpb, groups = _ECC_M[ver]
    blocks = []
    pos = 0
    for nb, dpb in groups:
        for _ in range(nb):
            data = codewords[pos:pos + dpb]
            pos += dpb
            blocks.append((data, _rs_ec(data, ecpb)))
    result = []
    maxd = max(len(d) for d, _ in blocks)
    for i in range(maxd):
        for d, _ in blocks:
            if i < len(d):
                result.append(d[i])
    for i in range(ecpb):
        for _, e in blocks:
            result.append(e[i])
    return result


# ── matrix ───────────────────────────────────────────────────────────────────────
def _new_matrix(size: int):
    return [[None] * size for _ in range(size)]


def _place_finder(m, r, c):
    for dr in range(-1, 8):
        for dc in range(-1, 8):
            rr, cc = r + dr, c + dc
            if 0 <= rr < len(m) and 0 <= cc < len(m):
                if dr in (-1, 7) or dc in (-1, 7):
                    m[rr][cc] = 0
                elif dr in (0, 6) or dc in (0, 6):
                    m[rr][cc] = 1
                elif 2 <= dr <= 4 and 2 <= dc <= 4:
                    m[rr][cc] = 1
                else:
                    m[rr][cc] = 0


def _reserve_format(m):
    size = len(m)
    for i in range(9):
        if m[8][i] is None:
            m[8][i] = 2
        if m[i][8] is None:
            m[i][8] = 2
    for i in range(8):
        m[8][size - 1 - i] = 2
        m[size - 1 - i][8] = 2


def _build_matrix(ver: int, final_bits: list[int]):
    size = ver * 4 + 17
    m = _new_matrix(size)
    _place_finder(m, 0, 0)
    _place_finder(m, 0, size - 7)
    _place_finder(m, size - 7, 0)
    # timing
    for i in range(size):
        if m[6][i] is None:
            m[6][i] = 1 if i % 2 == 0 else 0
        if m[i][6] is None:
            m[i][6] = 1 if i % 2 == 0 else 0
    # alignment
    coords = _ALIGN[ver]
    for r in coords:
        for c in coords:
            if (r, c) in ((6, 6), (6, size - 7), (size - 7, 6)):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    m[r + dr][c + dc] = 1 if max(abs(dr), abs(dc)) != 1 else 0
    m[size - 8][8] = 1  # dark module
    _reserve_format(m)
    # data placement (zigzag)
    bitidx = 0
    col = size - 1
    upward = True
    while col > 0:
        if col == 6:
            col -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for r in rows:
            for c in (col, col - 1):
                if m[r][c] is None:
                    bit = final_bits[bitidx] if bitidx < len(final_bits) else 0
                    m[r][c] = bit
                    bitidx += 1
        upward = not upward
        col -= 2
    return m


_MASKS = [
    lambda r, c: (r + c) % 2 == 0,
    lambda r, c: r % 2 == 0,
    lambda r, c: c % 3 == 0,
    lambda r, c: (r + c) % 3 == 0,
    lambda r, c: (r // 2 + c // 3) % 2 == 0,
    lambda r, c: (r * c) % 2 + (r * c) % 3 == 0,
    lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
    lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0,
]


def _apply_mask(m, mask):
    size = len(m)
    out = [row[:] for row in m]
    fn = _MASKS[mask]
    for r in range(size):
        for c in range(size):
            if m[r][c] in (0, 1) and not _is_function(m, r, c) and fn(r, c):
                out[r][c] ^= 1
    return out


# track function-module map separately for masking correctness
_FUNC = {}


def _is_function(m, r, c):
    return _FUNC.get((id(m), r, c), False)


def _format_bits(mask: int) -> list[int]:
    # ECC level M = 0b00; standard BCH(15,5) + mask XOR 0x5412
    data = (0b00 << 3) | mask
    rem = data
    for _ in range(10):
        rem = (rem << 1)
        if rem & (1 << 10):
            rem ^= 0b10100110111
    bits = ((data << 10) | rem) ^ 0b101010000010010
    return [(bits >> i) & 1 for i in range(14, -1, -1)]


def _place_format(m, mask):
    size = len(m)
    bits = _format_bits(mask)
    # around top-left
    coords1 = [(8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5), (8, 7), (8, 8),
               (7, 8), (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8)]
    for i, (r, c) in enumerate(coords1):
        m[r][c] = bits[i]
    # split copy
    for i in range(7):
        m[size - 1 - i][8] = bits[i]
    for i in range(8):
        m[8][size - 8 + i] = bits[7 + i]


def _penalty(m) -> int:
    size = len(m)
    score = 0
    for r in range(size):
        for run in (m[r], [m[i][r] for i in range(size)]):
            cnt, prev = 1, run[0]
            for v in run[1:]:
                if v == prev:
                    cnt += 1
                else:
                    if cnt >= 5:
                        score += 3 + (cnt - 5)
                    cnt, prev = 1, v
            if cnt >= 5:
                score += 3 + (cnt - 5)
    for r in range(size - 1):
        for c in range(size - 1):
            if m[r][c] == m[r][c + 1] == m[r + 1][c] == m[r + 1][c + 1]:
                score += 3
    dark = sum(v for row in m for v in row if v in (0, 1))
    total = size * size
    pct = dark * 100 // total
    score += 10 * (abs(pct - 50) // 5)
    return score


def encode(text: str) -> list[list[int]]:
    """Return the QR module matrix (1 = dark, 0 = light) for *text*."""
    data = text.encode("utf-8")
    ver = _choose_version(len(data))
    codewords = _make_data_codewords(data, ver)
    final = _interleave(codewords, ver)
    final_bits = [(b >> i) & 1 for b in final for i in range(7, -1, -1)]
    base = _build_matrix(ver, final_bits)
    # mark function modules (anything placed before data) for masking
    _FUNC.clear()
    size = len(base)
    func_matrix = _build_function_map(ver)
    for r in range(size):
        for c in range(size):
            if func_matrix[r][c]:
                _FUNC[(id(base), r, c)] = True
    best, best_score = None, None
    for mask in range(8):
        cand = _apply_mask(base, mask)
        _place_format(cand, mask)
        sc = _penalty(cand)
        if best_score is None or sc < best_score:
            best, best_score = cand, sc  # mask is already baked into `cand` via _place_format
    _FUNC.clear()
    return best


def _build_function_map(ver: int):
    """A boolean matrix: True where a module is a function pattern (never masked)."""
    size = ver * 4 + 17
    f = [[False] * size for _ in range(size)]

    def fill(r0, c0, h, w):
        for r in range(r0, r0 + h):
            for c in range(c0, c0 + w):
                if 0 <= r < size and 0 <= c < size:
                    f[r][c] = True

    fill(0, 0, 8, 8)
    fill(0, size - 8, 8, 8)
    fill(size - 8, 0, 8, 8)
    for i in range(size):
        f[6][i] = True
        f[i][6] = True
    coords = _ALIGN[ver]
    for r in coords:
        for c in coords:
            if (r, c) in ((6, 6), (6, size - 7), (size - 7, 6)):
                continue
            fill(r - 2, c - 2, 5, 5)
    # format-info regions
    for i in range(9):
        f[8][i] = True
        f[i][8] = True
    for i in range(8):
        f[8][size - 1 - i] = True
        f[size - 1 - i][8] = True
    return f


def svg(text: str, *, scale: int = 6, quiet: int = 4) -> str:
    """Render *text* as a scannable QR in an inline SVG string."""
    m = encode(text)
    size = len(m)
    dim = (size + 2 * quiet) * scale
    rects = []
    for r in range(size):
        for c in range(size):
            if m[r][c] == 1:
                x = (c + quiet) * scale
                y = (r + quiet) * scale
                rects.append(f'<rect x="{x}" y="{y}" width="{scale}" height="{scale}"/>')
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{dim}" height="{dim}" '
        f'viewBox="0 0 {dim} {dim}" shape-rendering="crispEdges">'
        f'<rect width="{dim}" height="{dim}" fill="#fff"/>'
        f'<g fill="#000">{"".join(rects)}</g></svg>'
    )
