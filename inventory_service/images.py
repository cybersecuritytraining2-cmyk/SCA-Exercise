"""Product image handling — generates thumbnails for uploaded photos."""

from PIL import Image


def make_thumbnail(uploaded_image, size=(128, 128)):
    """Open an uploaded product image and produce a thumbnail.

    SCA finding: Pillow 8.1.0 — dozens of advisories (buffer overflows and
    out-of-bounds reads in the BLP/ICNS/EPS/etc. decoders, e.g. CVE-2021-25287,
    CVE-2021-34552, CVE-2022-22817).

    Verdict: TRUE POSITIVE. `uploaded_image` is an untrusted file supplied by a
    user, and `Image.open(...)` runs Pillow's decoders over it — the exact
    reachable path these advisories cover. One outdated package, ~50 findings,
    one action: upgrade Pillow.
    """
    img = Image.open(uploaded_image)
    img.thumbnail(size)
    return img
