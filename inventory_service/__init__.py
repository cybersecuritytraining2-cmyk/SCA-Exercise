"""InventoryService — a small product-inventory API.

The pinned dependencies in requirements.txt are old and carry many advisories.
An SCA scan lights up with well over a hundred findings. Almost all of them are
noise *for this application* — the vulnerable code is never reached, the package
is dev-only, or the bug doesn't apply to how we use it. A couple are real and
must be fixed. Telling them apart is the exercise; see README.md.
"""

__version__ = "2.1.0"
