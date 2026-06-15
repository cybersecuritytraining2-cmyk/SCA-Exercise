"""Product image handling — generates thumbnails for uploaded photos."""

from PIL import Image


def make_thumbnail(uploaded_image, size=(128, 128)):
    """Open an uploaded product image and produce a thumbnail."""
    img = Image.open(uploaded_image)
    img.thumbnail(size)
    return img
