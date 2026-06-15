"""InventoryService — Flask entrypoint and HTTP routes."""

from flask import Flask, request, render_template, abort

from config import Config
from inventory_service import importer, images, pricing

app = Flask(__name__)
app.config.from_object(Config)

# Tiny in-memory catalogue so the app is self-contained.
PRODUCTS = {
    1: {"name": "Aluminium Widget", "description": "A sturdy, anodised widget."},
    2: {"name": "Brass Flange", "description": "Imperial-thread flange, 2 inch."},
}


@app.post("/inventory/import")
def import_inventory():
    uploaded = request.files["file"].read()
    items = importer.import_inventory(uploaded)
    return {"imported": len(items or [])}


@app.post("/products/<int:pid>/image")
def upload_image(pid):
    thumb = images.make_thumbnail(request.files["image"].stream)
    return {"ok": True, "thumbnail": list(thumb.size)}


@app.get("/products/<int:pid>")
def product(pid):
    item = PRODUCTS.get(pid)
    if item is None:
        abort(404)
    return render_template("product.html", product=item)


@app.get("/rates")
def rates():
    return pricing.fetch_rates()


if __name__ == "__main__":
    app.run(debug=app.config["DEBUG"])
