"""InventoryService — Flask entrypoint and HTTP routes.

This is where the dependencies are actually exercised, so it is where the
reachability story for each SCA finding becomes concrete.

Run (optional):  flask --app app run
Scan (the point): see README.md
"""

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
    # PyYAML — the uploaded file is untrusted and parsed with the full loader.
    uploaded = request.files["file"].read()
    items = importer.import_inventory(uploaded)
    return {"imported": len(items or [])}


@app.post("/products/<int:pid>/image")
def upload_image(pid):
    # Pillow — an untrusted uploaded image is decoded to build a thumbnail.
    thumb = images.make_thumbnail(request.files["image"].stream)
    return {"ok": True, "thumbnail": list(thumb.size)}


@app.get("/products/<int:pid>")
def product(pid):
    # Jinja — plain, auto-escaped rendering; no urlize/xmlattr/sandbox.
    item = PRODUCTS.get(pid)
    if item is None:
        abort(404)
    return render_template("product.html", product=item)


@app.get("/rates")
def rates():
    # requests/urllib3 — a fixed internal endpoint, no user-controlled URL.
    return pricing.fetch_rates()


if __name__ == "__main__":
    # DEBUG comes from Config and is False everywhere — the Werkzeug interactive
    # debugger is never enabled in a deployed environment.
    app.run(debug=app.config["DEBUG"])
