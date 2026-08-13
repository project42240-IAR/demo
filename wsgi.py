# Lightweight WSGI entrypoint for Vercel/WSGI servers
# Import the Flask `app` object from the project and expose it here.

from api.index import app

# Expose `app` at module level — WSGI loaders will import this file.
__all__ = ["app"]
