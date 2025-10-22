#!/usr/bin/env python3
"""
Simple ASGI entry point
"""
from master import app

# That's it - just export the app
application = app
print("✅ ASGI application ready - will bind to port")
