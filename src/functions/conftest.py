"""Put the function app root on sys.path so tests can import the blueprints.

The Functions host adds the app root automatically at runtime; pytest does not.
"""
import os
import sys

APP_ROOT = os.path.dirname(os.path.abspath(__file__))

if APP_ROOT not in sys.path:
    sys.path.insert(0, APP_ROOT)
