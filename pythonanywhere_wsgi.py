# ============================================================
# PYTHONANYWHERE WSGI CONFIGURATION
# ------------------------------------------------------------
# In your PythonAnywhere dashboard:
#   Web tab → WSGI configuration file → paste this entire file
#
# IMPORTANT: Replace YOUR_USERNAME with your PythonAnywhere username
# ============================================================

import sys
import os
import logging

logging.basicConfig(stream=sys.stderr, level=logging.INFO)

# ── CHANGE THIS TO YOUR USERNAME ──
USERNAME = 'YOUR_USERNAME'
PROJECT_DIR = f'/home/{USERNAME}/vajrax'

if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

os.chdir(PROJECT_DIR)

# Activate your virtualenv
VENV_PATH = f'/home/{USERNAME}/.virtualenvs/vajra_venv/bin/activate_this.py'
if os.path.exists(VENV_PATH):
    with open(VENV_PATH) as f:
        exec(f.read(), {'__file__': VENV_PATH})
else:
    logging.warning(f"Virtualenv not found at {VENV_PATH} — using system Python")

from app import create_app

application = create_app()
