"""
WSGI entry point.
For local dev: python run.py
For PythonAnywhere: use pythonanywhere_wsgi.py content in WSGI config file.
"""
import sys
import os

# Ensure project root is on the path
project_home = os.path.dirname(os.path.abspath(__file__))
if project_home not in sys.path:
    sys.path.insert(0, project_home)

os.chdir(project_home)

from app import create_app

application = create_app()
app = application  # Some servers look for 'app'
