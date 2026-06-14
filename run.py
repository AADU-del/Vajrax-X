#!/usr/bin/env python3
"""
Local development runner for VAJRA-X.
Usage:
    python run.py
"""
import os
import sys
import warnings

# Suppress the MINGW numpy RuntimeWarnings — cosmetic noise only, not errors
warnings.filterwarnings('ignore', category=RuntimeWarning, module='numpy')

# Always run from the project root
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(PROJECT_DIR)
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

try:
    from app import create_app, socketio
except Exception as _import_err:
    print("\n" + "!"*52)
    print("  VAJRA-X failed to import — details below:")
    print("!"*52)
    import traceback
    traceback.print_exc()
    print("\nFix the error above, then re-run `python run.py`.")
    sys.exit(1)

if __name__ == '__main__':
    try:
        app = create_app()
    except Exception as _init_err:
        print("\n" + "!"*52)
        print("  VAJRA-X failed during create_app():")
        print("!"*52)
        import traceback
        traceback.print_exc()
        sys.exit(1)

    print("\n" + "="*52)
    print("  [+] VAJRA-X Multi-Domain Situational Awareness Platform")
    print("="*52)
    print("  URL    : http://127.0.0.1:5000")
    print("  Login  : admin / ChangeMe@2024!")
    print("  Mode   : Development (debug=True)")
    print("="*52 + "\n")
    socketio.run(
        app,
        host='127.0.0.1',
        port=5000,
        debug=True,
        use_reloader=False,   # Prevent double YOLO model load
        log_output=True,
        allow_unsafe_werkzeug=True
    )

