#!/usr/bin/env python3
"""Thin project wrapper delegating to ~/.gemini/config/scripts/audit_workspace_skills.py."""
import os, sys, subprocess
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
GLOBAL_AUDITOR = os.path.expanduser('~/.gemini/config/scripts/audit_workspace_skills.py')
if __name__ == '__main__':
    sys.exit(subprocess.call([sys.executable, GLOBAL_AUDITOR, '--project-dir', PROJECT_ROOT] + sys.argv[1:]))
