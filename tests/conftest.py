"""Keep tests away from the real user profile (the backend writes logs under ~/.secure_credentials)."""

import os
import tempfile

_fake_home: str = tempfile.mkdtemp(prefix="sc_test_home_")
os.environ["USERPROFILE"] = _fake_home
os.environ["HOME"] = _fake_home
