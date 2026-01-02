#!/usr/bin/env python3
"""
Wrapper script that applies the safe gas patch before running operate CLI.
"""
import sys

# Apply the patch FIRST, before any operate modules are imported
try:
    import operate_safe_gas_patch

    # This will import operate.services.protocol and patch it
    operate_safe_gas_patch.patch_safe_gas_estimation()
except Exception as e:
    print(f"Warning: Could not apply safe gas patch: {e}", file=sys.stderr)

# Now import and run operate CLI (the patch is already applied)
from operate.cli import main

if __name__ == "__main__":
    sys.exit(main())


