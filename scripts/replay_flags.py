"""Replay saved task traces through the flag rules.

Usage: uv run python scripts/replay_flags.py [--details] [--save NAME] [--compare NAME]
"""

from sibyl_h0und.replay import main

if __name__ == "__main__":
    main()
