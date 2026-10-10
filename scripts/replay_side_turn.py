"""Run one side turn of the finish gate alone over saved traces.

Usage: uv run python scripts/replay_side_turn.py [--role challenger|judge|reporter]
       [--split dev|holdout|all] [--run TEXT] [--wrong-only] [--limit N] [--out PATH]
"""

from sibyl_h0und.side_replay import main

if __name__ == "__main__":
    main()
