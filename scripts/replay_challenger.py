"""Run the benign challenger alone over saved traces, cut at each task's first benign report.

Usage: uv run python scripts/replay_challenger.py [--split dev|holdout|all] [--run TEXT]
       [--wrong-only] [--limit N] [--out PATH]
"""

from sibyl_h0und.challenge_replay import main

if __name__ == "__main__":
    main()
