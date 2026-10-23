#!/usr/bin/env python3
"""Write a subagent's final message (from its JSONL transcript) to agents/<id>/final.txt and print the path."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import RUN, final_message  # noqa: E402

aid, transcript = sys.argv[1], sys.argv[2]
msg = final_message(transcript)
assert msg, "no final message"
out = f"{RUN}/agents/{aid}/final.txt"
open(out, "w", encoding="utf-8").write(msg.strip() + "\n")
print(out)
