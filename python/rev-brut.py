import sys
import subprocess

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <binary> <inputs.txt>")
    raise SystemExit(2)

binary, inputs_file = sys.argv[1], sys.argv[2]

with open(inputs_file, "r", errors="replace") as f:
    for line in f:
        if not line.endswith("\n"):
            line += "\n"

        print(line, end="")  # print the input (don’t add extra newline)
        subprocess.run([binary], input=line.encode("utf-8", "replace"))
