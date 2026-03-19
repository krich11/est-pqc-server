from pathlib import Path
import sys

if len(sys.argv) != 4:
    raise SystemExit("usage: normalize_remote_webui_users.py <admin-hash> <krich-hash> <config-path>")

admin_hash, krich_hash, config_path = sys.argv[1], sys.argv[2], sys.argv[3]
path = Path(config_path)
lines = path.read_text().splitlines()

out = []
i = 0
while i < len(lines):
    line = lines[i]
    stripped = line.strip()

    if stripped == "# temporary browser test users":
        i += 1
        continue

    if stripped == "[[webui.users]]":
        i += 1
        while i < len(lines):
            current = lines[i]
            current_stripped = current.strip()
            if current.startswith("[["):
                break
            if current.startswith("[") and current_stripped != "[[webui.users]]":
                break
            i += 1
        continue

    out.append(line)
    i += 1

text = "\n".join(out).rstrip() + f"""

# temporary browser test users
[[webui.users]]
username = "admin"
password_hash = "{admin_hash}"
role = "super-admin"
enabled = true

[[webui.users]]
username = "krich"
password_hash = "{krich_hash}"
role = "admin"
enabled = true
"""

path.write_text(text + "\n")