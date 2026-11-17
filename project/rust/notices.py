"""Write rust/NOTICES.md from what Cargo itself reports: every outside library compiled into garrett, its version,
the licence its authors declare, and the licence texts as they are in each library's own package. Nothing here is
typed by hand.

    python3 -B rust/notices.py            write the file
    python3 -B rust/notices.py --check    fail if the file is out of date
"""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ALLOWED = ("MIT", "Apache-2.0", "Unlicense", "BSL-1.0", "Unicode-3.0", "Unicode-DFS-2016", "BSD-3-Clause", "BSD-2-Clause", "ISC", "Zlib", "CDLA-Permissive-2.0", "MPL-2.0")

data = json.loads(subprocess.run(["cargo", "metadata", "--format-version", "1", "--locked", "--manifest-path", str(HERE / "Cargo.toml")],
                                 check=True, stdout=subprocess.PIPE).stdout)
ours = {member for member in data["workspace_members"]}
rows, strange, texts, without = [], [], {}, []
for package in sorted(data["packages"], key=lambda item: (item["name"], item["version"])):
    if package["id"] in ours:
        continue
    # The licence files in the library's own package, exactly as its authors wrote them.
    folder, found = Path(package["manifest_path"]).parent, False
    for entry in sorted(folder.iterdir(), key=lambda item: item.name.lower()):
        if entry.is_file() and entry.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "UNLICENSE", "NOTICE", "COPYRIGHT")):
            body = entry.read_bytes().decode("utf-8", "replace").replace("\r\n", "\n").strip()
            if body:
                texts.setdefault(body, []).append("%s %s (%s)" % (package["name"], package["version"], entry.name))
                found = True
    if not found:
        without.append("%s %s" % (package["name"], package["version"]))
    licence = package.get("license") or "(none declared)"
    words = licence.replace("(", " ").replace(")", " ").replace("/", " OR ").split()
    if not all(word in ALLOWED or word in ("OR", "AND", "WITH", "LLVM-exception") for word in words):
        strange.append("%s %s: %s" % (package["name"], package["version"], licence))
    rows.append("| %s | %s | %s | %s |" % (package["name"], package["version"], licence, package.get("repository") or ""))
if strange:
    raise SystemExit("a library declares a licence that has not been looked at:\n  " + "\n  ".join(strange))
text = "\n".join([
    "# Libraries compiled into garrett",
    "",
    "garrett's own code is MIT licensed (see LICENSE). The Rust agent is built with the open source libraries below,",
    "at exactly these versions (rust/Cargo.lock). This table is generated from Cargo's own records by rust/notices.py:",
    "the licence column is what each library's authors declare.",
    "",
    "| Library | Version | Licence | Source |",
    "|---|---|---|---|",
    *rows,
    "",
    "## The licence texts",
    "",
    "Each text below is copied from the package of the libraries named above it. Identical texts are printed once.",
    *(["", "No licence file is inside the package of: " + ", ".join(without) + ". Their licence is the one declared in the table."] if without else []),
    *[line for body, users in sorted(texts.items(), key=lambda item: (sorted(item[1]), item[0])) for line in ("", "### " + ", ".join(sorted(users)), "", "```", body.replace("```", "~~~"), "```")],
    "",
])
target = HERE / "NOTICES.md"
if "--check" in sys.argv:
    if not target.exists() or target.read_text(encoding="utf-8") != text:
        raise SystemExit("rust/NOTICES.md is out of date: run python3 -B rust/notices.py")
    print("NOTICES.md is current: %d libraries" % len(rows))
else:
    target.write_text(text, encoding="utf-8", newline="\n")
    print("wrote NOTICES.md: %d libraries" % len(rows))
