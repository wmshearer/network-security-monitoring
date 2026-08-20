"""Load the llm-abuse-detection corpus into SQLite.

The corpus is not copied into this repo. It is read from the sibling project,
so there is one copy of the data and no chance of the two drifting apart.
"""
import csv, sqlite3
from pathlib import Path

SRC = Path("/home/kali/director/projects/llm-abuse-detection/data")
DB = Path(__file__).resolve().parent.parent / "data" / "prompts.db"

FILES = [
    ("malicious_jailbreak_1405.csv", "malicious", "verazuo/jailbreak_llms"),
    ("benign_dolly_1405.csv", "benign", "databricks-dolly-15k"),
]

def main():
    DB.parent.mkdir(exist_ok=True)
    if DB.exists():
        DB.unlink()
    conn = sqlite3.connect(DB)
    conn.execute("""CREATE TABLE prompts(
        prompt_id INTEGER PRIMARY KEY,
        text TEXT NOT NULL,
        label TEXT NOT NULL,
        source TEXT NOT NULL)""")
    for fname, label, source in FILES:
        rows = []
        with open(SRC / fname, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            col = "text" if "text" in reader.fieldnames else reader.fieldnames[0]
            for row in reader:
                text = (row.get(col) or "").strip()
                if text:
                    rows.append((text, label, source))
        conn.executemany(
            "INSERT INTO prompts(text,label,source) VALUES(?,?,?)", rows)
        print(f"  {label}: {len(rows):,}")
    conn.execute("CREATE INDEX idx_label ON prompts(label)")
    conn.commit()
    conn.close()
    print(f"-> {DB}")

if __name__ == "__main__":
    main()
