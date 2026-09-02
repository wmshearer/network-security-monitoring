"""Fetch both corpora from their public sources.

Nothing in this repo ships the data. Both corpora are large and both belong to
their publishers, so this script pulls them and the repo stays small.

Run once before anything else.
"""
import subprocess
import sys
import zipfile
from pathlib import Path
from urllib.request import urlretrieve

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"

# Twitter's Election Integrity releases. The transparency page that used to
# link these now 404s, but the storage bucket behind it is still public. Access
# confirmed 2026-08-20. Treat availability as fragile and mirror what you need.
BUCKET = "https://storage.googleapis.com/twitter-election-integrity/hashed/2020_12"
OPERATIONS = ["armenia_202012", "GRU_202012", "IRA_202012", "iran_202012"]

# Caverlee 2011 social honeypot, via the OSoMe bot repository at Indiana
# University. Academic use. The legitimate_users half is the benign control.
CAVERLEE = ("https://botometer.osome.iu.edu/bot-repository/datasets/"
            "caverlee-2011/caverlee-2011.zip")


def fetch_operations():
    RAW.mkdir(parents=True, exist_ok=True)
    for op in OPERATIONS:
        dest = RAW / f"{op}_tweets.csv"
        if dest.exists():
            print(f"  {op}: already present")
            continue
        url = f"{BUCKET}/{op}/{op}_tweets_csv_hashed.csv"
        print(f"  {op}: downloading...")
        urlretrieve(url, dest)
        print(f"  {op}: {dest.stat().st_size / 1e6:.0f} MB")


def fetch_control():
    users = RAW / "legitimate_users.txt"
    tweets = RAW / "legitimate_users_tweets.txt"
    if users.exists() and tweets.exists():
        print("  control: already present")
        return

    archive = RAW / "caverlee-2011.zip"
    if not archive.exists():
        print("  control: downloading 252 MB...")
        urlretrieve(CAVERLEE, archive)

    print("  control: extracting the legitimate-user half only")
    with zipfile.ZipFile(archive) as z:
        for name in z.namelist():
            base = Path(name).name
            if base in ("legitimate_users.txt", "legitimate_users_tweets.txt"):
                with z.open(name) as src, (RAW / base).open("wb") as dst:
                    dst.write(src.read())
    archive.unlink()   # the content_polluters half is not used here


if __name__ == "__main__":
    print("influence operations:")
    fetch_operations()
    print("benign control:")
    fetch_control()
    print(f"\n-> {RAW}")
