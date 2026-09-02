# Dataset

This project uses the combined CIRA-CIC-DoHBrw-2020 / DoH-Tunnel-Traffic-HKD
dataset, an extended mirror of CIC's original DoH tunneling dataset with
per-tool labels added for the malicious side.

## Source

Download (219MB zip, 824MB unzipped, no login required):

```
curl -sL -o data/doh-hkd.zip "https://eprints.lib.hokudai.ac.jp/repo/huscap/all/88092/CIRA-CIC-DoHBrw-2020-and-DoH-Tunnel-Traffic-HKD.zip"
unzip -o data/doh-hkd.zip -d data/
```

This produces four files under `data/`, none of which are committed to
this repository (see below):

- `l1-total-add.csv` (550MB): DoH vs non-DoH traffic. Not used here.
- `l2-total-add.csv` (128MB, 374,804 rows): DoH traffic labeled Benign
  (19,807 rows) or Malicious (354,996 rows). This is where the benign
  class comes from.
- `l3-total-add.csv` (146MB, 354,997 rows): the malicious rows only,
  labeled by which tunneling tool produced them: dns2tcp (167,486),
  dnscat2 (35,770), iodine (46,580), dnstt (46,080), tcp-over-dns
  (30,040), tuns (29,040). This is where the per-tool labels used for
  leave-one-tool-out evaluation come from.
- `README.txt`: the upstream citation and license notice, reproduced
  below.

`src/data.py` loads the benign rows from `l2-total-add.csv` and the
tool-labeled malicious rows from `l3-total-add.csv` directly, rather than
joining the two files by row. Both files share the same 34-column
DoHLyzer schema. A join by IP/port/timestamp or even by the full feature
row was tried and rejected: about 99,902 rows in each file are exact
duplicates of another row (idle/empty flows produce identical stats), so
any key-based join is many-to-many and multiplies rows instead of
matching them one to one. Concatenating the two label sources avoids that
problem entirely, since neither file needs to be matched against the
other; see the module docstring in `src/data.py` for the full reasoning.

## Citation

If you use this dataset, cite both source papers:

Mohammadreza MontazeriShatoori, Logan Davidson, Gurdip Kaur, and Arash
Habibi Lashkari, "Detection of DoH Tunnels using Time-series
Classification of Encrypted Traffic," The 5th IEEE Cyber Science and
Technology Congress, Calgary, Canada, August 2020.
https://ieeexplore.ieee.org/document/9251211

Rikima Mitsuhashi, Yong Jin, Katsuyoshi Iida, Takahiro Shinagawa, and
Yoshiaki Takai, "Malicious DNS Tunnel Tool Recognition using Persistent
DoH Traffic Analysis," in IEEE Transactions on Network and Service
Management, 2022. https://ieeexplore.ieee.org/document/9924534

Original dataset pages:

- CIRA-CIC-DoHBrw-2020: https://www.unb.ca/cic/datasets/dohbrw-2020.html
- DoH-Tunnel-Traffic-HKD: https://github.com/doh-traffic-dataset/DoH-Tunnel-Traffic-HKD/

License terms (from the upstream `README.txt`, distributed with the zip):
free to redistribute with citation of both papers above.

## What's gitignored

`data/*.csv`, `data/*.zip`, and `data/*.txt` are excluded from this
repository (see `.gitignore`). The dataset is redistributable but large
(824MB unzipped) and not this project's to host as a mirror; the correct
way to get it is the source URL above, and the citation obligation stays
attached to it wherever it's downloaded from. Re-run the `curl`/`unzip`
commands above to reproduce `data/` locally before running
`scripts/run_analysis.py` or the real-data tests in `tests/`.
