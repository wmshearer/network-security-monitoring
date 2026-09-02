# Findings

Every number below is traceable to a named file in `evidence/`. Where a script
produces the evidence, the script is named too, so any number can be
recomputed from scratch by re-running `scripts/00_build_corpus.py` through
`scripts/07_generate_charts.py` in order.

Tool versions used throughout (confirmed live, not assumed, see
`tests/test_environment.py`): `yara` CLI 4.5.8 (system package), `yara-python`
4.5.4 and `yara-x` 1.20.0 (both in this project's `.venv`).

## The clean corpus

Built by `scripts/00_build_corpus.py`, recorded in
`evidence/corpus_manifest.json` and `evidence/corpus_manifest_summary.json`.

| Corpus | Root | Files | Notes |
|---|---|---|---|
| `usr_bin` | `/usr/bin` | 3,239 | regular files only, symlinks excluded, capped at 50MB/file |
| `usr_lib_x86_64` | `/usr/lib/x86_64-linux-gnu` | 1,683 | top level only, not recursive into plugin subdirectories |
| `openwrt_firmware` | OpenWrt 24.10.8 squashfs, from the sibling `firmware-analysis` project | 2,181 | full tree, no cap |
| `iotgoat_firmware` | OWASP IoTGoat (MIT licence), from the sibling `firmware-binary-analysis` project | 1,012 | full tree, no cap |

**IoTGoat is a deliberately vulnerable training image, not malware.** It ships
one intentional backdoor (`etc/init.d/shellback`, documented in the sibling
project's `FINDINGS.md`). No malware sample of any kind was downloaded or
used anywhere in this project.

A real bug was found and fixed while building this manifest: an early version
counted 4,366 entries under `usr_bin` instead of the correct 3,239, because
`os.walk()`'s file list includes symlinks, and `Path.is_file()` follows a
symlink to test its target. `/usr/bin` has 1,123 symlinks, 608 of which point
outside `/usr/bin` entirely (e.g. into `/etc/alternatives`), so counting them
as regular files double-counted bytes already present under another name. The
fix (`scripts/00_build_corpus.py`, `iter_files()`) skips symlinks explicitly;
the resulting counts match `find -type f` exactly (verified: `find /usr/bin
-type f | wc -l` = 3,244; 3,244 minus the 5 files over the 50MB cap = 3,239).

**Size cap.** `usr_bin` and `usr_lib_x86_64` each exclude files over 50MB (5
files in `usr_bin`, 10 in `usr_lib_x86_64`) so total scan time stays inside
this project's ~10 minute-per-run timebox. A handful of very large binaries
(`sliver-server` at 254MB, `pandoc` at 203MB) would otherwise dominate
wall-clock time with no bearing on the false-positive question. Every
excluded file is logged in `corpus_manifest.json`'s `excluded_too_large`
list, not silently dropped.

## Ruleset licences (verified from the cloned repos, not assumed)

Cloned by `scripts/01_fetch_rulesets.sh` into a gitignored `.rulesets/`
directory (never vendored into this repo); the actual LICENSE file from each
repo is captured verbatim in `evidence/ruleset_licenses.txt`.

| Repo | Commit | Licence | Verified from |
|---|---|---|---|
| `Yara-Rules/rules` | `0f93570` | GPLv2 | `LICENSE` |
| `reversinglabs/reversinglabs-yara-rules` | `e0a0be5` | MIT (Copyright 2020 ReversingLabs) | `LICENSE` |
| `Neo23x0/signature-base` | `e737ebd` | **Detection Rule License (DRL) 1.1** | `LICENSE` |
| `elastic/protections-artifacts` | `9c334cf` | **Elastic License 2.0** | `LICENSE.txt` |

**The licence split is itself a finding.** The common advice in public
writeups is "just clone signature-base," but its licence is the custom,
non-OSI Detection Rule License 1.1, which requires retaining author
attribution and a link back to the licence on redistribution. Elastic's
`protections-artifacts` is under the Elastic License 2.0, which is
source-available but explicitly forbids offering the software "to third
parties as a hosted or managed service." Only `Yara-Rules/rules` (GPLv2) and
`reversinglabs/reversinglabs-yara-rules` (MIT) are true OSI open source.
Nothing from any of the four repos is vendored into this project; all four
are cloned at runtime and referenced by path only.

## Q1: do public YARA rules fire on clean files?

Scans run by `scripts/04_scan_clean_corpus.py`, raw results in
`evidence/04_scan_clean_corpus_yara_python.json`, chart in
`evidence/chart_q1_false_positive_rate.png`.

Per-file compilation was necessary because compiling a whole ruleset as one
unit fails on the first bad file and never reaches the rest: compiling
`Yara-Rules/rules`' own maintained `index.yar` fails immediately at
`malware/RAT_CrossRAT.yar` with `invalid field name "md5"` (verified
directly with `yara.compile(filepath=...)`), long before any of the other
425 files in that ruleset are even attempted.

### The headline number, and why it needs a second number next to it

| Ruleset | usr/bin | usr/lib | OpenWrt firmware | IoTGoat firmware |
|---|---|---|---|---|
| `yara-rules`, naive clone (all directories, including `utils/`) | 395/400 (98.75%) | 398/400 (99.50%) | 2,159/2,181 (98.99%) | 1,001/1,012 (98.91%) |
| `yara-rules`, scoped to the project's own `index.yar` | 45/400 (11.25%) | 76/400 (19.00%) | 183/2,181 (8.39%) | 69/1,012 (6.82%) |
| `reversinglabs` | 0/3,239 (0.00%) | 0/1,683 (0.00%) | 0/2,181 (0.00%) | 0/1,012 (0.00%) |
| `signature-base` | 3/3,239 (0.09%) | 0/1,683 (0.00%) | 0/2,181 (0.00%) | 0/1,012 (0.00%) |
| `protections-artifacts` | 3/3,239 (0.09%) | 0/1,683 (0.00%) | 0/2,181 (0.00%) | 0/1,012 (0.00%) |

(`usr_bin`/`usr_lib_x86_64` are capped to 400 files for the two `yara-rules`
variants only, because that ruleset's 12,630 compiled rules scan roughly two
to three orders of magnitude slower than the other three rulesets on the
same corpus; see "Q2" below and `evidence/04_yara_rules_speed_probe.txt`.
Every other cell is the full corpus.)

**The 98.75-99.50% figure for the naive clone is almost entirely an artifact
of four rules that should never have been included.** `Yara-Rules/rules`'
own `index.yar` (the file its README points users to) does NOT include the
`utils/` directory. Checked directly (`evidence/ruleset_index_scope.txt`):
`grep "utils" index.yar` returns nothing, while every other non-deprecated
category is referenced. `utils/` contains four rules (`domain`, `url`,
`ip`, `contains_base64`) built to detect "does this look like a domain /
URL / IP address / base64 blob," not "is this malicious." `rule domain`'s
entire detection surface is the regex `/([\w\.-]+)/`, which matches any run
of word characters, dots, or hyphens: present in essentially every binary
that contains readable text. These four rules alone account for the bulk of
the naive-clone matches (`domain` 395/400, `contains_base64` 386/400 on
`usr_bin`; see `evidence/04_scan_clean_corpus_yara_python.json`). Once
`utils/` (and `mobile_malware/`, also excluded from `index.yar`) is dropped,
the same ruleset's rate falls by roughly an order of magnitude, to 6.8-19%.

**This is a two-part finding, not a contradiction:** (1) if you clone a
public YARA repo and compile every `.yar` file you find, as the "just
git clone it" advice on forums and blog posts implies, you get a
near-worthless, 98%+ false-positive detector; (2) the repo's own maintainers
already knew this and scoped their shipped index accordingly. The gap
between what people actually do and what the project intends is the
finding.

### Manual inspection of the top firing rules (the value-add over a bare rate)

**`Big_Numbers1`** (`crypto/crypto_signatures.yar`, 135/2,181 files on the
OpenWrt firmware corpus under the scoped ruleset) is not a cryptographic
constant check at all: `$c0 = /[0-9a-fA-F]{32}/ fullword wide ascii` matches
*any* fullword 32-character hex string. Traced to a concrete file
(`evidence/04_scan_clean_corpus_yara_python.json`,
`ns2_crypto_signatures.yar:Big_Numbers1`): `etc/opkg/distfeeds.conf`, an
entirely benign OpenWrt package-feed configuration file, contains the
32-character kernel-ABI hash `70248021204b78344d5fb62a0e7f5bea` inside a
plain-text package repository URL. This is a coincidental string match, not
a real cryptographic constant, and the rule's own name and description
("Looks for big numbers 32:sized") are honest about being a coincidence-prone
heuristic rather than a real detection.

**`ldpreload`** (`capabilities/capabilities.yar`, matched `/usr/bin/bash`
among others) fires on the mere presence of common libc symbol names --
`dlopen`, `dlsym`, `fopen`, `open`, `accept`, `unlink`, `opendir`,
`readdir`, which appear in the dynamic symbol table (`.dynstr`) of nearly
every dynamically-linked ELF binary that touches the filesystem or network.
Confirmed at the byte level in `/usr/bin/bash`: `dlopen` appears at file
offset `0x15542`, screenshotted directly in Cutter's hexdump view
(`evidence/gui/01-cutter-bash-ldpreload-hexdump.png`), sitting among dozens
of other ordinary libc symbol names (`__cxa_finalize`, `localtime`,
`putenv`, `setlocale`, `strchr`, `fgets_unlocked`, `readdir`) in bash's
`.dynstr` section. Bash calling `dlopen`/`open`/`fopen` is completely
unremarkable; the rule cannot distinguish "a program that touches files" from
"a program with LD_PRELOAD-style capability."

**`RijnDael_AES`** (same file, matched `usr/sbin/dropbear` inside the IoTGoat
firmware) is a genuinely different case: `$c0 = { A5 63 63 C6 84 7C 7C F8 }`
is the correctly-formatted first eight bytes of the AES forward S-box, laid
out as {Sbox[0], Sbox[0]^Sbox[1], Sbox[1], Sbox[1]^Sbox[2], ...}. Verified at
file offset `0x25790` in `usr/sbin/dropbear` with two independent tools
(`yara-python`'s match offset and a plain `xxd -s 0x25790 -l 16`, see
`evidence/rijndael_aes_dropbear_offset.txt`): both report
`a563 63c6 847c 7cf8 9977 77ee 8d7b 7bf6`, an exact AES S-box fragment.
Dropbear is a real SSH server that legitimately implements AES for the SSH
transport cipher, so this rule fires correctly on real cryptographic code --
the match is structurally meaningful, unlike `Big_Numbers1`'s coincidence,
even though dropbear itself is not malware. **A screenshot of this specific
byte pattern in Cutter's hexdump could not be reliably captured**: Cutter
exited without a visible window on repeated launches against this ARM32
binary, and the file offset does not equal the virtual address for this
non-PIE ELF (its `LOAD` segment maps file offset 0 to virtual address
`0x10000`, confirmed with `readelf -l`), which is itself a real,
worth-documenting trap for anyone pointing a disassembler at a YARA-reported
file offset. The bytes are independently confirmed by two CLI tools instead;
no image was fabricated to stand in for the missing screenshot.

**The three real detections on `usr_bin` are not false positives at all.**
`signature-base`'s `HKTL_Dsniff` rule fired on `/usr/bin/dsniff`,
`/usr/bin/sshmitm`, `/usr/bin/webmitm`, which are Kali's own dsniff/MITM toolkit.
`protections-artifacts`' rules fired on `/usr/bin/aircrack-ng` (a WiFi
attack tool), `/usr/bin/masscan` (a port scanner, flagged twice by two
separate `Linux_Hacktool_Portscan` sub-rules), and `/usr/bin/sliver-client`
(flagged by Elastic's own `Multi_Trojan_Sliver` rule, matched twice by two
sub-signatures). These are Kali Linux's real, intentionally-installed
offensive security tools, correctly identified as exactly what they are.
The near-zero false-positive rate for these two rulesets is not because they
are silent on everything, it is because the handful of times they do fire
on this machine, they are right.

## Q2: rule cost, what makes a ruleset slow

`rules/cost_experiment.yar` defines four rules targeting the identical 28
bytes of content (`/lib64/ld-linux-x86-64.so.2`, present in 2,278 of the
3,239 `usr_bin` files) via four constructs: a literal string, an equivalent
regex, an equivalent hex pattern with six wildcard nibbles, and a `for` loop
over `elf.sections` checking for a `.dynstr` section. Measured by
`scripts/06_cost_experiment.py`, raw data in
`evidence/06_cost_experiment_timing.json`, chart in
`evidence/chart_q2_cost_by_construct.png`, real `yara -S` output captured in
`evidence/gui/02-yara-print-stats-literal-string.png` and
`evidence/gui/03-yara-print-stats-cost-elf-loop.png`.

**Match parity, checked before trusting the timing comparison:** the literal
string, regex, and hex-with-wildcards rules match the exact same 2,278 files
(0 files different, checked pairwise). The `elf.sections` loop matches 2,310
files, 34 more (mostly `qemu-*` cross-architecture emulation binaries,
which have a `.dynstr` section but are not themselves x86-64 binaries
referencing that exact linker path string) and 2 fewer (`ldd`,
`gprofng-display-html`, which contain the literal path text but were not
classified as having a `.dynstr` section by this exact check). This 36-file
difference is explained, not hidden, and it means the elf-loop bar in the
chart is reported as a separate, not directly equivalent, measurement.

**Result: literal string, regex, and hex-with-wildcards are statistically
indistinguishable.** Over 7 repeated full-corpus scans each (3,239 files per
repeat):

| Construct | Mean | Stdev | Matches |
|---|---|---|---|
| Literal string | 1.851s | 0.043s | 2,278 |
| Regex | 1.826s | 0.006s | 2,278 |
| Hex + wildcards | 1.896s | 0.082s | 2,278 |
| `for` loop over `elf.sections` | 3.636s | 0.182s | 2,310 |

The three byte-scan constructs land within roughly one stdev of each other's
means; `yara -S`'s own stats confirm why: all three compile down to
identical Aho-Corasick automaton stats (`number of strings: 1`, `number of
AC matches: 1`, see `evidence/06_print_stats_output.txt` and the two
screenshots above). YARA's compiler reduces the literal string, the regex
`/\/lib64\/ld\-linux\-x86\-64\.so\.2/`, and the wildcarded hex pattern to the
same underlying string-matching structure, so at least for a single fixed
literal-equivalent pattern, the *syntax* used to write it does not change
the scan cost.

**The `elf` module loop is a genuinely different, ~2x slower cost.** Its own
`yara -S` output shows `number of strings: 0`, it never uses YARA's
string-matching engine at all, relying entirely on the `elf` module's parsed
view of the file's section table. That is a fundamentally different code
path (structured file parsing vs. a flat byte scan), and it costs roughly
double the wall-clock time of any of the three byte-scan constructs.

**What `yara -S --print-stats` actually reports**, described from the real
observed output (not from documentation): size of the Aho-Corasick
transition table, the average and per-percentile length of AC match lists
(how many candidate strings map to the same short atom), total rule count,
total string count, total AC match count, and AC matches broken out for the
100 longest lists plus percentile buckets. For a single-rule, single-string
ruleset, most of these numbers are trivially 0 or 1; the field that carries
information here is `number of strings` (1 for the three byte-scan
constructs, 0 for the module-based one), which is exactly what explains the
cost difference.

**A real, unplanned finding surfaced while building the corpus for this
experiment:** merging `yara-rules`' full 426-file, 12,630-rule set into one
compiled ruleset and scanning `usr_bin` measured at only ~5.3 files/sec,
versus 313-488 files/sec for the other three rulesets on the same 100 files
(`evidence/04_yara_rules_speed_probe.txt`). Investigated further: no single
category subdirectory within `yara-rules` scanned anywhere near this
slowly on its own (the slowest, `crypto`, took 1.64s for 50 files); merging
all 11 categories into one ruleset and re-timing the same 50 files took
4.04s, several times slower than any category alone. Combining many rule
files into one shared Aho-Corasick automaton adds per-file cost as the
automaton and its candidate-match lists grow, beyond the simple sum of each
category's individual cost, this is why `yara-rules` needed a corpus cap
(see Q1) while the other three rulesets, each with far fewer total rules,
did not.

## Q3: does YARA-X agree with YARA 4.x?

Compile comparison via `scripts/02_compile_rulesets.py` (yara-python) and
`scripts/03_compile_rulesets_yarax.py` (yara-x); scan comparison via
`scripts/05_diff_yara_vs_yarax.py`; module support via
`scripts/03b_check_module_support.py`.

### Compile-time portability: real, quantified differences

| Ruleset | yara-python compiled/total | yara-x compiled/total |
|---|---|---|
| `yara-rules` | 426/444 | 433/444 |
| `reversinglabs` | 308/310 | 310/310 |
| `signature-base` | 640/746 | 733/746 |
| `protections-artifacts` | 1,040/1,040 | 1,040/1,040 |

yara-python fails on 144 rule files total across all five compiled ruleset
variants (`evidence/02_compile_results_yara_python.json`); 85 of those 144
are the single error `invalid field name "imphash"` (a rule using
`pe.imphash` without an `import "pe"` statement, or referencing it in a
context yara-python's grammar rejects without the import). yara-x fails on
far fewer files across the same rulesets (11 for `yara-rules`, 0 for
`reversinglabs`, 13 for `signature-base`, 0 for `protections-artifacts`),
and its failures are of a different, specific kind: yara-x's compiler
requires external variables like `filename`, `filepath`, and `extension` to
be declared up front, while yara-python's `yara.compile()` accepts them as
undefined externals that only matter (and can error) at scan time. This is a
real behavioural difference in how strict the two compilers are, not a bug
in either.

**Concrete example, both directions checked:**
`reversinglabs/yara/certificate/blocklist.yara` (931 rules) fails to compile
under yara-python (`invalid field name "number_of_signatures"`, since this
file also omits `import "pe"`) but compiles successfully under yara-x. Also
checked directly (`scripts/03b_check_module_support.py`,
`evidence/03b_module_support.json`): the `hash` and `cuckoo` modules compile
fine under yara-x 1.20.0 but are unknown modules under this system's
yara-python 4.5.4 build (`unknown module "hash"` /
`unknown module "cuckoo"`), while `androguard` and `magic` are unsupported by
both. Module availability depends on how libyara was compiled
(`--enable-hash`, `--enable-cuckoo`), and this system's `libyara10` package
was not built with either.

### Runtime agreement: near-total, on the rules both engines can compile

Restricting to files that compile successfully under BOTH engines (the only
fair basis for a scan-behaviour diff), scanning the same corpora with the
same merged ruleset through both:

**14,869 of 14,871 sampled file-scans agree exactly** (99.99%) across all
four rulesets and all four corpora (`evidence/05_diff_yara_vs_yarax.json`).
`reversinglabs` and `protections-artifacts` show zero disagreements at all,
on every corpus sampled. This supports treating "no behavioural difference"
as the honest headline result for the files both engines can actually run,
which is a legitimate finding given VirusTotal's own framing of YARA-X as
the eventual replacement, no difference was manufactured to make this
project more interesting than it is.

**The two exceptions, both explained:**

1. `libQt5Core.so.5.15.19` and `libQt6Core.so.6.10.2` (in `usr_lib_x86_64`,
   under the `yara-rules-official-index` ruleset): yara-python's
   `Big_Numbers1` fires, yara-x's does not. `Big_Numbers1`'s pattern is a
   generic 32-hex-char match (see Q1); these two large Qt libraries likely
   contain a qualifying string in one engine's read of the file but not the
   other's, most plausibly from a difference in how each engine's regex
   engine or fullword boundary check treats a specific byte sequence. This
   is the only true behavioural disagreement found, out of 14,871 sampled
   scans, and it is on the weakest, most coincidence-prone rule in the
   ruleset, not evidence of a systemic engine difference.

2. A 20MB FAT32 partition image extracted from the IoTGoat firmware
   (`.../IoTGoat-raspberry-pi2-sysupgrade.img.extracted/0/FAT32_partition.0`):
   yara-python's 5-second per-file timeout was exceeded (`scanning timed
   out`), while yara-x completed the identical scan with the identical
   ruleset and found 17 matches, well within its own 5-second timeout.
   Independently re-run with a longer 15-second timeout: yara-python
   completes the same file in 6.5 seconds and finds the same 17 matches
   yara-x found. This is not a correctness disagreement, it is a real,
   reproducible speed difference on this specific file and ruleset.

### Performance: yara-x is meaningfully faster on this test

On the `yara-rules-official-index` ruleset (416 rule files compiling under
both engines), scanning the same 150-file `usr_bin` sample: yara-python
took 16.1s, yara-x took 1.1s, roughly 15x faster. On the 300-file
`usr_lib_x86_64` sample: yara-python 53.2s vs yara-x 8.0s, roughly 6.6x. The
other three, much smaller rulesets show far less difference (both engines
complete in under 2 seconds on the same samples), consistent with the Q2
finding that scan cost scales with ruleset size in a way that is not additive.

### Confirmed, not just cited, from YARA-X's own docs

Both claims from `site/content/docs/intro/yara_vs_yara-x.md` (VirusTotal's
own docs, cited in the task brief) were checked directly rather than taken
on faith: (1) the pip-installed `yara-x` package genuinely ships no `yr` CLI
binary in this venv (`tests/test_environment.py::test_yara_x_has_no_cli_binary_in_this_venv`,
confirmed with `shutil.which`); (2) the Python API is genuinely not a drop-in
replacement for yara-python's, `yara_x.Rules` has no `len()`/iteration
support for enumerating rule names (unlike `yara.Rules`), no rule-count
introspection method exists in 1.20.0, and file-scanning uses a separate
`Scanner` object (`yara_x.Scanner(rules).scan_file(path)`) rather than
`rules.match(path)`. This required writing a custom rule-declaration counter
(`scripts/rule_count.py`) just to report rule counts consistently across
both engines; that counter itself needed two real bug fixes during
development (see its module docstring) before it agreed with yara-python's
authoritative count on all 2,414 compilable files checked.

Process scanning (also flagged as unimplemented in YARA-X's own docs) was
not independently tested: this project only scans files, never live
processes, so the claim was out of scope to verify and is reported as-is
from the primary source, not re-confirmed.

## What was capped, and why (summary)

- `usr_bin`/`usr_lib_x86_64` corpora: capped at 50MB per file (excludes 5 and
  10 files respectively) so total scan time across all rulesets stays
  bounded. See "The clean corpus" above.
- `yara-rules` and `yara-rules-official-index` specifically: `usr_bin` and
  `usr_lib_x86_64` further capped to the first 400 files (alphabetical) for
  the Q1 scan, because this ruleset's ~12,600 compiled rules run 50-1500x
  slower per file than the other three rulesets on the same corpus
  (`evidence/04_yara_rules_speed_probe.txt`). The two firmware corpora
  (already small) are never capped.
- Q3's engine diff (`scripts/05_diff_yara_vs_yarax.py`): `usr_bin`/
  `usr_lib_x86_64` sampled to 300 files (150 for the `yara-rules-official-
  index` ruleset specifically), for the same reason
  (`evidence/05_diff_speed_note.txt`); the two firmware corpora run at full
  size for every ruleset.

No scan in the final evidence set ran longer than about 5.5 minutes
individually; the full pipeline (`scripts/00` through `scripts/07`) completes
in under 15 minutes total on this machine.

## GUI evidence: what was used, and what was not

**Used:** Cutter 2.5.0 (Rizin GUI), launched with `-A 1` for automated
analysis, for the `/usr/bin/bash` + `ldpreload` hexdump inspection
(`evidence/gui/01-cutter-bash-ldpreload-hexdump.png`), the single
highest-value manual-inspection artifact in this project, since it shows the
actual matched bytes at the actual file offset in a real disassembler.

**Attempted, and reported as incomplete:** a second Cutter
screenshot for the `RijnDael_AES` / dropbear example. Cutter's Hexdump view
would not navigate to the correct offset for this specific ARM32, non-PIE
binary across several attempts (the file-offset-vs-virtual-address distinction
described above), and the process exited without a visible window on two
further relaunches. Rather than fabricate or force a screenshot, the same
bytes are confirmed with two independent CLI tools instead
(`evidence/rijndael_aes_dropbear_offset.txt`), and the failure mode itself
(file offset != virtual address for a non-PIE ELF) is documented as a real,
useful trap.

**Considered and rejected:** Ghidra, for the same second example. The
sibling `firmware-binary-analysis` project already demonstrates Ghidra
working well on ARM/musl binaries from this same firmware image, so a second
Ghidra screenshot here would not add new tooling evidence, and Ghidra's
project-creation wizard is a much larger, harder-to-script interaction than
Cutter's single-flag automated analysis for the time available. A YARA-specific
GUI (`yaraQA`, a VS Code YARA extension, a GUI rule editor) was not
investigated for this project; the two questions this project answers
(false-positive rate, cost, engine agreement) are answered by the scripted
scan/compile/diff pipeline, not by an interactive rule editor, so a GUI rule
editor would not have produced load-bearing evidence for any of the three
questions.

**CLI-only evidence** (`evidence/gui/02-*`, `03-*`, `04-*`): captured as real
qterminal windows via `termcap.sh`, not rendered/mocked terminal output,
for the two parts of this project with no meaningful GUI surface --
`yara -S --print-stats` output and the ruleset-compile summary script.
