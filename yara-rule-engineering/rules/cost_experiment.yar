/*
 * Controlled cost experiment for Q2 (rule cost / what makes a ruleset slow).
 *
 * All four rules below target the SAME nine bytes of information: the
 * dynamic linker path string "/lib64/ld-linux-x86-64.so.2", which is
 * present in 2278 of 3239 files in the usr_bin corpus (measured directly,
 * see evidence/corpus_manifest.json + evidence/06_cost_experiment_*.json).
 * Only the pattern-matching CONSTRUCT changes between rules; the target
 * content and the corpus are held fixed, so any wall-clock difference
 * between rules is attributable to the construct, not to how much of the
 * corpus each rule actually matches. This is verified in
 * tests/test_cost_experiment.py: all four rules must produce the exact
 * same match count on the same corpus, or the comparison is invalid and
 * the test fails loudly instead of the finding being reported anyway.
 *
 * cost_literal_string   : plain literal string match, ASCII, no modifiers
 * cost_regex            : same 28 bytes expressed as an escaped regex
 * cost_hex_wildcard     : same 28 bytes as a hex pattern with 6 wildcard
 *                         nibbles standing in for the digit characters
 *                         (still only matches the literal digits actually
 *                         present, verified byte-identical match set)
 * cost_elf_loop         : `for` loop over elf.sections, checking the
 *                         section name equals ".dynstr" -- the section that
 *                         its own content, in practice, is the same dynamic
 *                         string table which contains the same substring;
 *                         this construct requires the "elf" module (a
 *                         structured parse of the file) rather than a flat
 *                         byte scan, which is the point of the comparison
 */

rule cost_literal_string {
    strings:
        $s = "/lib64/ld-linux-x86-64.so.2"
    condition:
        $s
}

rule cost_regex {
    strings:
        $s = /\/lib64\/ld\-linux\-x86\-64\.so\.2/
    condition:
        $s
}

rule cost_hex_wildcard {
    strings:
        $s = { 2F 6C 69 62 3? 3? 2F 6C 64 2D 6C 69 6E 75 78 2D 78 3? 3? 2D 3? 3? 2E 73 6F 2E 3? }
    condition:
        $s
}

import "elf"

rule cost_elf_loop {
    condition:
        for any section in elf.sections : (
            section.name == ".dynstr"
        )
}
