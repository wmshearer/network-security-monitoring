/*
Kerberoasting RC4 ticket detection expressed as a YARA rule.

This is the closest YARA can get to the Sigma base rule
(rules/sigma/kerberoasting_rc4_base.yml). YARA has no event model: no
timestamped stream, no schema, no field-typed comparison. It only matches
byte/text patterns in whatever blob it is pointed at. To use it here, the
Windows Security event record (raw XML or the EVTX-exported text log
format) is treated as an undifferentiated string, and the rule looks for
substrings that, on the real T1558.003 event, happen to co-occur:
  - "4769" (the EventID, but YARA cannot say "the field named EventID
    equals 4769" -- it can only say "this text contains 4769 somewhere")
  - "0x17" (meant to mean "TicketEncryptionType field equals 0x17", but
    YARA cannot bind the match to that field; it matches "0x17" ANYWHERE
    in the blob, including inside an unrelated field's value, e.g. a
    Process ID that happens to start with the digits 17)
  - one of the known Kerberoasting TicketOptions values, as a literal
    string, for the same reason: no field binding

What this rule CANNOT express, that the Sigma rule can:
  - "TicketEncryptionType equals 0x17" as a typed field comparison. YARA
    can only test "the substring 0x17 occurs in the blob." Any other field
    whose value happens to start with 0x17 (a process ID, a port, a byte
    offset) will satisfy this string just as well as the real field would.
  - Field co-occurrence within the SAME record boundary, if events are
    concatenated without per-record separation, is not guaranteed: YARA
    matches strings anywhere in the file it is pointed at unless the
    caller manually splits per-event and runs YARA once per event (done in
    scripts/03_run_yara_per_event.sh here specifically to keep the
    comparison fair; a single yara run over a whole multi-event log file
    would blur record boundaries even further).
  - Negation ("no such request occurred"): YARA only reports matches; a
    file with zero matches produces no output line, indistinguishable from
    "not scanned" or "tool broken," structurally identical to the
    stateless-negation problem raised for Sigma but worse, since YARA has
    no query language to express "count of matches == 0" as a positive
    condition itself.

Demonstrated false positive: see evidence/14_yara_false_positive.txt.
EventCode=4688 (process creation) in
_corpora/attack_data/datasets/attack_techniques/T1558.003/rubeus/windows-security.log,
line ~4164, is the Splunk Universal Forwarder's splunk-netmon.exe starting
under "New Process ID: 0x177c". It has nothing to do with Kerberos. The
substring "0x17" inside "0x177c" satisfies this rule's condition on its own
if the EventID/EventCode string check is loosened or omitted, which is
exactly the trap: TicketEncryptionType and a Process ID are different
fields with no relationship, but YARA cannot tell them apart once the
record is flattened to text.
*/

rule Kerberoasting_RC4_TGS_Request_StringMatch
{
    meta:
        description = "Best-effort YARA approximation of T1558.003 RC4 TGS ticket request detection. Matches raw text, not typed fields."
        attack_id = "T1558.003"
        author = "detection-engine-comparison project"
        reference = "rules/sigma/kerberoasting_rc4_base.yml"
        limitation = "Cannot bind 0x17 to the TicketEncryptionType field specifically; matches the substring anywhere in the scanned blob."

    strings:
        $eventid_xml = "<EventID>4769</EventID>"
        $eventid_text = "EventCode=4769"
        $enc_type = "0x17"
        $opt1 = "0x40810000"
        $opt2 = "0x40800000"
        $opt3 = "0x40810010"

    condition:
        ($eventid_xml or $eventid_text) and $enc_type and ($opt1 or $opt2 or $opt3)
}

rule Kerberoasting_RC4_Encryption_Type_Substring_Only
{
    meta:
        description = "Intentionally weaker rule kept for the false-positive demonstration: matches 0x17 as a bare substring with no EventID anchor at all, showing the failure mode at its simplest."
        attack_id = "T1558.003"
        author = "detection-engine-comparison project"
        limitation = "This is the demonstration rule for evidence/14_yara_false_positive.txt: it matches '0x177c' (an unrelated Process ID) exactly as readily as it matches a real TicketEncryptionType=0x17 field."

    strings:
        $enc_type = "0x17"

    condition:
        $enc_type
}
