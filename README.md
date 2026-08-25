# SIEM and detection engineering

Eight projects built on one Splunk instance, in the order they were built. Each
one has its own README, its own tests, and its own evidence directory holding the
real command output behind every number quoted here.

They are in one repository because they check each other. Three of them produce
results about the other five, and that argument only holds together in one place.

## The projects

| # | Project | What it does | Tests |
|---|---|---|---|
| 1 | [splunk-lab](splunk-lab/) | Installing and running Splunk Enterprise unprivileged, no root | - |
| 2 | [splunk-ingest-pipeline](splunk-ingest-pipeline/) | Universal Forwarder, sourcetypes, CIM, and what a bad sourcetype costs | 5 |
| 3 | [splunk-detection-lab](splunk-detection-lab/) | Six Windows detections scored against labelled attack captures, then scored again for robustness | 28 |
| 4 | [cloud-detection-lab](cloud-detection-lab/) | Twelve cloud detections across AWS, Azure and Office 365, written in Sigma | 29 |
| 5 | [ir-activemq-lockbit](ir-activemq-lockbit/) | A full incident investigation: ActiveMQ remote code execution through to LockBit ransomware | 18 |
| 6 | [detection-as-code](detection-as-code/) | Validating and behaviourally testing the detection content in projects 3 and 4 | 15 |
| 7 | [soar-playbooks](soar-playbooks/) | Automated response playbooks triggered by the alerts project 3 produces | 20 |
| 8 | [stix-feed-overlap](stix-feed-overlap/) | Do public threat feeds contain the indicators from project 5's intrusion? | 34 |

## The three results that check the others

**Project 3 predicted its own detections were fragile.** Scored against MITRE
CTID's Summiting the Pyramid rubric, four of the six sit at Level 1, the weakest
tier, because they match text an attacker chooses rather than anything intrinsic
to the technique.

**Project 5 proved it, on a completely different intrusion.** Those same six
detections, run unmodified against the LockBit intrusion, caught one. D3 and D6
missed activity they were built to catch: the attacker ran `net group "Admins
Domain" /domain` instead of `net localgroup administrators`, and spawned recon
from `cmd.exe` instead of `powershell.exe`. Same behaviour, different strings.

**Project 6 showed a headline number was weaker than it looked.** Project 3
reports zero false positives across 242,133 benign events. Project 6 checked
whether that baseline could ever have produced one. It holds 2,030 process
creations, 6,194 process accesses and 66,675 registry writes, and **zero** events
touching `net.exe`, `schtasks.exe`, `AUDIODG.EXE` or a registry Run key. So the
detections were never tested by it. That is not evidence of precision, it is
evidence of an unrepresentative baseline.

## What none of this claims

- One Splunk instance. No distributed indexing, no clustering, no production
  scale.
- Precision and false-positive rates are not computed anywhere, because no
  representative benign corpus exists here. Project 6 is the measurement of that
  gap rather than a workaround for it.
- The detection robustness scores are analytic judgements against a published
  rubric, made by the same person who wrote the detections. That is not
  independent review.
- Project 7 recommends response actions and labels them `SIMULATED_ACTION`.
  Nothing is isolated, disabled or blocked, because there is no live
  infrastructure to act on.
- Project 8 measured zero overlap against a partial sample of one public feed.
  A lab reproduction of an intrusion is a legitimate alternative explanation for
  absent indicators, and the project says so.

## Running any of these

Each project documents its own setup. Common to all of them:

```
export SPLUNK_PASS='your-splunk-admin-password'   # no default, by design
cd <project>
python3 -m pytest tests/ -q
```

Some tests skip without their source data, which is large, untracked and
refetchable. Each project's README says how to get it.
