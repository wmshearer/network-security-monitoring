"""Tests for src/select_cloud_files.py's classification and exclusion logic.

Does not hit the live corpus or Splunk -- these tests exercise the pure
classify()/is_excluded() functions against hand-built JSON objects and
paths, so they run the same whether or not the corpus/Splunk happen to be
available.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from select_cloud_files import classify, is_excluded  # noqa: E402


def test_classifies_raw_cloudtrail_shape():
    obj = {
        "eventTime": "2022-06-30T21:26:49Z",
        "eventSource": "cloudtrail.amazonaws.com",
        "awsRegion": "us-west-2",
        "eventName": "StopLogging",
    }
    assert classify(obj) == "aws_cloudtrail"


def test_classifies_ocsf_cloudtrail_shape_separately_from_raw():
    obj = {
        "metadata": {"product": {"name": "CloudTrail"}},
        "time": 1733908565000,  # epoch millis, an int, not a string
        "cloud": {"region": "us-east-1", "provider": "AWS"},
    }
    assert classify(obj) == "aws_cloudtrail_ocsf"


def test_classifies_azure_monitor_shape():
    obj = {
        "time": "2023-06-20T16:30:24.1848520Z",
        "operationName": "Add service principal",
        "category": "AuditLogs",
        "resourceId": "/tenants/x",
    }
    assert classify(obj) == "azure_monitor"


def test_classifies_o365_management_shape():
    obj = {
        "CreationTime": "2021-01-19T22:21:39",
        "Operation": "Add app role assignment grant to user.",
        "UserId": "someone@example.com",
    }
    assert classify(obj) == "o365_management"


def test_rejects_splunk_search_export_preview_shape():
    """This is the real trap the brief named: 4 O365 files use
    {"preview":..,"result":{"Actor{}.ID":..}} -- a Splunk search-result
    export, not the real O365 Management Activity API shape. This object
    ALSO carries CreationTime/Operation (the real o365_management shape)
    nested inside "result", nested exactly the way a real preview-wrapped
    export would -- but since those keys are one level down inside
    "result", not top-level, classify() would already return None for them
    via the normal shape check. The preview-shape check is exercised
    directly by giving the object a top-level CreationTime/Operation pair
    OUTSIDE of "result" as well, so the ONLY thing stopping a false
    o365_management match is _is_splunk_export_shape() catching the
    preview/result envelope first. Proven able to fail: with
    _is_splunk_export_shape() forced to return False (a local edit made and
    reverted after confirming), this assertion fails because classify()
    falls through to the o365_management branch and returns that instead of
    None."""
    obj = {
        "preview": False,
        "CreationTime": "2021-01-19T22:21:39",
        "Operation": "Add app role assignment grant to user.",
        "result": {
            "ActorIpAddress": "40.124.84.4",
            "Actor{}.ID": ["someone@example.com"],
            "ResultStatus": "Success",
        },
    }
    assert classify(obj) is None


def test_rejects_unrelated_json_shape():
    obj = {"some_other_field": "value", "count": 5}
    assert classify(obj) is None


def test_azure_time_as_epoch_int_is_not_misclassified_as_raw_azure():
    """A file with operationName but time as an integer (not a string)
    should NOT match azure_monitor -- catches a classifier that only checks
    key presence, not value type, which would wrongly conflate an
    OCSF-shaped record carrying an operationName-like key with the real
    Azure Monitor Activity Log shape."""
    obj = {
        "time": 1733908565000,
        "operationName": "test",
        "category": "AuditLogs",
    }
    assert classify(obj) != "azure_monitor"


def test_exclusion_by_named_path():
    assert is_excluded("T1528/vidar_azure_file_access/azure_vidar_access.log") is True


def test_exclusion_by_directory_pattern():
    assert is_excluded("T1204/kubernetes_falco_shell_spawned/falco.log") is True
    assert is_excluded("T1212/some_dataset/kubernetes_nginx_attack.log") is True


def test_real_cloud_file_in_same_directory_as_excluded_file_is_not_excluded():
    """T1136.003 has BOTH a real O365 file and 3 excluded preview-shaped
    O365 files in sibling directories -- exclusion must be scoped to the
    exact excluded paths/patterns, not the whole T1136.003 directory."""
    assert is_excluded("T1136.003/o365_new_federation/o365_new_federation.json") is False


def test_non_excluded_path_is_not_excluded():
    assert is_excluded("T1562.008/stop_delete_cloudtrail/aws_cloudtrail_events.json") is False
