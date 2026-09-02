"""Tests for the manual LDAP full-subtree dump detector.

Scope is the entire discriminator: a baseObject probe and a wholeSubtree dump
can carry the identical filter string, `(objectclass=*)`. A test that only
checked the filter and ignored scope would not catch a bug that merged the two
into one finding, so scope is exercised directly here.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.ldap_recon import (  # noqa: E402
    SCOPE_BASE_OBJECT,
    SCOPE_SINGLE_LEVEL,
    SCOPE_WHOLE_SUBTREE,
    LdapSearch,
    describe,
    is_subtree_dump,
)


def search(scope, base="", filter_present=True, frame=1,
           src="192.168.1.41", dst="192.168.1.62"):
    return LdapSearch(frame=frame, src=src, dst=dst, scope=scope,
                       base_object=base, filter_present=filter_present)


def test_wholesubtree_objectclass_star_is_a_dump():
    """The core case: (objectclass=*) at scope wholeSubtree over a real base DN."""
    s = search(SCOPE_WHOLE_SUBTREE, base="DC=picklesworth,DC=local")
    assert is_subtree_dump(s)
    assert "directory dump shape" in describe(s)


def test_baseobject_objectclass_star_is_a_probe_not_a_dump():
    """Identical filter string, different scope, a completely different query.

    A baseObject search returns exactly one object (often RootDSE) and is how
    a client discovers server capabilities. Without checking scope, this
    would be indistinguishable from pulling the entire directory.
    """
    s = search(SCOPE_BASE_OBJECT, base="")
    assert not is_subtree_dump(s)
    assert "capability probe" in describe(s)
    assert "dump" not in describe(s)


def test_single_level_scope_is_not_called_a_dump():
    """Scope 1 (one level below the base) is neither probe nor full dump."""
    s = search(SCOPE_SINGLE_LEVEL, base="OU=Users,DC=picklesworth,DC=local")
    assert not is_subtree_dump(s)
    assert "single-level" in describe(s)


def test_wholesubtree_with_a_narrow_filter_is_not_flagged_as_a_dump():
    """Scope alone is not sufficient: the filter must also be maximally permissive.

    A wholeSubtree search for one specific account is a targeted lookup, not
    a dump, even though it shares the scope with one.
    """
    s = search(SCOPE_WHOLE_SUBTREE, base="DC=picklesworth,DC=local",
               filter_present=False)
    assert not is_subtree_dump(s)


def test_empty_root_base_object_is_labelled_root():
    s = search(SCOPE_BASE_OBJECT, base="")
    assert "<ROOT>" in describe(s)


def test_describe_never_asserts_malice():
    """A human running ldapsearch by hand and a directory-sync tool both
    produce a wholeSubtree (objectclass=*) query. Shape does not distinguish
    intent.
    """
    labels = [describe(search(SCOPE_WHOLE_SUBTREE, base="DC=picklesworth,DC=local")),
              describe(search(SCOPE_BASE_OBJECT))]
    for label in labels:
        for word in ("attack", "malicious", "attacker", "compromise", "bloodhound"):
            assert word not in label.lower()
