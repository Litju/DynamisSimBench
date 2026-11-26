"""The production Windows AppContainer boundary refuses a non-adopted principal."""

from __future__ import annotations

import os

import pytest

from dynamisbench.host import protected_windows

windows_only = pytest.mark.skipif(
    os.name != "nt", reason="the AppContainer principal is a Windows observation"
)


def test_availability_is_a_boolean_observation() -> None:
    assert isinstance(protected_windows.is_available(), bool)


@windows_only
def test_the_supervisor_principal_is_measured_from_its_own_token() -> None:
    principal = protected_windows.supervisor_principal()

    assert isinstance(principal["elevated"], bool)
    assert isinstance(principal["elevation_type"], int)
    assert str(principal["integrity_level"]).startswith("S-1-16-")
    assert isinstance(principal["capability_count"], int)
    assert isinstance(principal["privileges"], list)


@windows_only
def test_an_elevated_supervisor_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    elevated = {
        "elevated": True,
        "elevation_type": 1,
        "integrity_level": "S-1-16-12288",
        "capability_count": 0,
        "privileges": [],
    }
    monkeypatch.setattr(protected_windows, "supervisor_principal", lambda: dict(elevated))

    with pytest.raises(protected_windows.PrincipalError, match="elevated"):
        protected_windows.require_non_elevated_supervisor()


@windows_only
def test_an_elevated_residual_can_only_be_accepted_explicitly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    elevated = {
        "elevated": True,
        "elevation_type": 1,
        "integrity_level": "S-1-16-12288",
        "capability_count": 0,
        "privileges": [],
    }
    monkeypatch.setattr(protected_windows, "supervisor_principal", lambda: dict(elevated))

    accepted = protected_windows.require_non_elevated_supervisor(accept_elevated_residual=True)

    assert accepted["elevated"] is True


@windows_only
def test_the_real_supervisor_principal_is_the_adopted_one() -> None:
    """On this host, either the non-elevated gate passes or it refuses an elevated token.

    The hosted Windows runner is elevated, so its CI assertion is the refusal. The qualified
    protected execution is on a non-elevated principal, which is the owner's production
    requirement.
    """
    if os.name != "nt":
        pytest.skip("the AppContainer principal is a Windows observation")
    principal = protected_windows.supervisor_principal()

    if principal["elevated"]:
        with pytest.raises(protected_windows.PrincipalError):
            protected_windows.require_non_elevated_supervisor()
    else:
        accepted = protected_windows.require_non_elevated_supervisor()
        assert accepted["elevated"] is False
