"""Load each function's main.py under a distinct module name.

Both functions ship a file called main.py, so a plain import collides. We load them
explicitly by path and expose them as fixtures. The GCP/PAM calls inside each module
are lazy imports behind seams, so importing here needs only functions-framework, not
any google-cloud library.
"""

import importlib.util
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load(name: str, relpath: str):
    path = ROOT / relpath
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def broker():
    return _load("broker_main", "functions/request_broker/main.py")


@pytest.fixture
def reconcile_mod():
    return _load("reconcile_main", "functions/reconcile/main.py")


@pytest.fixture
def cfg():
    return {
        "project_id": "test-project",
        "location": "global",
        "audit_dataset": "bankvault_audit",
        "ledger_table": "access_grants",
        "credit_bucket": "test-credit-reports",
        "allowed_domain": "lender.example.com",
        "max_auth_age_seconds": 900,
        "max_grant_minutes": 30,
        "entitlement_prefix": "bankvault-credit-report-",
    }
