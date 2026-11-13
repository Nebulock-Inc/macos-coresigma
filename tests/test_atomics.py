"""Validate simulation atomic YAML files against schema."""
import pytest
import yaml
from pathlib import Path


ATOMICS_DIR = Path(__file__).parent.parent / "simulations" / "atomics"
ATOMIC_FILES = list(ATOMICS_DIR.glob("*.yaml"))


@pytest.mark.parametrize("atomic_file", ATOMIC_FILES, ids=lambda p: p.name)
def test_atomic_schema(atomic_file):
    """Validate atomic YAML structure and required fields."""
    with open(atomic_file) as f:
        data = yaml.safe_load(f)

    # Required top-level fields
    assert "attack_technique" in data, "Missing attack_technique"
    assert data["attack_technique"].startswith("T"), "attack_technique must start with T"

    assert "atomic_tests" in data, "Missing atomic_tests"
    assert isinstance(data["atomic_tests"], list), "atomic_tests must be a list"
    assert len(data["atomic_tests"]) > 0, "atomic_tests must not be empty"


@pytest.mark.parametrize("atomic_file", ATOMIC_FILES, ids=lambda p: p.name)
def test_atomic_test_structure(atomic_file):
    """Validate each test within the atomic."""
    with open(atomic_file) as f:
        data = yaml.safe_load(f)

    for i, test in enumerate(data["atomic_tests"]):
        # Required test fields
        assert "name" in test, f"Test {i}: missing name"
        assert "description" in test, f"Test {i}: missing description"
        assert "supported_platforms" in test, f"Test {i}: missing supported_platforms"
        assert "executor" in test, f"Test {i}: missing executor"

        # Validate supported_platforms
        assert isinstance(test["supported_platforms"], list), f"Test {i}: supported_platforms must be a list"
        assert "macos" in test["supported_platforms"], f"Test {i}: must support macos platform"

        # Validate executor
        executor = test["executor"]
        assert "name" in executor, f"Test {i}: executor missing name"
        assert executor["name"] in ["sh", "bash"], f"Test {i}: executor name must be sh or bash"
        assert "command" in executor, f"Test {i}: executor missing command"
        assert "cleanup_command" in executor, f"Test {i}: executor missing cleanup_command"

        # Validate non-empty commands
        assert executor["command"].strip(), f"Test {i}: command must not be empty"
        assert executor["cleanup_command"].strip(), f"Test {i}: cleanup_command must not be empty"


@pytest.mark.parametrize("atomic_file", ATOMIC_FILES, ids=lambda p: p.name)
def test_atomic_description_has_fidelity_limits(atomic_file):
    """Validate that descriptions document fidelity limits."""
    with open(atomic_file) as f:
        data = yaml.safe_load(f)

    for i, test in enumerate(data["atomic_tests"]):
        desc = test["description"]
        # Check for fidelity limits section
        assert "fidelity limit" in desc.lower(), \
            f"Test {i}: description must document fidelity limits"


@pytest.mark.parametrize("atomic_file", ATOMIC_FILES, ids=lambda p: p.name)
def test_atomic_description_has_falcon_status(atomic_file):
    """Validate that descriptions record a Falcon block status: pending, blocked or not blocked."""
    with open(atomic_file) as f:
        data = yaml.safe_load(f)

    for i, test in enumerate(data["atomic_tests"]):
        status = [line for line in test["description"].lower().splitlines() if "falcon block status" in line]
        assert status, f"Test {i}: description must have a Falcon block status line"
        assert any(word in status[0] for word in ("pending", "blocked")), \
            f"Test {i}: Falcon status must be pending, blocked or not blocked"


def test_all_atomics_found():
    """Verify all expected atomic files exist."""
    expected = [
        "T1059.002-paste-to-stealer.yaml",
        "T1553.001-gatekeeper-evasion.yaml",
        "T1195.002-package-manager-persistence.yaml",
        "T1021.004-ssh-localhost-login.yaml",
        "T1620-wx-memory.yaml",
        "T1021-remote-execution-tool.yaml",
        "T1021.002-smb-mount-attempt.yaml",
        "T1036.008-media-file-in-app-bundle.yaml",
        "T1071-netcat-localhost.yaml",
        "T1071.004-dns-query-tool.yaml",
        "T1078-authorization-right-denied.yaml",
        "T1486-encryption-tool.yaml",
        "T1489-launch-job-bootout.yaml",
        "T1489-mass-process-termination.yaml",
        "T1552.001-credential-fanout-node-standin.yaml",
        "T1553.001-spctl-assess-unsigned.yaml",
        "T1555.001-keychain-partition-list.yaml",
        "T1559-xpc-from-tmp.yaml",
        "T1559-xpc-test-service.yaml",
        "T1560.001-data-compression-tools.yaml",
        "T1567.002-cloud-storage-cli.yaml",
        "T1570-scp-local-copy.yaml",
        "T1685-sigkill-security-tool-standin.yaml",
        "T1685-sigterm-btm-agent-standin.yaml",
        "T1136.001-local-account-lifecycle.yaml",
        "T1548.003-rejected-sudo-non-sudoer.yaml",
    ]
    actual = [f.name for f in ATOMIC_FILES]

    for expected_file in expected:
        assert expected_file in actual, f"Missing expected atomic: {expected_file}"
