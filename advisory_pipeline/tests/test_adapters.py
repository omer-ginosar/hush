"""
Basic validation tests for ingestion adapters.

Tests basic functionality and data loading for all adapters.
"""
import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from ingestion import (
    EchoCsvAdapter,
    EchoDataAdapter,
    NvdAdapter,
    OsvAdapter,
)


def test_echo_data_adapter():
    """Test Echo data.json adapter can load and normalize data."""
    config = {
        "cache_path": "../data/data.json",
        "url": None
    }
    adapter = EchoDataAdapter(config)

    # Fetch observations
    observations = adapter.fetch()

    # Basic validations
    assert len(observations) > 0, "Should fetch observations from data.json"
    assert adapter.source_id == "echo_data"

    # Check health
    health = adapter.get_health()
    assert health.is_healthy, f"Adapter should be healthy: {health.error_message}"
    assert health.records_fetched == len(observations)

    # Validate observation structure
    obs = observations[0]
    assert obs.source_id == "echo_data"
    assert obs.cve_id is not None
    assert obs.package_name is not None
    assert obs.observation_id is not None

    print(f"✓ EchoDataAdapter: Loaded {len(observations)} observations")


def test_echo_csv_adapter():
    """Test Echo CSV adapter can load and normalize CSV overrides."""
    config = {
        "path": "../data/advisory-not-applicable.csv"
    }
    adapter = EchoCsvAdapter(config)

    # Fetch observations
    observations = adapter.fetch()

    # Basic validations
    assert len(observations) > 0, "Should fetch observations from CSV"
    assert adapter.source_id == "echo_csv"

    # Check health
    health = adapter.get_health()
    assert health.is_healthy, f"Adapter should be healthy: {health.error_message}"

    # Validate observation structure
    obs = observations[0]
    assert obs.source_id == "echo_csv"
    assert obs.cve_id is not None
    assert obs.package_name is not None
    assert obs.status is not None

    print(f"✓ EchoCsvAdapter: Loaded {len(observations)} observations")


def test_nvd_adapter():
    """Test NVD adapter can load and normalize mock responses."""
    config = {
        "use_mock": True,
        "mock_file": "ingestion/mock_responses/nvd_responses.json"
    }
    adapter = NvdAdapter(config)

    # Fetch observations
    observations = adapter.fetch()

    # Basic validations
    assert len(observations) > 0, "Should fetch mock NVD observations"
    assert adapter.source_id == "nvd"

    # Check health
    health = adapter.get_health()
    assert health.is_healthy, f"Adapter should be healthy: {health.error_message}"

    # Validate observation structure
    obs = observations[0]
    assert obs.source_id == "nvd"
    assert obs.cve_id is not None
    assert obs.cvss_score is not None or obs.rejection_status == "rejected"

    print(f"✓ NvdAdapter: Loaded {len(observations)} observations")


def test_osv_adapter():
    """Test OSV adapter can load and normalize mock responses."""
    config = {
        "use_mock": True,
        "mock_file": "ingestion/mock_responses/osv_responses.json"
    }
    adapter = OsvAdapter(config)

    # Fetch observations
    observations = adapter.fetch()

    # Basic validations
    assert len(observations) > 0, "Should fetch mock OSV observations"
    assert adapter.source_id == "osv"

    # Check health
    health = adapter.get_health()
    assert health.is_healthy, f"Adapter should be healthy: {health.error_message}"

    # Validate observation structure
    obs = observations[0]
    assert obs.source_id == "osv"
    assert obs.package_name is not None

    print(f"✓ OsvAdapter: Loaded {len(observations)} observations")


def main():
    """Run all tests."""
    print("Running adapter validation tests...\n")

    try:
        test_echo_data_adapter()
        test_echo_csv_adapter()
        test_nvd_adapter()
        test_osv_adapter()

        print("\n✅ All tests passed!")
        return 0

    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        return 1

    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
