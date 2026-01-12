# Advisory Pipeline Tests

Comprehensive test suite for the CVE advisory enrichment pipeline.

## Test Organization

### Unit Tests

- **test_adapters.py** - Source adapter validation
  - Tests for Echo, NVD, OSV, and CSV adapters
  - Normalization and data extraction logic
  - Error handling and edge cases
  - NVD/OSV tests run in mock mode by default (`use_mock: true`)

- **test_storage.py** - Storage layer tests
  - Database schema initialization
  - Source observation loading
  - Loader idempotency guarantees

- **test_decisioning_rules.py** - Individual rule validation
  - Each rule (R0-R6) tested independently
  - Rule condition evaluation
  - Decision output verification

- **test_rule_engine.py** - Rule engine orchestration
  - Rule chain execution
  - Priority-based matching
  - Batch processing
  - Deterministic decision validation

- **test_state_machine.py** - State transition validation
  - Valid and invalid transitions
  - Regression prevention (final -> non-final)
  - State type classification

- **test_explainer.py** - Explanation generation
  - Template substitution
  - Evidence formatting
  - Human-readable output

- **test_observability.py** - Metrics and quality checks
  - Run metrics collection
  - Data quality validation
  - Report generation

### Integration Tests

- **test_conflict_resolution.py** - Multi-source conflict handling
  - Source priority enforcement (CSV > NVD > OSV > Echo)
  - Conflicting signal resolution
  - Dissenting source tracking
  - Confidence scoring with multiple sources

- **test_integration.py** - End-to-end pipeline validation
  - Full ingestion -> load -> query flow
  - Cross-source joins
  - JSON payload preservation
  - NULL handling
  - Idempotent pipeline runs

### Test Fixtures

- **conftest.py** - Shared test fixtures
  - Temporary database setup
  - Sample observations for each source
  - Reusable loader instances

## Running Tests

### Run All Tests

```bash
cd advisory_pipeline
pytest tests/ -v
```

### Run Specific Test Module

```bash
pytest tests/test_rule_engine.py -v
pytest tests/test_conflict_resolution.py -v
```

### Run With Coverage

```bash
pytest tests/ --cov=advisory_pipeline --cov-report=html
```

### Run Integration Tests Only

```bash
pytest tests/test_integration.py tests/test_conflict_resolution.py -v
```

### Run Fast Unit Tests Only

```bash
pytest tests/ -v -m "not slow"
```

## Test Coverage Goals

- **Unit Tests**: >90% line coverage for core logic
- **Integration Tests**: Validate end-to-end flows
- **Edge Cases**: NULL handling, malformed data, empty inputs

## Writing New Tests

### Test Naming Conventions

- `test_<function>_<scenario>` - Clear, descriptive names
- Example: `test_csv_override_wins_over_upstream_fix`

### Test Structure

```python
def test_feature_behavior():
    """
    Docstring explaining what this test validates.

    This helps reviewers understand test intent.
    """
    # Arrange - Set up test data
    advisory_data = {...}

    # Act - Execute the function under test
    result = function_under_test(advisory_data)

    # Assert - Verify expected behavior
    assert result.state == 'expected_value'
```

### Using Fixtures

```python
def test_with_fixture(temp_db, loader):
    """Fixtures automatically injected by pytest."""
    loader.load_echo_advisories(observations, run_id)
    # Test continues...
```

## Test Philosophy

1. **Fast** - Unit tests run in milliseconds
2. **Isolated** - Each test is independent
3. **Comprehensive** - Cover happy path + edge cases
4. **Maintainable** - Clear names, good fixtures
5. **Deterministic** - Same input = same output, always

## Known Limitations

- **No dbt tests**: dbt models tested via `dbt test` separately
- **No live API tests**: Adapters use mock data
- **No performance tests**: Focus on correctness, not speed
- **No SCD2 tests**: Phase 11 will add SCD2Manager and tests

## Next Steps (Future Phases)

- Add SCD2 state history tests (Phase 11)
- Add performance benchmarks
- Add property-based tests (hypothesis)
- Add mutation testing (mutpy)
