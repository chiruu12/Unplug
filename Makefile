.PHONY: install test test-security lint format

install:
	cd sdk && uv sync --all-extras

test:
	cd sdk && uv run pytest -v

test-security:
	cd sdk && uv run pytest tests/test_adversarial.py tests/test_false_positives.py tests/test_encodings.py tests/test_secrets.py tests/test_scan_policy.py tests/test_security_stress.py tests/test_sdk_coverage.py tests/test_financial.py -v
	@if [ -f ../repos/unplug_exp/scripts/eval_sdk_security.py ]; then \
		cd ../repos/unplug_exp && uv run python scripts/eval_sdk_security.py --sdk ../../jakarta/sdk; \
	fi

lint:
	cd sdk && uv run ruff check .

format:
	cd sdk && uv run ruff format .
