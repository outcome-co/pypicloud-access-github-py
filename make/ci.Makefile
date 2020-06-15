ifndef MK_CI
MK_CI=1

# Determine whether we're in a CI environment such as Github Actions
# Github Actions defines a GITHUB_ACTIONS=true variable
#
# Generic tools can set CI=true 
ifneq "$(or $(GITHUB_ACTIONS), $(CI))" ""
$(info Running in CI mode)
INSIDE_CI=1
else
NOT_INSIDE_CI=1
endif

# CI WORKFLOW

.PHONY: check check-types lint lint-flake lint-black lint-isort

check: check-types lint ## Run checks and linters

check-types: ## Run mypy
	# Disabled for now
	#poetry run mypy ./bin ./src

lint: clean lint-isort lint-black lint-flake ## Run all linters
	
lint-flake: ## Run flake linting
	poetry run flake8 ./src ./test
	(test -d bin && poetry run flake8 ./bin) || true

ifdef NOT_INSIDE_CI
# Not inside a CI process
lint-black: ## Run black
	poetry run black .

lint-isort: ## Run isort 
	poetry run isort -rc .
endif
	
ifdef INSIDE_CI
# Inside the CI process, we want to run black with the --check flag and isort 
# with the --diff flag to not change the files but fail if changes should be made
lint-black: 
	poetry run black --check .

lint-isort: 
	poetry run isort -rc . --check-only
endif

.PHONY: test test-unit test-integration coverage

# We have two types of tests, unit tests and integration tests. Sometimes we want to run both types, sometimes just one type.
#
# We have three targets: `test`, `test-unit`, and `test-integration`
#
# Combining the two types is the only way to get 100% coverage (or, more specifically, unit-tests can't get 100% coverage, 
# and we don't want to have to test complex business logic with integration tests), so we use `coverage combine` to merge the
# coverage reports from the unit tests and integration tests.
#
# This raises a couple of issues as we have to do some housekeeping before and after each test run:
#
# before -> remove previous coverage files
# run tests
# after -> combine coverage files and run reports
#
# We want this behaviour to work for *all three* targets, but since `test-unit` and `test-integration` are dependent targets of `test`,
# `test-unit` and `test-integration` need to know whether they're being called independently (i.e. they handle the housekeeping), or
# if they're being called as dependents of `test`.
#
# This is achieved by through the SKIP_COVERAGE variable. When `make` is called with SKIP_COVERAGE=1 all coverage targets are
# no-ops. Read through the targets below to follow the implementation.

# By default, we're not running all tests
ALL_TESTS = 0

# Unless we've already got a value for SKIP_COVERAGE, set it to 0
ifndef SKIP_COVERAGE
SKIP_COVERAGE=0
endif

# When we run `test`, we set ALL_TESTS=1
# Note, no use of `export`
test: ALL_TESTS=1
# The `test` target calls `clean-coverage` and `coverage` as normal dependent targets
test: clean test-unit test-integration coverage ## Run all tests

# This Makefile macro is used by both `test-unit` and `test-integration`
# We recursively call `make`, setting the SKIP_COVERAGE variable to the value of ALL_TESTS
# i.e. SKIP_COVERAGE=1 when the `test` target has been called, or SKIP_COVERAGE=0 otherwise
define run-pytest
	@SKIP_COVERAGE=$(ALL_TESTS) $(MAKE) clean-coverage
	poetry run coverage run --context=$(COVERAGE_CONTEXT) -m pytest ./test
	poetry run coverage combine --append
	@SKIP_COVERAGE=$(ALL_TESTS) $(MAKE) coverage
endef

# For all cases, we set the python path
coverage: export PYTHONPATH = src
# If SKIP_COVERAGE=0, define normal coverage targets
ifeq ($(SKIP_COVERAGE), 0)
ifdef NOT_INSIDE_CI
# Not inside a CI process
coverage: ## Create coverage reports
	# Run a first coverage, to the console but don't fail based on %
	poetry run coverage report -m --fail-under 0
	# Run a second coverage to output html, and fail according to %
	poetry run coverage html --show-contexts
endif # closes ifdef NOT_INSIDE_CI

ifdef INSIDE_CI
coverage: 
	@# Just run converage, and fail according to %
	poetry run coverage report -m
endif # closes ifdef INSIDE_CI
endif # closes ifndef SKIP_COVERAGE

# If SKIP_COVERAGE=1, define the target as a no-op
ifeq ($(SKIP_COVERAGE), 1)
# Defining the clean-coverage target here overrides the existing target
coverage:
	@# no-op
endif

# The types of tests to run are controlled by the APP_ENV variable
test-unit: export APP_ENV = test
test-unit: export COVERAGE_CONTEXT = unit-test
test-unit: export PYTHONPATH = src
test-unit: ## Run unit tests
	# Unit tests
	$(call run-pytest)	

test-integration: export APP_ENV = integration
test-integration: export COVERAGE_CONTEXT = integration-test
test-integration: export PYTHONPATH = src
test-integration: ## Run integration tests 
	# Integration tests
	$(call run-pytest)	


# CLEANING

.PHONY: clean clean-docs clean-coverage

clean: clean-docs clean-coverage clean-python ## Remove generated data

clean-docs: ## Remove docs
	rm -rf docs

clean-python: ## Remove python artifacts
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -delete
	rm -rf dist

ifeq ($(SKIP_COVERAGE), 1)
clean-coverage:
	@# no-op
endif

ifeq ($(SKIP_COVERAGE), 0)
clean-coverage: ## Remove coverage reports
	# Cleaning coverage files
	rm -rf coverage
endif

endif
