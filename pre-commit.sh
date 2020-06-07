#! /bin/sh

# Setup pre-commit
pip install pre-commit
pre-commit install -t pre-commit
pre-commit install -t pre-push
pre-commit install -t commit-msg
