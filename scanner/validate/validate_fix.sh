#!/usr/bin/env bash
set -e

APP_DIR="$1"
TARGET_FILE="$2"
PATCH_FILE="$3"

if [ -z "$APP_DIR" ] || [ -z "$TARGET_FILE" ] || [ -z "$PATCH_FILE" ]; then
    echo "Usage: $0 <app_dir> <target_file_relative_path> <patch_file>"
    exit 1
fi

cd "$APP_DIR"

WORKTREE_DIR=$(mktemp -d -t validate_fix_XXXXXX)
BRANCH_NAME="validate-fix-$(basename $WORKTREE_DIR)"

# Create a worktree
git worktree add -b "$BRANCH_NAME" "$WORKTREE_DIR" HEAD

# Ensure cleanup on exit
cleanup() {
    cd "$APP_DIR"
    git worktree remove --force "$WORKTREE_DIR"
    git branch -D "$BRANCH_NAME" > /dev/null 2>&1 || true
}
trap cleanup EXIT

# Apply the patch in the worktree
mkdir -p "$(dirname "$WORKTREE_DIR/$TARGET_FILE")"
cp "$PATCH_FILE" "$WORKTREE_DIR/$TARGET_FILE"

cd "$WORKTREE_DIR"

# Run tests
echo "Running ruff check..."
if ! command -v ruff &> /dev/null; then
    echo "ERROR: ruff not found in validation environment. Failing closed."
    exit 1
fi
ruff check "$TARGET_FILE" || exit 1

echo "Running bench run-tests..."
if ! command -v bench &> /dev/null; then
    echo "ERROR: bench not found in validation environment. Failing closed."
    exit 1
fi
timeout 600 bench run-tests --app "$(basename "$APP_DIR")" || exit 1

echo "Validation successful."
exit 0
