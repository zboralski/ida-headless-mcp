#!/bin/bash
# Check consistency rules - linked patterns must all match
set -e

RULES_FILE="${1:-consistency.yaml}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ ! -f "$RULES_FILE" ]]; then
    echo "Error: Rules file not found: $RULES_FILE"
    exit 1
fi

# Parse YAML and check each pattern
# Format: name, then patterns as "file:/regex/"
parse_and_check() {
    local current_rule=""
    local failed=0
    local total_rules=0
    local total_checks=0

    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$line" ]] && continue

        # Extract rule name
        if [[ "$line" =~ ^-[[:space:]]+name:[[:space:]]+(.+)$ ]]; then
            current_rule="${BASH_REMATCH[1]}"
            ((total_rules++))
            continue
        fi

        # Extract and check patterns
        if [[ "$line" =~ ^[[:space:]]+-[[:space:]]+([^:]+):\/(.+)\/$ ]]; then
            local file="${BASH_REMATCH[1]}"
            local pattern="${BASH_REMATCH[2]}"
            local full_path="$REPO_ROOT/$file"

            ((total_checks++))

            if [[ ! -f "$full_path" ]]; then
                echo "FAIL: $current_rule - file not found: $file"
                ((failed++))
                continue
            fi

            if ! grep -qE "$pattern" "$full_path"; then
                echo "FAIL: $current_rule - pattern not found in $file"
                echo "      Pattern: /$pattern/"
                ((failed++))
            fi
        fi
    done < "$RULES_FILE"

    echo ""
    echo "Consistency check: $total_checks patterns across $total_rules rules"

    if [[ $failed -gt 0 ]]; then
        echo "FAILED: $failed pattern(s) missing"
        return 1
    else
        echo "PASSED: All patterns found"
        return 0
    fi
}

parse_and_check
