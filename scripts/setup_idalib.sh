#!/bin/bash
#
# Setup idalib for ida-headless-mcp
# Auto-detects the latest IDA Pro/Essential installation

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Find IDA installation: check IDA_PATH env, then scan /Applications for latest version
find_ida() {
    if [ -n "$IDA_PATH" ] && [ -d "$IDA_PATH" ]; then
        echo "$IDA_PATH"
        return
    fi

    # Find all IDA installations, sort by version descending, pick the latest
    local latest
    latest=$(ls -d /Applications/IDA*.app/Contents/MacOS 2>/dev/null | sort -t'/' -k3,3rV | head -1)
    if [ -n "$latest" ]; then
        echo "$latest"
    fi
}

IDA_PATH=$(find_ida)

if [ -z "$IDA_PATH" ] || [ ! -d "$IDA_PATH" ]; then
    echo -e "${RED}No IDA installation found in /Applications${NC}"
    echo "Set IDA_PATH to your IDA MacOS directory, e.g.:"
    echo "  IDA_PATH=\"/Applications/IDA Pro 9.3.app/Contents/MacOS\" $0"
    exit 1
fi

# Extract app name for display
IDA_APP=$(echo "$IDA_PATH" | sed 's|.*/\(IDA[^/]*\)\.app/.*|\1|')
echo -e "${GREEN}Found $IDA_APP${NC}"

IDALIB_DIR="$IDA_PATH/idalib"

if [ ! -d "$IDALIB_DIR" ]; then
    echo -e "${RED}idalib directory not found in $IDA_APP${NC}"
    echo "idalib requires IDA Pro 9.0+ or IDA Essential 9.2+"
    exit 1
fi

echo -e "${GREEN}Found idalib${NC}"
echo

# Install idapro Python package (wheel or setup.py)
echo "Installing idapro Python package..."
WHL=$(ls "$IDALIB_DIR/python/"*.whl 2>/dev/null | head -1)
if [ -n "$WHL" ]; then
    # IDA 9.3+: wheel package
    if pip3 install --force-reinstall "$WHL" 2>/dev/null; then
        echo -e "${GREEN}Installed $(basename "$WHL")${NC}"
    else
        echo -e "${YELLOW}pip3 install failed for $WHL${NC}"
    fi
elif [ -f "$IDALIB_DIR/python/setup.py" ]; then
    # IDA 9.2: setup.py
    if pip3 install "$IDALIB_DIR/python" 2>/dev/null; then
        echo -e "${GREEN}Installed idapro via setup.py${NC}"
    else
        echo -e "${YELLOW}pip3 install failed${NC}"
    fi
else
    echo -e "${RED}No wheel or setup.py found in $IDALIB_DIR/python/${NC}"
    exit 1
fi

echo

# Activate idalib (points idapro at the correct IDA installation)
echo "Activating idalib..."
ACTIVATE_SCRIPT="$IDALIB_DIR/python/py-activate-idalib.py"

if [ ! -f "$ACTIVATE_SCRIPT" ]; then
    echo -e "${RED}Activation script not found: $ACTIVATE_SCRIPT${NC}"
    exit 1
fi

if python3 "$ACTIVATE_SCRIPT" -d "$IDA_PATH"; then
    echo -e "${GREEN}idalib activated${NC}"
else
    echo -e "${RED}Failed to activate idalib${NC}"
    exit 1
fi

echo

# Verify
echo "Testing idalib import..."
if python3 -c "import idapro; v=idapro.get_library_version(); print(f'idalib {v[0]}.{v[1]} ready')" 2>/dev/null; then
    echo -e "${GREEN}Setup complete${NC}"
else
    echo -e "${RED}Failed to import idapro${NC}"
    exit 1
fi
