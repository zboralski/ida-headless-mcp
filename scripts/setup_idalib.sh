#!/bin/bash

IDA_PATH="/Applications/IDA Essential 9.2.app/Contents/MacOS"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ -d "$IDA_PATH" ]; then
    echo -e "${GREEN}✓ Found IDA Essential 9.2${NC}"
else
    echo -e "${RED}✗ IDA not found at: $IDA_PATH${NC}"
    exit 1
fi

IDALIB_DIR="$IDA_PATH/idalib"

if [ ! -d "$IDALIB_DIR" ]; then
    echo -e "${RED}✗ idalib directory not found${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Found idalib${NC}"
echo

echo "Installing idalib Python package..."
if pip3 install "$IDALIB_DIR/python" 2>/dev/null; then
    echo -e "${GREEN}✓ idalib Python package installed${NC}"
else
    echo -e "${YELLOW}⚠ idalib might already be installed${NC}"
fi

echo
echo "Activating idalib..."
ACTIVATE_SCRIPT="$IDA_PATH/idalib/python/py-activate-idalib.py"

if python3 "$ACTIVATE_SCRIPT" -d "$IDA_PATH"; then
    echo -e "${GREEN}✓ idalib activated${NC}"
else
    echo -e "${RED}✗ Failed to activate idalib${NC}"
    exit 1
fi

echo
echo "Testing idalib import..."
if python3 -c "import idapro; print('✓ idalib ready')" 2>/dev/null; then
    echo -e "${GREEN}✓ idalib is ready${NC}"
else
    echo -e "${RED}✗ Failed to import idalib${NC}"
    exit 1
fi

echo
echo -e "${GREEN}Setup complete!${NC}"
