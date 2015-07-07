#! /bin/bash
set -e

# tests
# run the suite with and without the daemon

# TODO: run the suite with/without encryption!

echo "-----------------------------"
echo "testing the raw cli (no http)"
echo "-----------------------------"
./test_commands.sh
echo "-----------------------------"
echo "testing the cli over http"
echo "-----------------------------"
echo "starting the server"
eris-keys server &
./test_commands.sh
