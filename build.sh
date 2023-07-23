#!/bin/bash
THREADS=1

# Check for core numbers.
if [ -n "$1" ]; then
    if [ "$1" -eq 0 ]; then
        THREADS=$(nproc)
    elif [ "$1" -gt 0 ]; then
        THREADS=$1
    fi
fi

echo "Building Packet Batch (AF_XDP) using $THREADS threads..."

# First, we want to build our common objects which includes LibYAML. Read the PB-Common directory for more information.
echo "Building Common Repository..."

echo "Building LibYAML..."
sudo make -j $THREADS -C modules/common libyaml
echo "Done..."

echo "Building Common Main..."
make -j $THREADS -C modules/common
echo "Done..."

echo "Installing Common..."
sudo make -j $THREADS -C modules/common install
echo "Done..."

echo "Building AF_XDP Version..."

# Next, build LibBPF objects.
echo "Building LibBPF..."
make -j $THREADS libbpf
echo "Done..."

# Now build our primary objects and executables. You may use the `-j` flag followed by a number that indicates how many threads to use with the build process.
echo "Building Main..."
make -j $THREADS
echo "Done..."

# Finally, install our binary. This must be ran by root or with sudo.
echo "Installing Main..."
sudo make -j $THREADS install
echo "Done..."