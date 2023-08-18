#!/bin/bash
#shell for cleaning the temporary and output files.

current_dir=$(dirname $0)

echo "cleaning files..."

rm -rf $current_dir/include
rm -rf $current_dir/tmp
rm -rf $current_dir/bin

echo "clean completion."
