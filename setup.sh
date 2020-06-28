#!/bin/bash

lldb_dir=$(pwd)/lldbinit.py
lldb_home=$HOME/.lldbinit

echo "settings set target.x86-disassembly-flavor intel" >> $lldb_home
echo "command script import $lldb_dir" >> $lldb_home
