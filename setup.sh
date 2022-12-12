#!/bin/bash

XCODE_PATH=/Applications/Xcode.app/Contents/Developer/
lldb_dir=$(pwd)/lldbinit.py
lldb_home=$HOME/.lldbinit

echo "Install typing_extensions...."

if ! [ -d "$XCODE_PATH" ]; then
	echo "Please install xcode first. :)"
	exit 1
fi

/Applications/Xcode.app/Contents/Developer/usr/bin/python3 -m pip install typing_extensions

echo "settings set target.x86-disassembly-flavor intel" >> $lldb_home
echo "command script import $lldb_dir" >> $lldb_home