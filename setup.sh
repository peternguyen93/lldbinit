#!/bin/bash

XCODE_PATH=/Applications/Xcode.app/Contents/Developer/
COMMAND_LINE_PATH=/Library/Developer/CommandLineTools/usr/bin/
lldb_dir=$(pwd)/lldbinit.py
lldb_home=$HOME/.lldbinit

echo "Install typing_extensions...."

if [ -d "$XCODE_PATH" ]; then
	echo "Using python in Xcode to install"
	/Applications/Xcode.app/Contents/Developer/usr/bin/python3 -m pip install typing_extensions
elif [ -d "$COMMAND_LINE_PATH" ]; then
	echo "Using python in CommandLineTools to install"
	/Library/Developer/CommandLineTools/usr/bin/python3 -m pip install typing_extensions
else
	echo "Require xcode or CommandLineTools is installed"
	exit 1
fi

echo "settings set target.x86-disassembly-flavor intel" >> $lldb_home
echo "command script import $lldb_dir" >> $lldb_home