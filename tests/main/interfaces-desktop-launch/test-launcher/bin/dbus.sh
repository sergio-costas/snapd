#!/bin/sh

exec dbus-send --session --print-reply \
    --dest=io.snapcraft.Launcher /io/snapcraft/PrivilegedDesktopLauncher \
    io.snapcraft.PrivilegedDesktopLauncher.OpenDesktopEntryWithArguments \
    string:"$1" array:string:"$2"
