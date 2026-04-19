#!/bin/bash

#set -x

gcc `pkg-config xorg-server --cflags --libs dbus-1,libnotify,json-c` -DXACE -D_XSERVER64 -DX_REGISTRY_REQUEST -DX_REGISTRY_RESOURCE -DCOMPOSITE xsm.c -o xsm.so -shared -ldl -fPIC -s

gcc xsm-agent.c -o xsm-agent `pkg-config --cflags --libs gtk+-3.0 libnotify dbus-1`
