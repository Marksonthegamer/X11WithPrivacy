#!/bin/bash

# Xorg Module
sudo cp ./xsm.so /usr/lib/xorg/modules/extensions/
sudo cp ./99-xsm.conf /usr/share/X11/xorg.conf.d/

# XSM Policy
xsm_policy_dir="/etc/xsm"
if [ ! -d "$xsm_policy_dir" ];
then
	sudo mkdir -p "$xsm_policy_dir"
	sudo touch "$xsm_policy_dir/whitelist"
fi
sudo cp ./default.rules "$xsm_policy_dir"

sudo cp ./dbus-policy/xsm-policy.conf /etc/dbus-1/session.d/xsm-policy.conf
