#!/bin/bash

# XSM Policy
xsm_policy_dir="/etc/xsm"
if [ ! -d "$xsm_policy_dir" ];
then
	sudo mkdir -p "$xsm_policy_dir"
	sudo touch "$xsm_policy_dir/whitelist_screenshot"
	sudo touch "$xsm_policy_dir/whitelist_screencast"
	sudo touch "$xsm_policy_dir/whitelist_clipboard"
	sudo touch "$xsm_policy_dir/whitelist_xrecord"
	echo "/usr/libexec/at-spi2-registryd" | sudo tee -a "$xsm_policy_dir/whitelist_xrecord" > /dev/null
	echo "/usr/bin/kglobalaccel5" | sudo tee -a "$xsm_policy_dir/whitelist_xrecord" > /dev/null
	echo "/usr/bin/kded5" | sudo tee -a "$xsm_policy_dir/whitelist_xrecord" > /dev/null

	sudo touch "$xsm_policy_dir/blacklist_screenshot"
	sudo touch "$xsm_policy_dir/blacklist_screencast"
	sudo touch "$xsm_policy_dir/blacklist_clipboard"
	sudo touch "$xsm_policy_dir/blacklist_xrecord"
fi

# Xorg Module
sudo cp ./xsm.so /usr/lib/xorg/modules/extensions/
sudo cp ./99-xsm.conf /usr/share/X11/xorg.conf.d/

sudo cp ./default.rules "$xsm_policy_dir"

sudo cp ./dbus-policy/xsm-policy.conf /etc/dbus-1/session.d/xsm-policy.conf
