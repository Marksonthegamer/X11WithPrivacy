#!/bin/bash

sudo cp ./xsm-agent /usr/local/bin/

mkdir -p ~/.config/autostart

cp ./xsm-agent.desktop ~/.config/autostart/

chmod 644 ~/.config/autostart/xsm-agent.desktop
