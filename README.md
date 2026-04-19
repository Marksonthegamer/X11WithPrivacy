# X11WithPrivacy

**X11WithPrivacy** is a lightweight Xorg server extension that provides fine-grained control over privacy-sensitive operations on the X Window System. It can restrict **screenshots**, **screencasts**, **XRecord/XTest** (session recording/replaying), and **clipboard access** at the X server level.

This project is a **enhanced version** of the original [X.org-Security-Module](https://github.com/ultract/X.org-Security-Module) by ultract.

## Features

- **Policy-based restrictions** (allow/disallow) for:
  - Screenshot / screen capture (via `XGetImage`, `MIT-SHM`, `CopyArea`, etc.)
  - Screencast / screen sharing
  - XRecord / XTest (recording or faking input)
  - Clipboard access (`CLIPBOARD` selection)
- D-Bus integration
- Blocks spyware from capturing other processes' windows + RootWindow, but allows self-capture)

## Files

- **`xsm.c`** — The Xorg loadable extension module (compiled and loaded by the X server)
- **`xsm-agent.c`** — User-space D-Bus agent that shows desktop notifications and handles whitelist additions

## Installation

### Prerequisites

``` bash
sudo apt install build-essential pkg-config -y
sudo apt install xserver-xorg-dev libjson-c-dev libnotify-dev libdbus-1-dev -y
sudo apt install libdbus-glib-1-dev -y
sudo apt install libsystemd-dev -y
sudo apt install gtk+-3.0-dev -y
```

## Build and install

``` bash
./build.sh
./install.sh # then reboot :)
```

### Configuration Files

**Default policy** (`/etc/xsm/default.rules`, modify one or more of them to `disallow` at your preference):

```ini
screenshot: disallow
screencast: disallow
xrecord: allow
clipboard: allow
```

**Whitelists** (under `/etc/xsm/`) — one entry per line (full path or basename):

``` bash
/usr/bin/spectacle
/usr/bin/kmag
(...)
```

### Running

- Run the agent at login (add to autostart):

```bash
xsm-agent &
```

## How It Works

This module uses the **X Access Control Extension (XACE)** hooks provided by the Xorg server to intercept sensitive requests such as `X11:GetImage`, `MIT-SHM:GetImage`, `CopyArea`, `RECORD:*`, `XTEST:*`, and clipboard selections.

It distinguishes between:
- **Own windows** (allowed)
- **Other processes' windows** and **RootWindow** (restricted when policy says disallow)

Notifications are sent over the system D-Bus. The agent shows a desktop notification with **Allow** (adds to whitelist via pkexec) and **Deny** buttons.

## Security Notes

- The module runs with X server privileges.
- Whitelist changes require user authentication via PolicyKit.
- This is **not** a replacement for proper sandboxing (Flatpak, Firejail, etc.), but a useful additional layer on X11.
- On Wayland this module has no effect (Wayland has its own security model).

## Based on

This project is based on the original **X.org Security Module** by ultract:
https://github.com/ultract/X.org-Security-Module

It builds upon the X Access Control Extension (XACE) framework from the X.Org project.

**Warning**: Modifying X server extensions can cause instability. Test in a safe environment first.
