# arpspoof-detect
Detects change in Linux ARP tables for common ARP Spoofing/Poisoning techniques.
Currently Linux only.

## ARP Spoofing
ARP Spoofing is a common and dangerous attack in which a malicious user on a network sends falsified ARP messages in order to convince a victim computer to send all traffic to them, as opposed to the actual router. This is effectively a Man In the Middle attack that allows malicious actors to view, and tamper with, all internet traffic coming from a device. This script aims to allow users to detect when their ARP tables are being tampered with so that they may take necessary precautions to prevent any of their personal data from being intercepted.

## Usage

To use the script, simply run

`perl arpspoof-detect.pl`

This will activate the script and watch for any changes in your router's MAC address, which is normally the result of ARP Spoofing attacks.

If you know what your router's MAC address is supposed to be, you can specify it to the script directly.

`perl arpspoof-detect.pl -m <MAC Address>`


### TODO
 - Add other notification options (email, libnotify?)
 - Add option to run script upon ARP spoof detection
 - ??
