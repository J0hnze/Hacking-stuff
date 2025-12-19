## Keep-Awake.ps1`

### Overview

This script keeps a laptop **awake** during long Nessus scans, installs, or data transfers by simulating a tiny bit of keyboard activity.

It works by briefly toggling **NumLock on and off every N seconds**, so Windows sees input and doesn’t go to sleep, while NumLock ends up in the same state it started in.