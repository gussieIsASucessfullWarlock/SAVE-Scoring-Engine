# Checks

This is a list of vulnerability checks that can be used in the configuration for `SAVE`.

> **Note**: Each of the commands here can check for the opposite by changing 'equateTo' to `false`.

> **Note**: If a check has negative points assigned to it, it's a penalty.

> **Note**: The checks can have `Pass`, `PassOverride` or `Fail` type.

**CommandContains**: pass if command output contains string. If executing the command fails (the check returns an error), check never passes. Use of this check is discouraged.

```
 {
            "message": "UFW Enabled",
            "points": 20,
            "verification": [
                {
                    "type": "Pass",
                    "function": "CommandOutput",
                    "cmd": "ufw status",
                    "value": "Status: active",
                    "equateTo": true
                }
            ]
}
```

**DirContains**: pass if directory contains regular expression (regex) string

```
 {
            "message": "Sudoers Secure",
            "points": 20,
            "verification": [
                {
                    "type": "Pass",
                    "function": "DirContains",
                    "path": "/etc/sudoers.d/",
                    "value": "NOPASSWD",
                    "equateTo": false
                }
            ]
}
```

> `DirContains` is recursive! This means it checks every folder and subfolder. It currently is capped at 10,000 files, so you should begin your search at the deepest folder possible.

**FileContains**: pass if file contains regex

> **Note**: `FileContains` will never pass if file does not exist! Add an additional PassOverride check for PathExistsNot, if you want to score that a file does not contain a line, OR it doesn't exist.
```
 {
            "message": "Forensics Question 1 Correct!",
            "points": 20,
            "verification": [
                {
                    "type": "Pass",
                    "function": "FileContains",
                    "path": "/home/user/Desktop/Forensic\ Question\ 1.txt",
                    "value": "ANSWER: This is the Answer!",
                    "equateTo": true
                }
            ]
}
```

**FileEquals**: pass if file equals sha256 hash

```
{
            "message": "Correct!",
            "points": 20,
            "verification": [
                {
                    "type": "Pass",
                    "function": "FileEquals",
                    "path": "/etc/sysctl.conf",
                    "value": "i61uu3om83p51ft922rk03rr0408q2n15s4t8t69q8488q4ts1dep854pr45mk9p",
                    "equateTo": true
                }
            ]
}
```

**FileOwner**: pass if specified user owns a given file

```
{
            "message": "Correct!",
            "points": 20,
            "verification": [
                {
                    "type": "Pass",
                    "function": "FileOwner",
                    "path": "/etc/passwd",
                    "name": "root",
                    "equateTo": true
                }
            ]
}
```

> Get owner of the file in Linux, use `ls -la FILENAME`.

**FirewallUp**: pass if firewall is active

```
{
            "message": "Correct!",
            "points": 20,
            "verification": [
                {
                    "type": "Pass",
                    "function": "FirewallUp",
                    "equateTo": true
                }
            ]
}
```

> **Note**: Only `ufw` (checks `/etc/ufw/ufw.conf`) is supported. 

For Linux, check if user's password hash is not next to their username in `/etc/shadow`. If you don't use the whole hash, make sure you start it from the beginning (typically `$X$...` where X is a number).

```
{
            "message": "Correct!",
            "points": 20,
            "verification": [
                {
                    "type": "Pass",
                    "function": "PasswordChanged",
                    "user": "bob",
                    "value": "$2$NsNeDxmvviHAaCOK$di5INEtm4zwbkzlrOlo3kKwH1AkPtd.QXaVABbupiLaksGlDRNREdfQ3rkB0UFgnOiZ9Nn9PGcHH3ylFTX8ei/",
                    "equateTo": true
                }
            ]
}
```

**PathExists**: pass if specified path exists. This works for both files AND folders (directories).

```
{
            "message": "Removed important files!",
            "points": -20,
            "verification": [
                {
                    "type": "Pass",
                    "function": "PathExists",
                    "path": "/var/www/backup.zip",
                    "equateTo": false
                }
            ]
}
```

**PermissionIs**: pass if specified user has specified permission on a given file

For Linux, use the standard octal `rwx` format (`ls -la yourfile` will show them). Use question marks to omit bits you don't care about.

```
{
            "message": "Correct!",
            "points": 20,
            "verification": [
                {
                    "type": "Pass",
                    "function": "PermissionIs",
                    "path": "/etc/shadow",
                    "value": "rw-rw----",
                    "equateTo": true
                }
            ]
}
```

> **Note**: Use absolute paths when possible (rather than relative) for more reliable scoring.

**ProgramInstalled**: pass if program is installed. On Linux, will use `dpkg` (or `rpm` for RHEL-based systems), and on Windows, checks if any installed programs contain your program string.

```
{
            "message": "Correct!",
            "points": 20,
            "verification": [
                {
                    "type": "Pass",
                    "function": "ProgramInstalled",
                    "name": "nmap",
                    "equateTo": false
                }
            ]
}
```

**ProgramVersion**: pass if a program meets the version requirements

For Linux, get version from `dpkg -s programnamehere`.

```
{
            "message": "Correct!",
            "points": 20,
            "verification": [
                {
                    "type": "Pass",
                    "function": "ProgramVersion",
                    "name": "Firefox",
                    "value": "88.0.1+build1-0ubuntu0.20.04.2",
                    "equateTo": false
                }
            ]
}
```

> For packages, Linux uses `dpkg`

**ServiceUp**: pass if service is running

For Linux, use the `systemd` service name.
```
{
            "message": "Correct!",
            "points": 20,
            "verification": [
                {
                    "type": "Pass",
                    "function": "ServiceUp",
                    "name": "sshd",
                    "equateTo": true
                }
            ]
}
```

**UserExists**: pass if user exists on system

```
{
            "message": "Correct!",
            "points": 20,
            "verification": [
                {
                    "type": "Pass",
                    "function": "UserExists",
                    "user": "bad",
                    "equateTo": false
                }
            ]
}
```

**UserInGroup**: pass if specified user is in specified group

```
{
            "message": "Correct!",
            "points": 20,
            "verification": [
                {
                    "type": "Pass",
                    "function": "UserExists",
                    "user": "bad",
                    "group": "sudo",
                    "equateTo": false
                }
            ]
}
```

> Linux reads `/etc/group`
<hr>

### Linux-Specific Checks

**AutoCheckUpdatesEnabled**: pass if the system is configured to automatically check for updates (supports `apt` and `dnf-automatic`)

```
{
            "message": "Correct!",
            "points": 20,
            "verification": [
                {
                    "type": "Pass",
                    "function": "AutoCheckUpdatesEnabled",
                    "equateTo": false
                }
            ]
}
```

**Command**: pass if command succeeds (command is executed, and has a return code of zero). Use of this check is discouraged. This check will NOT return an error if the command is not found

```
{
            "message": "Correct!",
            "points": 20,
            "verification": [
                {
                    "type": "Pass",
                    "function": "Command",
                    "cmd": "cat file.txt",
                    "equateTo": true
                }
            ]
}
```

**GuestDisabledLDM**: pass if guest is disabled (for LightDM)

```
{
            "message": "Correct!",
            "points": 20,
            "verification": [
                {
                    "type": "Pass",
                    "function": "GuestDisabledLDM",
                    "equateTo": true
                }
            ]
}
```

**KernelVersion**: pass if kernel version is equal to specified

```
{
            "message": "Correct!",
            "points": 20,
            "verification": [
                {
                    "type": "Pass",
                    "function": "KernelVersion",
                    "value": "5.4.0-42-generic"
                    "equateTo": true
                }
            ]
}
```

> Tip: Check your `KernelVersion` with `uname -r`. This check performs the `uname` syscall.
