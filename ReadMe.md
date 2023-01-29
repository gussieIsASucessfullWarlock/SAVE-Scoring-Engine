# SAVE

<img align="right" width="200" src="https://github.com/gussieIsASucessfullWarlock/SAVE-Scoring-Engine/blob/main/image/icon.png?raw=true" alt="SAVE logo"/>

`SAVE` is the most simple vulnerability scoring engine for Ubuntu.

## Installation

0. **Pull the release** into `/home/user/.SAVE/`

1. **Set up the environment.**

	- Put your **config** in `/home/user/.SAVE/data.json`

		- _Don't have a config? See the example below._

	- Put your **README data** in `ReadMe.conf`.

2. **Install Python Dependencies.**

```
pip install rich && pip install json && pip install notify2 && pip install flask && pip install pycryptodome
```

If that didn't work try installing these dependencies:

- rich
- json
- datetime
- subprocess
- re
- notify2
- sys
- os
- hashlib
- base64
- cryptography
- flask
- threading
- time

3. **Check that your config is valid.**

```
python3 run.py checkConfig
```

> Check out what you can do with `SAVE` with `python3 run.py help`
4. **Prepare the image for release.**

> **WARNING**: This will encrypt `data.json`. Back it up somewhere if you want to save it!
```
python3 run.py build
```

## Screenshots

### Scoring Report:
[<img width="735" alt="Screenshot 2023-01-28 at 8 57 30 PM" src="https://user-images.githubusercontent.com/82612866/215302076-8e00b02f-9e20-4de6-9dac-fd4345f43c44.png">](https://user-images.githubusercontent.com/82612866/215302076-8e00b02f-9e20-4de6-9dac-fd4345f43c44.png)
### Read Me:
[<img width="735" alt="Screenshot 2023-01-28 at 8 56 58 PM 1" src="https://user-images.githubusercontent.com/82612866/215302079-dc2d184f-2e9b-4bb9-877a-090ad4f18908.png">](https://user-images.githubusercontent.com/82612866/215302079-dc2d184f-2e9b-4bb9-877a-090ad4f18908.png)

## Features

-   Robust & Simple
-   Image Building (Start Service, README, etc)
-   20 + Vuln Functions

## Documentation

All checks (with examples and notes) [are documented here](cmd.txt).

## Configuration

The configuration is written in JSON. Here is a minimal example:

```
{
    "id": "0x7868666",
    "name": "House IMG",
    "os": "Ubuntu 22.04",
    "superUser": "house",
    "desktop": "/home/student/Desktop/",
    "SAVEVersion": "1",
    "checks": [
        {
            "message": "Malicious user 'user' can't read /etc/shadow",
            "points": 20,
            "verification": [
                {
                    "type": "Pass",
                    "function": "PermissionIs",
                    "path": "/etc/shadow",
                    "value": "??????r??",
                    "equateTo": false
                },
                {
                    "type": "Pass Override",
                    "function": "UserExists",
                    "user": "user",
                    "equateTo": true
                },
                {
                    "type": "Fail",
                    "function": "PathExists",
                    "path": "/etc/shadow",
                    "equateTo": false
                }
            ],
            "cmdEffector": "chmod 777 /etc/shadow"
        }
    ],
    "readme": [
        {
            "type": "list",
            "Title": "Critical Services",
            "listData": [
                "OpenSSH Server (sshd)",
                "VSFTPD"
            ]
        },
        {
            "type": "paragraph",
            "Title": "Competition Senero",
            "message": "Congratulations! You just recruited a promising new team member. Create a new Standard user account named \"bobbington\" with a temporary password of your choosing."
        },
        {
            "type": "pre",
            "Title": "Authorized Administrators:",
            "data": [
                "coolUser (you)",
                "\tpassword: coolPassword",
                "bob",
                "\tpassword: bob"
            ]
        },
        {
            "type": "list",
            "Title": "Authorized Administrators:",
            "listData": [
                "coolFriend",
                "awesomeUser",
                "radUser",
                "coolGuy",
                "niceUser"
            ]
        }
],
    "execConf": [
        "ping localhost"
    ]
}
```
