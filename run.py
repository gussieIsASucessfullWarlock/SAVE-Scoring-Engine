from rich import print
import json
import datetime
import subprocess
import re
import notify2
import sys
import os
import hashlib
import base64
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask, send_file
import threading
import time

program_dir = os.path.dirname(os.path.abspath(__file__))

class Check:
    def __init__(self, name=None, value=None, user=None, group=None, cmd=None, path=None):
        self.name = name
        self.value = value
        self.user = user
        self.group = group
        self.cmd = cmd
        self.path = path

    def require_args(self, args):
        for arg in args:
            if not getattr(self, arg):
                raise ValueError(f"Missing {arg} for cond")

    def DirContains(self):
        if not os.path.exists(self.path):
            return False, None
        output = subprocess.run(["grep", "-r", self.value, self.path], capture_output=True)
        return output.returncode == 0, output.stderr

    def PathExists(self):
        return os.path.exists(self.path), None

    def FileContains(self):
        if not os.path.isfile(self.path):
            return False, None
        with open(self.path) as f:
            content = f.read()
        return re.search(self.value, content) is not None, None

    def ShellCommand(self, cmd):
        output = subprocess.run(cmd, capture_output=True, shell=True)
        return output.returncode == 0, output.stderr

    def AutoCheckUpdatesEnabled(self):
        self.require_args(["path"])
        result, err = self._dir_contains()
        if err:
            self.path = "/etc/dnf/automatic.conf"
            auto_conf, err = self._path_exists()
            if err:
                return False, err
            if auto_conf:
                apply_updates, err = self._file_contains()
                if err:
                    return False, err
                self.path = "/etc/systemd/system/timers.target.wants/dnf-automatic.timer"
                auto_timer, err = self._path_exists()
                if err:
                    return False, err
                if apply_updates and auto_timer:
                    return True, None
                self.path = "/etc/systemd/system/timers.target.wants/dnf-automatic-install.timer"
                auto_install_timer, err = self._path_exists()
                if err:
                    return False, err
                return auto_install_timer, err
        return result, err

    def Command(self, cmd):
        self.require_args(["cmd"])
        return self._shell_command(cmd)

    def FirewallUp(self):
        self.path = "/etc/ufw/ufw.conf"
        self.value = "^\s*ENABLED=yes\s*$"
        result, err = self._file_contains()
        if err:
            return self._shell_command("systemctl status firewalld")
        return result, err

    def GuestDisabledLdm(self):
        self.path = "/usr/share/lightdm/lightdm.conf.d/"
        self.value = "\s*allow-guest\s*=\s*false"
        result, err = self._dir_contains()
    
    def KernelVersion(self):
        self.require_args(["Value"])
        utsname = syscall.Utsname()
        err = syscall.uname(utsname)
        releaseUint = []
        for i in range(65):
            if utsname.release[i] == 0:
                break
            releaseUint.append(uint8(utsname.release[i]))
        print(f"System uname value is {releaseUint} and our value is {self.value}")
        return releaseUint == self.value, err

    def PasswordChanged(self):
        self.require_args(["user", "value"])
        try:
            with open("/etc/shadow") as f:
                fileContent = f.read()
        except IOError as e:
            return False, e
        for line in fileContent.split("\n"):
            if self.user+":" in line:
                if self.user+":"+self.value in line:
                    print(f"Exact value found in /etc/shadow for user {c.User}: {line}")
                    return False, None
                print(f"Differing value found in /etc/shadow for user {c.User}: {line}")
                return True, None
        return False, errors.New("user not found")
    
    def FileOwner(self):
        self.require_args(["path", "name"])
        try:
            u = user.lookup(self.name)
        except KeyError as e:
            return False, e

        try:
            f = os.stat(self.path)
        except OSError as e:
            return False, e

        uid = f.st_uid
        o = int(u.pw_uid)
        print(f"File owner for {self.path} uid is {uid}")
        return o == uid, None
    
    def PermissionIs(self):
        self.require_args(["path", "value"])
        try:
            f = os.stat(self.path)
        except OSError as err:
            return False, err
    
        fileMode = f.st_mode
        modeBytes = str(oct(fileMode))[2:]
        if len(modeBytes) != 10:
            return False, "Invalid system permission string"
    
        if fileMode & stat.S_ISUID != 0:
            modeBytes = modeBytes[:2] + 's' + modeBytes[3:]
        if fileMode & stat.S_ISGID != 0:
            modeBytes = modeBytes[:5] + 's' + modeBytes[6:]
    
        self.value = self.value.strip()
    
        if len(self.value) == 9:
            # If we're provided a mode string of only 9 characters, we'll assume
            # that the 0th bit is irrelevant and should be a wildcard
            self.value = "?" + self.value
        elif len(self.value) != 10:
            fail("Your permission string is the wrong length (should be 9 or 10 characters):", self.value)
            return False, errors.New("Invalid user permission string")
    
        for i in range(len(self.value)):
            if self.value[i] == '?':
                continue
            if self.value[i] != modeBytes[i]:
                return False, None
    
        return True, None

    def CommandOutput(self):
        result = subprocess.run(self.cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode().strip() == self.value, result.stderr
    
    def FileContains(self):
        with open(self.path) as f:
            contents = f.read()
        return re.search(self.value, contents) is not None, None
    
    def ProgramInstalled(self):
        self.require_args(["name"])
        result, err = self.Command()
        if err:
            self.cmd = "rpm -q " + self.name
            return self.Command()
        return result, err
    
    def ProgramVersion(self):
        self.require_args(["name", "value"])
        self.cmd = f'dpkg -s {self.name} | grep Version | cut -d" " -f2'
        return self.CommandOutput()
    
    def ServiceUp(self):
        self.require_args(["name"])
        self.cmd = "systemctl is-active " + self.name
        return self.Command()
    
    def UserExists(self):
        self.require_args(["user"])
        self.path = "/etc/passwd"
        self.value = "^" + self.user + ":"
        return self.FileContains()
    
    def UserInGroup(self):
        self.require_args(["user", "group"])
        self.path = "/etc/group"
        self.value = self.group + '[0-9a-zA-Z,:\s+]+' + self.user
        return self.FileContains()

currentPoints = 0

def createDesktopShortcut(name, exec, icon, desktop):
    file = "[Desktop Entry]\nName=" + name + "\nExec=" + exec + "\nIcon=" + icon + "\nType=Application"
    sefile = str(desktop) + str(name) + ".desktop"
    fs = open(str(sefile), "w")
    fs.write(file)
    fs.close()

def createService(user):
    with open("/etc/systemd/system/scoring.service", "w") as f:
        contents = "[Unit]\nDescription=Scoring Report\n\n[Service]\nExecStart=/bin/python3 " + program_dir + "/run.py startScoring\nRestart=always\nUser=" + user +"\n\n[Install]\nWantedBy=multi-user.target"
        f.write(contents)
        f.close()
    os.system("sudo systemctl enable scoring.service")
    os.system("sudo systemctl start scoring.service")

def createScoringReport(image, points, recieved, penalties, foundVulns, totalNumVulns):
    numPoints = 0
    for i in foundVulns:
        numPoints = i["points"]
    now = datetime.datetime.now()
    time = now.strftime("%a %b %d %I:%M %p")
    stringBuilder = '<!DOCTYPE html>\n  <html lang="en" data-theme="lofi">\n  <head>\n      <meta charset="UTF-8">\n      <meta http-equiv="X-UA-Compatible" content="IE=edge">\n      <meta name="viewport" content="width=device-width, initial-scale=1.0">\n      <title>Scoring</title>\n      <link href="https://cdn.jsdelivr.net/npm/daisyui@2.49.0/dist/full.css" rel="stylesheet" type="text/css" />\n      <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2/dist/tailwind.min.css" rel="stylesheet" type="text/css" />\n      <style>\n          h1 {\n              color: rgb(49, 49, 49);\n          }\n          h2 {\n              color: rgb(95, 95, 95);\n          }\n          p {\n              color: rgb(120, 120, 120);\n          }\n          tr th {\n              color: rgb(95, 95, 95);\n          }\n          th {\n              color: rgb(120, 120, 120);\n          }\n          td {\n              color: rgb(120, 120, 120);\n          }\n          .divider {\n              color: rgb(120, 120, 120);\n          }\n      </style>\n  </head>\n  <body style="overflow-x: hidden;">\n      <div class="hero-content">\n      <div style="min-height: calc(100vh - 102px) !important; max-width: 600px;">\n      <div style="padding-top: 10vh;" class="hero">\n          <div class="hero-content text-center">\n            <div class="max-w-md">\n              <div class="avatar">\n                  <div class="w-24 rounded">\n                    <img src="' + image + '" />\n                  </div>\n                </div>\n              <h1 style="color: rgb(49, 49, 49)" class="text-5xl font-bold">Scoring Report</h1>\n              <h2 style="color: rgb(95, 95, 95)" class="py-3 text-2xl">' + str(recieved) + ' out of ' + str(points) + ' points recieved</h2>\n              <p style="color: rgb(120, 120, 120)">Report Generated At: ' + time + '</p>\n            </div>\n          </div>\n        </div>\n  '

    if len(penalties) > 0:
        loss = 0
        for i in penalties:
            loss += i['points']
        stringBuilder += '\n        <div>'
        stringBuilder += '\n          <h2>' + str(len(penalties)) + ' penalties assessed, for a loss of ' + str(loss) + ' points:</h2>'
    for i in penalties:
        stringBuilder += '\n          <p style="color: red; font-weight: 500;;">' + i['message'] +' - ' + str(i['points']) + ' pts</p>'
    if len(penalties) > 0:
        stringBuilder += '\n        </div>\n        <div class="divider"></div>'

    stringBuilder += "\n      <div>"
    stringBuilder += '\n        <h2>' + str(len(foundVulns)) + ' out of ' + str(totalNumVulns) + ' scored security issues fixed, for a gain of ' + str(numPoints) + ' points:</h2>'
    for i in foundVulns:
        stringBuilder += '\n        <p style="color: green; font-weight: 500;;">' + i['message'] + ' - ' + str(i['points']) + ' pts</p>'
    stringBuilder += '\n      </div>\n      </div>\n      </div>\n        <footer style="margin-top: 50px; width: 100vw; overflow-x: hidden;" class="footer footer-center p-4 bg-base-300 text-base-content">\n          <div>\n            <p>Copyright © 2023 - All right reserved SAVE.</p>\n          </div>\n        </footer>\n  </body>\n  </html>'
    
    with open("Pages/scoring.html", "w") as save:
        save.write(stringBuilder)

def createReadMe(data):
    stringBuilder = '\n      <!DOCTYPE html>\n    <html lang="en" data-theme="lofi">\n    <head>\n        <meta charset="UTF-8">\n        <meta http-equiv="X-UA-Compatible" content="IE=edge">\n        <meta name="viewport" content="width=device-width, initial-scale=1.0">\n        <title>Scoring</title>\n        <link href="https://cdn.jsdelivr.net/npm/daisyui@2.49.0/dist/full.css" rel="stylesheet" type="text/css" />\n        <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2/dist/tailwind.min.css" rel="stylesheet" type="text/css" />\n        <style>\n            h1 {\n                color: rgb(49, 49, 49);\n            }\n            h2 {\n                color: rgb(95, 95, 95);\n            }\n            p {\n                color: rgb(120, 120, 120);\n            }\n            tr th {\n                color: rgb(95, 95, 95);\n            }\n            th {\n                color: rgb(120, 120, 120);\n            }\n            td {\n                color: rgb(120, 120, 120);\n            }\n            .divider {\n                color: rgb(120, 120, 120);\n            }\n            pre {\n              color: rgb(120, 120, 120)\n            }\n            li {\n              color: rgb(120, 120, 120);\n              list-style-type: square;\n              margin-left: 15px;\n            }\n            ul {\n              color: rgb(120, 120, 120)\n            }\n        </style>\n    </head>\n    <body style="overflow-x: hidden;">\n      <div class="hero-content">\n        <div style="min-height: calc(100vh - 102px) !important; max-width: 600px;">\n        <div style="padding-top: 10vh;" class="hero">\n            <div class="hero-content text-center">\n              <div class="max-w-md">\n                <div class="avatar">\n                    <div class="w-24 rounded">\n                      <img src="https://static1.squarespace.com/static/5e6f85fc49db9d4fa479a1c9/t/63d57453e6b7475d6379528d/1674933331656/logo-5.png" />\n                    </div>\n                  </div>\n                <h1 style="color: rgb(49, 49, 49)" class="text-5xl font-bold">Read Me</h1>\n                <p style="color: rgb(120, 120, 120)">Ubuntu 22.04 - House Practice Image</p>\n              </div>\n            </div>\n          </div>'
    stringBuilder += '<div>\n            <h2 class="text-xl" style="padding-top: 10px; padding-bottom: 5px; font-weight: 500; color: rgb(0, 0, 0);">Unique Identifier</h2>\n            <p>If you have not yet entered a valid Team ID, please do so immediately by double clicking on the "Aeacus Set Team ID" icon on the desktop. If you do not enter a valid Team ID this VM may stop functioning after a\n              short period of time.</p>\n          </div>\n  \n          <div>\n            <h2 class="text-xl" style="padding-top: 10px; padding-bottom: 5px; font-weight: 500; color: rgb(0, 0, 0);">Forensics Questions</h2>\n            <p>If there are "Forensics Questions" on your Desktop, you will receive points for answering these questions correctly. Valid (scored) "Forensics Questions" will only be located directly on your Desktop. Please read all "Forensics Questions" thoroughly before modifying this computer, as you may change something that\n              prevents you from answering the question correctly.</p>\n          </div>'
    for i in data:
        if i["type"] == "list":
            stringBuilder += '<div>\n            <h2 class="text-xl" style="padding-top: 10px; padding-bottom: 5px; font-weight: 500; color: rgb(0, 0, 0);">' + i["Title"] + '</h2>\n            <p><ul>\n              '
            for i in i["listData"]:
                stringBuilder += '<li>' + i + '</li>\n            '
            stringBuilder += '</ul></p>\n          </div>'
        elif i["type"] == "pre":
            save = ""
            for d in i["data"]:
                save += d + "\n"
            stringBuilder += '\n              <div>\n            <h2 class="text-xl" style="padding-top: 10px; padding-bottom: 5px; font-weight: 500; color: rgb(0, 0, 0);">' + i["Title"] + '</h2>\n            <p><pre>' + save + '\n          </pre></p>\n        </div>'
        elif i["type"] == "paragraph":
            stringBuilder += '<div>\n          <h2 class="text-xl" style="padding-top: 10px; padding-bottom: 5px; font-weight: 500; color: rgb(0, 0, 0);">' + i["Title"] + '</h2>\n          <p>' + i['message'] + '</p>\n        </div>'
    stringBuilder += '\n            </div>\n      </div>\n          <footer style="margin-top: 50px; width: 100vw; overflow-x: hidden;" class="footer footer-center p-4 bg-base-300 text-base-content">\n            <div>\n              <p>Copyright © 2023 - All right reserved SAVE.</p>\n            </div>\n          </footer>\n    </body>\n    </html>'
    with open("Pages/readme.html", "w") as save:
       save.write(stringBuilder)

def sendNotification(title, message):
    try:
        notify2.init("SAVE")
        notice = notify2.Notification(title, message)
        notice.icon = program_dir + "/image/icon.png"
        notice.show()
    except:
        print("NotoficationNotSent")
    return

def enodeData(key, file):
    cipher = Fernet(key)
    with open(file, "rb") as f:
        data = f.read()
        encrypted_data = cipher.encrypt(data)
    with open(file, "wb") as f:
        f.write(encrypted_data)

def decryptData(key, file):
    cipher = Fernet(key)
    with open(file, "rb") as f:
        encrypted_data = f.read()
        decrypted_data = cipher.decrypt(encrypted_data)
        return decrypted_data

def getConfs():
    encPasswd = open(".password", "r").read()
    key = base64.b64decode(encPasswd.encode())
    return decryptData(key, "data.json")

def addToList(v, data, dataList, i):
    if "Pass" == v["type"]:
        dataList += [
            {
                "message": i["message"],
                "points": i["points"]
            }
        ]
    elif "Pass Override" == v["type"]:
        dataList += [
            {
                "message": i["message"],
                "points": i["points"],
                "overriden": True
            }
        ]
    elif "Fail" == v["type"]:
        newDatalist = []
        for i in dataList:
            if { "message": i["message"], "points": i["points"] } != i:
                newDatalist += i

def updateReport(data):
    global currentPoints
    data["checks"]
    totalNumVulns = 0
    gainedPoints = 0
    maxpts = 0
    dataList = []
    for i in data["checks"]:
        maxpts += i["points"]
        totalNumVulns += 1
        for v in i["verification"]:
            if v["function"] == "DirContains":
                value = v["value"]
                path = v["path"]
                if v["equateTo"] == Check(value=value, path=path).DirContains()[0]:
                    addToList(v, data, dataList, i)
            if v["function"] == "PathExists":
                path = v["path"]
                if v["equateTo"] == Check(path=path).PathExists()[0]:
                    addToList(v, data, dataList, i)
            if v["function"] == "FileContains":
                value = v["value"]
                path = v["path"]
                if v["equateTo"] == Check(value=value, path=path).FileContains()[0]:
                    addToList(v, data, dataList, i)
            if v["function"] == "ShellCommand":
                cmd = v["cmd"]
                if v["equateTo"] == Check(cmd=cmd).ShellCommand()[0]:
                    addToList(v, data, dataList, i)
            if v["function"] == "AutoCheckUpdatesEnabled":
                path = v["path"]
                if v["equateTo"] == Check(path=path).AutoCheckUpdatesEnabled()[0]:
                    addToList(v, data, dataList, i)
            if v["function"] == "Command":
                cmd = v["cmd"]
                if v["equateTo"] == Check(cmd=cmd).Command()[0]:
                    addToList(v, data, dataList, i)
            if v["function"] == "FirewallUp":
                if v["equateTo"] == Check().FirewallUp()[0]:
                    addToList(v, data, dataList, i)
            if v["function"] == "GuestDisabledLdm":
                if v["equateTo"] == Check().GuestDisabledLdm()[0]:
                    addToList(v, data, dataList, i)
            if v["function"] == "KernelVersion":
                value = v["value"]
                if v["equateTo"] == Check(value=value).KernelVersion()[0]:
                    addToList(v, data, dataList, i)
            if v["function"] == "PasswordChanged":
                user = v["user"]
                value = v["value"]
                if v["equateTo"] == Check(value=value, user=user).PasswordChanged()[0]:
                    addToList(v, data, dataList, i)
            if v["function"] == "FileOwner":
                path = v["path"]
                name = v["name"]
                if v["equateTo"] == Check(name=name, path=path).FileOwner()[0]:
                    addToList(v, data, dataList, i)
            if v["function"] == "PermissionIs":
                path = v["path"]
                value = v["value"]
                if v["equateTo"] == Check(value=value, path=path).PermissionIs()[0]:
                    addToList(v, data, dataList, i)
            if v["function"] == "CommandOutput":
                cmd = v["cmd"]
                if v["equateTo"] == Check(cmd=cmd).CommandOutput()[0]:
                    addToList(v, data, dataList, i)
            if v["function"] == "FileContains":
                path = v["path"]
                value = v["value"]
                if v["equateTo"] == Check(value=value, path=path).FileContains()[0]:
                    addToList(v, data, dataList, i)
            if v["function"] == "ProgramInstalled":
                name = v["name"]
                if v["equateTo"] == Check(name=name).ProgramInstalled()[0]:
                    addToList(v, data, dataList, i)
            if v["function"] == "ProgramVersion":
                name = v["name"]
                if v["equateTo"] == Check(name=name).ProgramVersion()[0]:
                    addToList(v, data, dataList, i)
            if v["function"] == "ServiceUp":
                name = v["name"]
                if v["equateTo"] == Check(name=name).ServiceUp()[0]:
                    addToList(v, data, dataList, i)
            if v["function"] == "UserExists":
                user = v["user"]
                if v["equateTo"] == Check(user=user).UserExists()[0]:
                    addToList(v, data, dataList, i)
            if v["function"] == "UserInGroup":
                user = v["user"]
                group = v["group"]
                if v["equateTo"] == Check(user=user, group=group).UserInGroup()[0]:
                    addToList(v, data, dataList, i)

    penalties = [
    ]
    foundVulns = [
    ]
    
    for i in dataList:
        gainedPoints += i['points']
        if i['points'] < 0:
            penalties += [i]
        else:
            foundVulns += [i]
    image = "https://static1.squarespace.com/static/5e6f85fc49db9d4fa479a1c9/t/63d56108a2fc8f768def9f9c/1674928392301/logo-4.png"
    createScoringReport(image, gainedPoints, maxpts, penalties, foundVulns, totalNumVulns)
    if currentPoints < gainedPoints:
        sendNotification("SAVE", "You Gained Points!")
        currentPoints = gainedPoints

def runScoringEngine():
    while True:
        data = json.loads(getConfs())
        updateReport(data)

if sys.argv[-1] == "build":

    inputFile = open("data.json", "r")
    inputFile = json.load(inputFile)
    maxpts = 0
    totalNumVulns = 26
    for i in inputFile["checks"]:
        maxpts += i["points"]
        totalNumVulns += 1
    image = "https://static1.squarespace.com/static/5e6f85fc49db9d4fa479a1c9/t/63d56108a2fc8f768def9f9c/1674928392301/logo-4.png"
    createScoringReport(image, 0, maxpts, [], [], totalNumVulns)
    print("Creating Scoring Report")
    createReadMe(inputFile["readme"])
    print("Creating ReadMe")
    createDesktopShortcut("Scoring Report", "python3 " + program_dir + "/run.py openScoring", program_dir + "/image/icon.png", str(inputFile["desktop"]))
    createDesktopShortcut("Read Me", "python3 " + program_dir + "/run.py openReadme", program_dir + "/image/icon.png", str(inputFile["desktop"]))
    print("Creating Shortcuts")

    createService(inputFile["superUser"])
    print("startedService")

    key = Fernet.generate_key()
    key_base64 = base64.b64encode(key)
    os.system("echo \"" + key_base64.decode("UTF-8")  + "\" > .password")
    enodeData(key, "data.json")

    print("Encrypted Input File")
    
    for i in inputFile["execConf"]:
        os.system(i)
    print("Run Image Configuration Commands")
elif sys.argv[-1] == "systemCheck":
    d = getConfs()
    data = json.loads(d)
    updateReport(data)
elif sys.argv[-1] == "openScoring":
    os.system("firefox \"localhost:8080/scoring\"")
elif sys.argv[-1] == "openReadme":
    os.system("firefox \"localhost:8080/readme\"")
elif sys.argv[-1] == "startScoring":
    app = Flask(__name__)
    @app.route("/scoring")
    def scoreex():
        return send_file(program_dir + "/Pages/scoring.html")
    @app.route("/readme")
    def readmeex():
        return send_file(program_dir + "/Pages/readme.html")
    t = threading.Thread(target=runScoringEngine)
    t.start()
    app.run(debug=False, host='0.0.0.0', port=8080)
elif sys.argv[-1] == "checkConfig":
    f = open("data.json", "r")
    conf = json.load(f)
    if conf["SAVEVersion"] == "1":
        print("[blue bold]ID:[/blue bold] [green]" + conf["id"] + "[/green]")
        print("[blue bold]Name:[/blue bold] [green]" + conf["name"] + "[/green]")
        print("[blue bold]EncryptionPassword:[/blue bold] [green]" + conf["encryptionPassword"] + "[/green]")
        print("[blue bold]Operating System:[/blue bold] [green]" + conf["os"] + "[/green]")
        print("[blue bold]Super User:[/blue bold] [green]" + conf["superUser"] + "[/green]")
        print("[blue bold]Version:[/blue bold] [green]" + conf["SAVEVersion"] + "[/green]")
        print("")
        print("Checks:")
        for i in conf["checks"]:
            if i["points"] < 0:
                print("                 [blue bold]Type:[/blue bold] [green]" + "Penalty" + "[/green]")
            else:
                print("                 [blue bold]Type:[/blue bold] [green]" + "Score" + "[/green]")
            print("                 [blue bold]Run:[/blue bold] [green]" + str(i["cmdEffector"]) + "[/green]")
            print("                 [blue bold]Message:[/blue bold] [green]" + i["message"] + "[/green]")
            print("                 [blue bold]Points:[/blue bold] [green]" + str(i["points"]) + "[/green]")
            for i in i["verification"]:
                print("")
                print("                                  [blue bold]Type:[/blue bold] [green]" + str(i["type"]) + "[/green]")
                print("                                  [blue bold]Function:[/blue bold] [green]" + str(i["function"]) + "[/green]")
                if i["function"] == "PermissionIs":
                    print("                                  [blue bold]Path:[/blue bold] [green]" + str(i["path"]) + "[/green]")
                    print("                                  [blue bold]Value:[/blue bold] [green]" + str(i["value"]) + "[/green]")
                print("                                  [blue bold]Must Be:[/blue bold] [green]" + str(i["equateTo"]) + "[/green]")
                if i["function"] == "UserInGroup":
                    print("                                  [blue bold]User:[/blue bold] [green]" + str(i["user"]) + "[/green]")
                    print("                                  [blue bold]Group:[/blue bold] [green]" + str(i["group"]) + "[/green]")
                print("                                  [blue bold]Must Be:[/blue bold] [green]" + str(i["equateTo"]) + "[/green]")
                if i["function"] == "UserExists":
                    print("                                  [blue bold]User:[/blue bold] [green]" + str(i["user"]) + "[/green]")
                print("                                  [blue bold]Must Be:[/blue bold] [green]" + str(i["equateTo"]) + "[/green]")

        print("")
        print("Read Me:")
        for i in conf["readme"]:
            print("")
            if i["type"] == "paragraph":
                print("[blue bold]Type:[/blue bold] [green]" + str(i["type"]) + "[/green]")
                print("                 [blue bold]Title:[/blue bold] [green]" + str(i["Title"]) + "[/green]")
                print("                 [blue bold]Message:[/blue bold] [green]" + str(i["message"]) + "[/green]")
            elif i["type"] == "list":
                print("[blue bold]Type:[/blue bold] [green]" + str(i["type"]) + "[/green]")
                print("                 [blue bold]Title:[/blue bold] [green]" + str(i["Title"]) + "[/green]")
                print("                 [blue bold]Data:[/blue bold]")
                for d in i["listData"]:
                    print("                                  [green]" + str(d) + "[/green]")
            elif i["type"] == "pre":
                print("[blue bold]Type:[/blue bold] [green]" + str(i["type"]) + "[/green]")
                print("                 [blue bold]Title:[/blue bold] [green]" + str(i["Title"]) + "[/green]")
                print("                 [blue bold]Data:[/blue bold]")
                for d in i["data"]:
                    print("                                 [green]" + str(d) + "[/green]")
        for i in conf["execConf"]:
                print("[blue bold]Commands to configure image:[/blue bold]")
                print("                 [green]" + str(i) + "[/green]")
elif "help" in sys.argv:
    print("[bold green]build[/bold green] [bold blue]- Encrypts data.json and makes system ready. [/bold blue]")
    print("[bold green]systemCheck[/bold green] [bold blue]- Builds scoring report manully. [/bold blue]")
    print("[bold green]openScoring[/bold green] [bold blue]- Opens the scoring report. (build must have been run & scoring.service must be running) [/bold blue]")
    print("[bold green]openReadme[/bold green] [bold blue]- Opens the read me. (build must have been run & scoring.service must be running) [/bold blue]")
    print("[bold green]startScoring[/bold green] [bold blue]- scoring.service file utilizes it to start scroing. [/bold blue]")
    print("[bold green]checkConfig[/bold green] [bold blue]- Shows a deatiled print out of the programs interpratation of your input file. [/bold blue]")
