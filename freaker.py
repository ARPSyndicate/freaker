import yaml
import sys
import os

from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit import PromptSession
from prompt_toolkit.styles import Style
from prompt_toolkit.history import FileHistory
from shutil import which
from urllib.parse import urlparse

BLUE='\033[94m'
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
CLEAR='\x1b[0m'
CONFIG='configs.yaml'

style = Style.from_dict({
    '':          '#2753A5',
})
session = PromptSession(history=FileHistory('.freaker_history'))

print(BLUE + "Freaker[1.0] by ARPSyndicate" + CLEAR)
print(YELLOW + "automated vulnerability testing & exploitation framework for kenzer" + CLEAR)

try:
    with open(CONFIG) as configs:
        config = yaml.load(configs, Loader=yaml.FullLoader)
        freakerdb = config['freakerdb']
        kenzerdb = config['kenzerdb']+"directory/"
        workspace = config['kenzerdb']+"exploitation/"
        if(os.path.exists(workspace) == False):
            os.system("mkdir "+workspace)
        print(GREEN + "[*] configurations loaded successfully" + CLEAR)
except:
    print(RED + "[!] invalid configurations" + CLEAR)
    sys.exit()

try:
    with open(freakerdb+"freakerdb.yaml") as database:
        db = yaml.load(database, Loader=yaml.FullLoader)
        print(GREEN + "[*] freakerdb loaded successfully" + CLEAR)
except:
    print(RED + "[!] freakerdb could not be loaded" + CLEAR)
    sys.exit()

commands = ['list-exploits', 'list-commands', 'exploit-info', 'run-exploit']
exploits = db.keys()

print(GREEN + "[*] {0} exploits loaded successfully".format(len(exploits)) + CLEAR)

def listcommands():
    print("`{0}` - returns all exploits".format(commands[0]))
    print("`{0}` - returns all commands".format(commands[1]))
    print("`{0}` - returns all information for an exploit".format(commands[2]))
    print("`{0}` - runs an exploit".format(commands[3]))
    return

def listexploits():
    for exploit in exploits:
        print(exploit)
    return

def isinstalled(name):
    return which(name) is not None

def getinputs(detect, output):
    os.system("cat {0}*/*scan.kenz | grep -i '\[{1}\]'| cut -d ' ' -f 2 | sort -u | tee -a {2}".format(kenzerdb, detect, output))

def filterinputs(inputs, output):
    list =[]
    with open(inputs) as f:
	    targets=f.read().splitlines()
    for target in targets:
        list.append("{0}://{1}".format(urlparse(target).scheme, urlparse(target).netloc))
    list.sort()
    with open(output, 'a') as f:
        f.writelines("%s\n" % line for line in list)
    

def exploitinfo():
    while(True):
        autoc = WordCompleter(exploits)
        command = session.prompt("freaker:~$ exploit-info: ",completer=autoc, style=style, complete_while_typing=True).lower()
        if command in exploits:
            print("{1} description: {2} {0}".format(db[command]['info'], YELLOW, CLEAR))
            print("{1} requirements: {2} {0}".format(db[command]['requires'], YELLOW, CLEAR))
            print("{1} detections: {2} {0}".format(db[command]['detections'], YELLOW, CLEAR))
        elif command=="exit":
            return
        else:
            print(RED + "[!] exploit not found" + CLEAR)

def exploitit(command):
    out = workspace+"{0}.freakout".format(command)
    depends = db[command]['requires'].split(" ")
    run = True
    for elf in depends:
        if(isinstalled(elf)==False):
            print(RED + "[!] `{0}` is not installed".format(elf)+CLEAR)
            run = False
    if run:
        emp = workspace+"{0}.freakem".format(command)
        inp = workspace+"{0}.freakin".format(command)
        detections = db[command]['detections'].split(" ")
        for detects in detections:
            getinputs(detects,emp)
        filterinputs(emp, inp)
        with open(inp) as f:
            targets=f.read().splitlines()
        for target in targets:
            os.system("cd {0}{1} && python3 main.py '{2}' {3}".format(freakerdb, db[command]['path'], target, out))

def runexploit():
    while(True):
        autoc = WordCompleter(exploits)
        command = session.prompt("freaker:~$ run-exploit: ",completer=autoc, style=style, complete_while_typing=True).lower()
        if command in exploits:
            exploitit(command)
        elif command=="*":
            for coms in exploits:
                exploitit(coms)
        elif command=="exit":
            return
        else:
            print(RED + "[!] exploit not found" + CLEAR)

try:
    while(True):
        autoc = WordCompleter(commands)
        command = session.prompt("freaker:~$ ",completer=autoc, style=style, complete_while_typing=True).lower()
        if command == commands[0]:
            listexploits()
        elif command == commands[1]:
            listcommands()
        elif command == commands[2]:
            exploitinfo()
        elif command == commands[3]:
            runexploit()
        elif command == "exit":
            exit()
        else:
            print(RED + "[!] invalid command"+ CLEAR)

except KeyboardInterrupt:
    print(RED + "[!] interrupted"+ CLEAR)

except:
    print(RED + "[!] an exception occurred"+ CLEAR)