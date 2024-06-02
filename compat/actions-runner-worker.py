# This script can be used to call Runner.Worker as github-act-runner worker on unix like systems
# You just have to create simple .runner file in the root folder with the following Content
# {"workFolder": "_work"}
# Then use `python3 path/to/this/script.py path/to/actions/runner/bin/Runner.Worker` as the worker args

import sys
import subprocess
import os
import threading
import codecs

wdr, wdw = os.pipe()
rdr, rdw = os.pipe()

def redirectio():
    while(True):
        stdin = sys.stdin.fileno()
        messageType = int.from_bytes(os.read(stdin, 4), "big", signed=False)
        os.write(rdw, messageType.to_bytes(4, sys.byteorder, signed=False))
        messageLength = int.from_bytes(os.read(stdin, 4), "big", signed=False)
        message = os.read(stdin, messageLength)
        encoded = codecs.decode(message, "utf-8").encode("utf_16")[2:]        
        os.write(rdw, len(encoded).to_bytes(4, sys.byteorder, signed=False))
        os.write(rdw, encoded)

threading.Thread(target=redirectio, daemon=True).start()

interpreter = []
worker = sys.argv[1]
if worker.endswith(".dll"):
    interpreter = [ "dotnet" ]

code = subprocess.call(interpreter + [worker, "spawnclient", format(rdr), format(wdw)], pass_fds=(rdr, wdw))
print(code)
# https://github.com/actions/runner/blob/af6ed41bcb47019cce2a7035bad76c97ac97b92a/src/Runner.Common/Util/TaskResultUtil.cs#L13-L14
if code >= 100 and code <= 105:
    sys.exit(0)
else:
    sys.exit(1)
