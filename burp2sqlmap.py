#!/usr/bin/python3
import subprocess, sys
from bs4 import BeautifulSoup
import os
import uuid
import base64

def read_burp(file):
  if os.path.isfile(file):
    # Read xml file
    with open(file, "r") as f:
      data = f.read()
    parsed_data = BeautifulSoup(data, "xml")
    requests = parsed_data.find_all("request")
    return requests
  else:
    print("File does not exist")

def write_requests(requests):
  os.makedirs("requests/", exist_ok=True)
  for req in requests:
    request = base64.b64decode(req.contents[0])

    # Write request to file
    req_id = uuid.uuid4().hex
    file = "requests/{}".format(req_id)

    with open(file, "wb+") as f:
      f.write(request)

  print("[*] Written {} requests to disk".format(len(requests)))

def run_sqlmap():
  request_files = os.listdir("requests/")

  for request in request_files:
    if "scanned" not in request and "vulnerable" not in request:
      alert = "mv requests/{0} requests/{0}-vulnerable".format(request)

      command = ["python3","sqlmap-dev/sqlmap.py","-r","requests/{}".format(request),
        "--proxy=http://127.0.0.1:8080", "--random-agent", "--threads=10", "--batch", 
        "--flush-session","--answer='redirect=N'","--alert={}".format(alert)]
      
      print("[i] Running command: {}".format(command))
      subprocess.run(command)

      request = os.system("ls requests/ |grep {}".format(request))
      if "vulnerable" not in request:
        os.system("mv requests/{0} requests/{0}-scanned".format(request))


if __name__ == "__main__":
  try:
    burp_file = sys.argv[1]
    cont = False
    if len(sys.argv) == 3 and sys.argv[2] == "continue":
      cont = True

    if not cont:
      requests = read_burp(burp_file)
      write_requests(requests)

    run_sqlmap()

  except Exception as e:
    print("Error! - Example")
    print("python3 burp2sqlmap.py BURPFILE [continue]")
    print(e)
