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

def run_sqlmap(requests):
  for req in requests:
    request = base64.b64decode(req.contents[0])

    # Write request to file
    req_id = uuid.uuid4().hex
    file = "requests/{}".format(req_id)

    with open(file, "wb+") as f:
      f.write(request)

    alert = "echo {} >> vulnerable.log".format(req_id)
    command = ["sqlmap","-r","requests/{}".format(req_id),
               "--random-agent", "--threads=10", "--batch", "--flush-session",
               "--answer='redirect=N'","--force-ssl","--proxy=http://localhost:8080/","--alert={}".format(alert)]
    subprocess.run(command)

if __name__ == "__main__":
  try:
    burp_file = sys.argv[1]
    requests = read_burp(burp_file)
    os.makedirs("requests/", exist_ok=True)
    run_sqlmap(requests)

  except Exception as e:
    print("Error! - Example")
    print("python3 burp2sqlmap.py BURPFILE")
    print(e)
