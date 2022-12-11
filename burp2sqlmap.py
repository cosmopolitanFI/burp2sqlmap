#!/usr/bin/python3
import os
import sys
import uuid
import base64
import shutil
import argparse
import subprocess

from bs4 import BeautifulSoup

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

def update_log(file):
  read_log = []
  with open("requests/log.txt", "r") as f:
    for line in f.readlines():
      if file in line:
        line = line.replace("WAIT", "DONE")
      read_log.append(line)

  with open("requests/log.txt", "w+") as f:
    for line in read_log:
      f.write(line)

def run_sqlmap(files, args):
  for file in files:
    if "WAIT" in file:
      filename = file.split(" ")[0]
      alert = "'echo {} >> vulnerable.log'".format(filename)
      command = ["sqlmap","-r","requests/{}".format(filename), \
                 "--level={}".format(args.intensity), \
                 "--risk={}".format(args.risk),
                 "--random-agent", \
                 "--threads={}".format(args.threads), \
                 "--batch", "--flush-session",
                 "--answer='redirect=N'","--force-ssl", \
                 "--alert={}".format(alert)]
      if args.proxy != "":
        command.append("--proxy={}".format(args.proxy))
      subprocess.run(command)
      update_log(file)

def store_requests(requests):
  if os.path.exists("requests"):
    shutil.rmtree("requests")
  os.makedirs("requests/", exist_ok=True)
  files = []
  with open("requests/log.txt", "w+") as log:
    for request in requests:
      request = base64.b64decode(request.contents[0])
      
      # Write request to file
      req_id = uuid.uuid4().hex
      file = "requests/{}".format(req_id)
      with open(file, "wb+") as f:
        f.write(request)
      file += " -- WAIT\n"
      file = file.replace("requests/","")
      log.write(file) # keep track of file names
      files.append(file.strip()) # Store file names to list
  return files

def read_log():
  files = []
  with open("requests/log.txt", "r") as f:
    for file in f.readlines():
      files.append(file.strip())
  return files


if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="Do sqlmap for burp file")
  required = parser.add_argument_group("Required arguments")
  parser.add_argument("--requests", action="store", dest="requests", help="requests.xml")
  parser.add_argument("--intensity", default="1", action="store", dest="intensity")
  parser.add_argument("--risk", default="1", action="store", dest="risk")
  parser.add_argument("--proxy", default="", action="store", dest="proxy")
  parser.add_argument("--threads", default="10", action="store", dest="threads")
  parser.add_argument("--new", default=True, action="store", dest="new")
  args = parser.parse_args()
  try:
    burp_file = args.requests
    requests = read_burp(burp_file)
    if args.new != "False":
      files = store_requests(requests)
    else:
      files = read_log()
    run_sqlmap(files, args)

  except Exception as e:
    print("Error! - do help")
    print(e)
