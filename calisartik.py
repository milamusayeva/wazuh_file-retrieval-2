#!/usr/bin/python3
# Copyright (C) 2015-2022, Wazuh Inc.
# All rights reserved.

# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import os
import sys
import json
import datetime
from pathlib import PureWindowsPath, PurePosixPath

if os.name == 'nt':
    LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"

ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3

OS_SUCCESS = 0
OS_INVALID = -1

class message:
    def __init__(self):
        self.alert = ""
        self.command = 0


def write_debug_file(ar_name, msg):
    with open(LOG_FILE, mode="a") as log_file:
        ar_name_posix = str(PurePosixPath(PureWindowsPath(ar_name[ar_name.find("active-response"):])))

        log_file.write(str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')) + " " + ar_name_posix + ": " + msg + "\n")


def setup_and_check_message(argv):
    # get alert from stdin
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break

    write_debug_file(argv[0], input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        message.command = OS_INVALID
        return message

    message.alert = data

    command = data.get("command")

    if command == "add":
        message.command = ADD_COMMAND
    elif command == "delete":
        message.command = DELETE_COMMAND
    else:
        message.command = OS_INVALID
        write_debug_file(argv[0], 'Not valid command: ' + command)

    return message


def send_keys_and_check_message(argv, keys):
    # build and send message with keys
    keys_msg = json.dumps({
        "version": 1,
        "origin": {"name": argv[0], "module": "active-response"},
        "command": "check_keys",
        "parameters": {"keys": keys}
    })

    write_debug_file(argv[0], keys_msg)

    print(keys_msg)
    sys.stdout.flush()

    # read the response of previous message
    input_str = ""
    while True:
        line = sys.stdin.readline()
        if line:
            input_str = line
            break

    write_debug_file(argv[0], input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        return message

    action = data.get("command")

    if "continue" == action:
        ret = CONTINUE_COMMAND
    elif "abort" == action:
        ret = ABORT_COMMAND
    else:
        ret = OS_INVALID
        write_debug_file(argv[0], "Invalid value of 'command'")

    return ret


def main(argv):
    write_debug_file(argv[0], "Started")

    # validate json and get command
    msg = setup_and_check_message(argv)

    if msg.command < 0:
        sys.exit(OS_INVALID)

    if msg.command == ADD_COMMAND:
    try:
        alert = msg.alert["parameters"]["alert"]
        # Navigate the nested JSON to extract 'targetFilename'
        target_filename = msg.alert["parameters"]["alert"]["data"]["win"]["eventdata"]["targetFilename"]

        # Ensure the targetFilename is not empty or invalid
        if not target_filename:
            write_debug_file(argv[0], "No valid targetFilename found in the alert")
            sys.exit(OS_INVALID)

        # Log the extracted file path for debugging
        write_debug_file(argv[0], f"Extracted targetFilename: {target_filename}")

        # Create the keys array with the extracted filename
        keys = [target_filename]

    except KeyError as e:
        write_debug_file(argv[0], f"Error extracting targetFilename: {str(e)}")
        sys.exit(OS_INVALID)

    # Proceed with sending keys and checking the message
    action = send_keys_and_check_message(argv, keys)
    import requests

    url = "https://www.virustotal.com/api/v3/files"

    files = { "file": (str(keys), open(str(keys), "rb"), "application/x-msdownload") }
    headers = {
        "accept": "application/json",
        "x-apikey": "your-api-key"
    }

response = requests.post(url, files=files, headers=headers)

print(response.text)

    if action != CONTINUE_COMMAND:
        if action == ABORT_COMMAND:
            write_debug_file(argv[0], "Aborted")
            sys.exit(OS_SUCCESS)
        else:
            write_debug_file(argv[0], "Invalid command")
            sys.exit(OS_INVALID)

    # Write to ar-test-result.txt
    with open("ar-test-result.txt", mode="a") as test_file:
        test_file.write("Active response triggered for file path: <" + str(keys) + ">\n")
        """ End Custom Action Add """

    elif msg.command == DELETE_COMMAND:

        """ Start Custom Action Delete """
        os.remove("ar-test-result.txt")
        """ End Custom Action Delete """

    else:
        write_debug_file(argv[0], "Invalid command")

    write_debug_file(argv[0], "Ended")
    sys.exit(OS_SUCCESS)


if __name__ == "__main__":
    main(sys.argv)
