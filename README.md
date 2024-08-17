# Covert-Channels-Group1
## Overview
EN.695.722 Group 1 Semester Long Project for EN.695.722.81.SU24.

This project implements a novel storage based covert channel using the IP Options field. 
Please read the report for further understanding of the project.

## Files
```
project
|   hello.txt: A small text file to convertly send.
│   ip_options.py: Application to run the covert channel.
|   large-text.txt: A large text file to send, used for experiment 2.
│   README.md
|   requrements.txt: pip requirements
```

## Flags
```  
  -h, --help            show this help message and exit
  -s SOURCE, --source SOURCE
                        The source IP address
  -d DESTINATION, --destination DESTINATION
                        The destination IP address
  -f FILE, --file FILE  File name read or write the message to
  -c, --client          Machine sending the message
  -r, --server          Machine receiving the message
  -t TIMEOUT, --timeout TIMEOUT
                        Time out for receiving a message. Defaults to 60s.
  -v, --verbose         Enable verbose mode.
  -k KEY, --key KEY     The secure key

```

## Running the application
Run the following commands 

```bash
# Send a message
python3 ip_options.py -c -s <IP_SRC> -d <IP_DST> -f <File_to_send> -k <private_key>

# Receive a message
python3 ip_options.py -r -s <IP_SRC> -f <File_to_save_received_message> -k <private_key>
```