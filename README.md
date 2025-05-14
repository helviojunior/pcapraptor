# PCAP Raptor

`pcapraptor` is a tool to manipulate PCAP files! 

Available modules:

* [x] Auto adjust PCAP package times using an NTP package from reference
* [x] Locate all network subnets and supernets inside of PCAP file

## Motivation

For me, it's very common to run into an issue when capturing network traffic using tools like the [Hak5 Packet Squirrel](https://shop.hak5.org/products/packet-squirrel-mark-ii): the packet timestamps are not accurate. This usually happens because the device (the sniffer) hasn't synced its clock before starting the capture. As a result, I end up having to manually analyze and calculate the correct time for each packet—which is a pain.

Wireshark does offer a "Time Shift" feature to adjust timestamps, but the adjustment isn't persistent. Every time you close and reopen the PCAP file, you have to recalculate the time shift from scratch.

To solve this problem, I created PCAPRaptor. In most cases, the devices being captured (like computers, printers, etc.) use NTP to synchronize their clocks. PCAPRaptor takes advantage of this by scanning the PCAP file for NTP traffic and using that information to correct the timestamps across the entire capture.

Of course, I know NTP traffic isn’t always present, so I’m planning to add support for parsing other protocols that can reveal accurate date and time info—like HTTP responses and other packets that carry timestamp metadata. I'm also working on a feature to sync timestamps across two separate PCAP files.

In addition, I plan to add other useful functions, such as merging multiple PCAP files.

*Note:* If you know of any other network protocols that can be used to extract real date and time from a PCAP, feel free to let me know!

## Some amazing features

* [x] Look for NTP request/response into PCAP file and calculate package time.   
* [x] Auto calculate and save PCAP Time Shift.  
* [x] And much more!  

## TODO

* [x] Sync time using another PCAP file as reference  
* [x] Support PCAPNG.  
* [x] Support another protocols if possible (not only NTP).


## Get last release

Check how to get last release by your Operational Systems procedures here [INSTALL.md](https://github.com/helviojunior/pcapraptor/blob/main/INSTALL.md)


# Utilization

## Time shifiting using NTP data

```
$ pcapraptor ntp -i ~/Desktop/dump2.pcap

______  _____   ___  ______                _
| ___ \/  __ \ / _ \ | ___ \ __ __ _ _ __ | |_ ___  _ __
| |_/ /| /  \// /_\ \| |_/ /'__/ _' | '_ \| __/ _ \| '__|
|  __/ | |    |  _  ||  __/ | ( |_| | |_) | || (_) | |
| |    | \__/\| | | || |  |_|  \__,_| .__/ \__\___/|_|
\_|     \____/\_| |_/\_|            |_|

INFO Looking for NTP data into pcap file, this can take a while. Please be patient.
INFO Converting to /Users/m4v3r1ck/Desktop/dump_20250321_172943.pcap
INFO Adjusting PCAP packages time to 247d 22h 44m 58s 058651ms ahead
INFO Convertion status
     -> Elapsed time.......: 00:00:02
     -> Packets converted..: 118.818
```

### Image 1 - Pcap file before adjust

![PCAP1 - before adjustments](https://github.com/helviojunior/pcapraptor/blob/main/images/pcap1.jpg "before adjustments")

### Image 2 - NTP packet

As we can see at the image bellow, the package time is wrong. Also, we have a reference time inside of an NTP response package, so the `pcapraptor` will identify this NTP package, calculate network request/response delay and adjust the time of all packages inside of PCAP file.

![PCAP2 - ntp packet](https://github.com/helviojunior/pcapraptor/blob/main/images/pcap2.jpg "ntp packet")

### Image 3 - Pcap file after adjust

![PCAP3 - after adjustments](https://github.com/helviojunior/pcapraptor/blob/main/images/pcap3.jpg "after adjustments")


## Help

```
$ pcapraptor ntp -h

______  _____   ___  ______                _
| ___ \/  __ \ / _ \ | ___ \ __ __ _ _ __ | |_ ___  _ __
| |_/ /| /  \// /_\ \| |_/ /'__/ _' | '_ \| __/ _ \| '__|
|  __/ | |    |  _  ||  __/ | (_| | |_) | || (_) | |
| |    | \__/\| | | || |  |_|  \__,_| .__/ \__\___/|_|
\_|     \____/\_| |_/\_|            |_| 


Usage:
  pcapraptor ntp [flags]

Examples:

   - pcapraptor ntp --pcap data.pcap
   - pcapraptor ntp --pcap data.pcap --output-file adjusted.pcap

Flags:
  -h, --help                 help for ntp
  -o, --output-file string   The file to write adjusted PCAP data to
  -i, --pcap string          PCAP source file

Global Flags:
  -D, --debug-log   Enable debug logging
  -q, --quiet       Silence (almost all) logging


```
