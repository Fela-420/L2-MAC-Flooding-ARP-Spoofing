# L2-MAC-Flooding-ARP-Spoofing 
Learn how to use MAC Flooding to sniff traffic and ARP Cache Poisoning to manipulate network traffic as a MITM

For the sake of this room, let’s assume the following:

While conducting a pentest, you have gained initial access to a network and escalated privileges to root on a Linux machine. During your routine OS enumeration, you realize it’s a dual-homed host, meaning it is connected to two (or more) networks. Being the curious hacker you are, you decided to explore this network to see if you can move laterally.

After having established persistence, you can access the compromised host via SSH:

Zoom image will be displayed

ssh -o StrictHostKeyChecking=accept-new admin@10.10.248.161

Note: The admin user is in the sudo group. I suggest using the root user to complete this room: sudo su -
<img width="720" height="461" alt="image" src="https://github.com/user-attachments/assets/201ed209-d1fc-42fd-9311-340e132489aa" />

Zoom image will be displayed

Now, can you (re)gain access? (Yay/Nay)
Anwser : Yay
Network Discovery
As mentioned previously, the host is connected to one or more additional networks. You are currently connected to the machine via SSH on Ethernet adapter eth0. The network of interest is connected with Ethernet adapter eth1.

First, have a look at the adapter:

ip address show eth1 or the shorthand version: ip a s eth1

Using this knowledge, answer questions #1 and #2.

Now, use the network enumeration tool of your choice, e.g., ping, a bash or python script, or Nmap (pre-installed) to discover other hosts in the network and answer question #3.
<img width="720" height="102" alt="image" src="https://github.com/user-attachments/assets/a00bb933-2163-4588-a236-0ed2b1136f7a" />

Zoom image will be displayed

What is your IP address?
Anwser : 192.168.12.66
What’s the network’s CIDR prefix?
Anwser : /24
Zoom image will be displayed
<img width="720" height="426" alt="image" src="https://github.com/user-attachments/assets/5037646e-46a1-4a75-b25e-efc1dd44eb23" />

How many other live hosts are there?
Anwser : 2
What’s the hostname of the first host (lowest IP address) you’ve found?
Anwser : alice
Passive Network Sniffing
Simply scanning those hosts won’t help us gather any useful information, and you may be asking, what could a pentester do in this situation? Depending on the rules of engagement and scope, you could try sniffing traffic on this network.

The diagram below describes your current situation where you are the Attacker and have persistent access to eve.
<img width="609" height="425" alt="image" src="https://github.com/user-attachments/assets/1b5dc299-7929-40ce-a02b-6c1394365ab7" />


Let’s try running tcpdump on the eth1 network interface:

tcpdump -i eth1

Optionally, for a more verbose output that prints each packet (minus its link level header) in ASCII format:

tcpdump -A -i eth1

Try to answer questions #1 through #2.

Now, let’s take a closer look at the captured packets! We can redirect them into a pcap file providing a destination file via the -w argument:

tcpdump -A -i eth1 -w /tmp/tcpdump.pcap

Capture traffic for about a minute, then transfer the pcap to either your machine or the AttackBox to open it in Wireshark.

Example to transfer the packet capture using scp and open it in Wireshark:

scp admin@10.10.248.161:/tmp/tcpdump.pcap .
wireshark tcpdump.pcap

Now, you should be able to answer questions #3 and #4.

Note: If you receive an error “tcpdump: /tmp/tcpdump.pcap: Permission denied” and cannot overwrite the existing /tmp/tcpdump.pcap file, specify a new filename such as tcpdump2.pcap, or run rm -f /tmp/*.pcap then re-run tcpdump.
<img width="720" height="400" alt="image" src="https://github.com/user-attachments/assets/34f6e9c5-aab3-4ce9-93c6-e5ed8c336793" />

Zoom image will be displayed
<img width="720" height="329" alt="image" src="https://github.com/user-attachments/assets/578e0984-c62b-4d7d-a75e-b0084d798b25" />

Zoom image will be displayed
<img width="658" height="661" alt="image" src="https://github.com/user-attachments/assets/1bdef243-56b3-4501-aed0-4bec11c90916" />


Zoom image will be displayed
<img width="720" height="371" alt="image" src="https://github.com/user-attachments/assets/dddaa6f3-809f-42ba-8b07-ebe9a64bf9a8" />

Can you see any traffic from those hosts? (Yay/Nay)
Anwser : Yay
Who keeps sending packets to eve?
Anwser : Bob
What type of packets are sent?
Anwser : ICMP
Zoom image will be displayed
<img width="720" height="89" alt="image" src="https://github.com/user-attachments/assets/eda1b04c-e79e-41cc-99a4-2b89075d6567" />

Zoom image will be displayed
<img width="720" height="179" alt="image" src="https://github.com/user-attachments/assets/27422ad7-4852-4ea3-bed5-3300299ff7e3" />

Zoom image will be displayed
<img width="720" height="330" alt="image" src="https://github.com/user-attachments/assets/5a8bcbd0-1de0-4570-8edb-e789f4aee785" />

Zoom image will be displayed
<img width="461" height="110" alt="image" src="https://github.com/user-attachments/assets/fc0d674a-5fc5-47cc-ab72-754f849e4b30" />


Zoom image will be displayed
<img width="720" height="341" alt="image" src="https://github.com/user-attachments/assets/c523d704-8627-4aca-ba9b-48d986ba2143" />

Zoom image will be displayed
<img width="1100" height="156" alt="image" src="https://github.com/user-attachments/assets/f5ddad73-6fc0-408f-93dc-ef2747d97af2" />

4. What’s the size of their data section? (bytes)
Anwser : 666

Sniffing while MAC Flooding
MAC flooding is a network attack where an attacker sends numerous packets with different source MAC addresses to a network switch. This overwhelms the switch’s MAC address table, which is used to map MAC addresses to physical ports. When the table is full, the switch cannot associate incoming packets with their correct ports and starts broadcasting packets to all ports, turning the switch into a hub. This allows the attacker to capture network traffic that would otherwise not be accessible to them, leading to potential data interception and network performance degradation.

Unfortunately, we weren’t able to capture any interesting traffic so far. However, we’re not going to give up this easily! So, how can we capture more network traffic? As mentioned in the room description, we could try to launch a MAC flooding attack against the L2-Switch.

Beware: MAC flooding could trigger an alarm in a SOC. No, seriously, suspicious layer 2 traffic can easily be detected and reported by state-of-the-art and properly configured network devices. Even worse, your network port could even get blocked by the network device altogether, rendering your machine locked out of the network. In case of production services running on or production traffic being routed through that network connection, this could even result in an effective Denial-of-Service!

However, if we’re successful, the switch will resort to fail-open mode and temporarily operate similarly to a network hub — forwarding all received frames to every connected port (aside from the port the traffic originated from). This would allow an adversary or pentester to sniff the network traffic between other hosts that normally wouldn’t be received by their device if the switch were functioning properly.

Considering such an attack vector is only recommended when you have reasons to believe that…

It is in fact a switched network (and not a virtual bridge) AND
The switch might be a consumer or prosumer (unmanaged) switch OR the network admins haven’t configured mitigations such as Dynamic ARP Inspection (DAI) for instance AND
ARP and MAC spoofing attacks are explicitly permitted in the rules of engagement. When in doubt, clarify with your client first!
Anyhow, let’s assume you’ve met the well-thought decision to give it a try.

For better usability, open a second SSH session. This way, you can leave the tcpdump process running in the foreground on the first SSH session:

tcpdump -A -i eth1 -w /tmp/tcpdump4.pcap

Now, on the second SSH session, buckle up and let macof run against the interface to start flooding the switch:

macof -i eth1

Zoom image will be displayed

After around 30 seconds, stop both macof and tcpdump (Ctrl+C).

As in the previous task, transfer the pcap to your machine (kali/AttackBox) and take a look:

scp admin@10.10.248.161:/tmp/tcpdump4.pcap .
wireshark tcpdump4.pcap

Now, you should be able to answer questions #1 and #2.

Note: If it didn’t work, try to capture for 30 seconds, again (while macof is running).
If it still won’t work, give it one last try with a capture duration of one minute.
As the measure of last resort, try using ettercap (introduced in the following tasks) with the rand_flood plugin:

ettercap -T -i eth1 -P rand_flood -q -w /tmp/tcpdump3.pcap (Quit with q)

Zoom image will be displayed
<img width="720" height="579" alt="image" src="https://github.com/user-attachments/assets/d4ff7aa7-529f-460b-8ee2-610a3d3e38b1" />
<img width="619" height="225" alt="image" src="https://github.com/user-attachments/assets/3979c80f-1b19-40e1-8832-1a0f20fa4ad5" />

flood the local network with random mac address

Capture the packets on the eth1 and copiesthe capture file from remote host to locat machine

What kind of packets is Alice continuously sending to Bob?
Anwser : ICMP
What’s the size of their data section? (bytes)
Anwser : 1337
Man-in-the-Middle: Intro to ARP Spoofing
As you may have noticed, MAC Flooding can be considered a real “noisy” technique.

In order to reduce the risk of detection and DoS we will leave macof aside for now.

Instead, we are going to perform so-called ARP cache poisoning attacks against Alice and Bob, in an attempt to become a fully-fledged Man-in-the-Middle (MITM).

For a deeper understanding of this technique, read the Wikipedia article on ARP spoofing.

tl;dr — “an attacker sends (spoofed) ARP messages […] to associate the attacker’s MAC address with the IP address of another host […] causing any traffic meant for that IP address to be sent to the attacker instead.

ARP spoofing may allow an attacker to intercept data frames on a network,

modify the traffic, or stop all traffic. Often the attack is used as an opening for other attacks, such as denial of service, man in the middle, or session hijacking attacks.” — Wikipedia — ARP spoofing
<img width="466" height="356" alt="image" src="https://github.com/user-attachments/assets/8ee4306a-8784-4e81-98a1-a08813304d4b" />


https://commons.wikimedia.org/wiki/File:ARP_Spfing.svg

Get Niman Ransindu’s stories in your inbox
Join Medium for free to get updates from this writer.

Enter your email
Subscribe
There are, however, measures and controls available to detect and prevent such attacks. In the current scenario, both hosts are running an ARP implementation that takes pains to validate incoming ARP replies. Without further ado,

we are using ettercap to launch an ARP Spoofing attack against Alice and Bob and see how they react:

ettercap -T -i eth1 -M arp

Zoom image will be displayed
<img width="720" height="590" alt="image" src="https://github.com/user-attachments/assets/ebf3270c-b8c1-4798-ae35-970f16289668" />

Can ettercap establish a MITM in between Alice and Bob? (Yay/Nay)
Anwser : Nay
Would you expect a different result when attacking hosts without ARP packet validation enabled? (Yay/Nay)
Anwser :Yay
Man-in-the-Middle: Sniffing
Sniffing is a type of MITM attack in which an attacker intercepts and alters data packets passing through a given network.

In this somewhat altered scenario, Alice and Bob are running a different OS (Ubuntu) with its default ARP implementation and no protective controls on their machines. As in the previous task, try to establish a MITM using ettercap and see if Ubuntu (by default) is falling prey to it.

After starting the VM attached to this task, you can log on via SSH with the same credentials as before:

Username: admin
Password: Layer2

As with the previous machine, please, also allow a minimum of 5 minutes for this box to spin up, then try connecting with SSH (if you login, and the command line isn’t showing up yet, don’t hit Ctrl+C! Just be patient…)
<img width="720" height="404" alt="image" src="https://github.com/user-attachments/assets/d6ca9562-7cd8-42d6-b328-d5c2acc6c4d6" />

Zoom image will be displayed
<img width="720" height="505" alt="image" src="https://github.com/user-attachments/assets/98956c5b-0149-4df2-9103-8407f7bf621d" />

Zoom image will be displayed

Scan the network on eth1. Who’s there? Enter their IP addresses in ascending order.
Anwser : 192.168.12.10, 192.168.12.20
Which machine has an open well-known port?
Anwser : 192.168.12.20
What is the port number?
Anwser : 80

Can you access the content behind the service from your current position? (Nay/Yay)
Anwser : Nay
Zoom image will be displayed

Can you see any meaningful traffic to or from that port passively sniffing on you interface eth1? (Nay/Yay)
Anwser : Nay
Zoom image will be displayed

Zoom image will be displayed

Now launch the same ARP spoofing attack as in the previous task. Can you see some interesting traffic, now? (Nay/Yay)
Anwser : Yay
HTTP Request and Response:

Zoom image will be displayed

1. A GET request for test.txt is sent from 192.168.12.10 to 192.168.12.20 on port 80. ………….2. The request includes a basic authorization header (Authorization: Basic YWRtaW46czNjcjN0X1A0eno=), which decodes to admin:s3cr3t_P4zz(REQUEST)
Zoom image will be displayed
<img width="720" height="527" alt="image" src="https://github.com/user-attachments/assets/75c1c600-0e3b-4318-8b69-78183cf95387" />

3. The response from the server confirms the credentials and the requested file (/test.txt) with a 200 OK status.(RESPONSE)
Who is using that service?
Anwser : Alice(192.168.12.10)
What’s the hostname the requests are sent to?
Anwser : www.server.bob
Which file is being requested?
Anwser : test.txt
Zoom image will be displayed

3. The Content-Length: 3 header indicates the length of the content, and the content itself is "OK".(RESPONSE)
What text is in the file?
Anwser : OK
Which credentials are being used for authentication? (username:password)
Anwser : admin:s3cr3t_P4zz
Zoom image will be displayed

q
Now, stop the attack (by pressing q). What is ettercap doing in order to leave its man-in-the-middle position gracefully and undo the poisoning?(HINT: The second-last line displayed after pressing q (without the “…”))
Anwser : RE-ARPing the victims
Zoom image will be displayed

curl -u admin:s3cr3t_P4zz http://192.168.12.20/
Can you access the content behind that service, now, using the obtained credentials? (Nay/Yay)
Anwser : Yay
Zoom image will be displayed

curl -u admin:s3cr3t_P4zz http://192.168.12.20/user.txt
What is the user.txt flag?
Anwser : THM{wh0s_$n!ff1ng_0ur_cr3ds}
Alice has a reverse shell on the server at 192.168.12.20. This allows her to execute commands on the server from her machine at 192.168.12.10. The commands sent (e.g., ls, whoami, pwd) and their respective responses indicate that she has root access on the server.

You should also have seen some rather questionable kind of traffic. What kind of remote access (shell) does Alice have on the server?(HINT :The type of connection you want to catch when compromising hosts allowing you to execute commands by calling back to your listener.)
Anwser : reverse shell
Zoom image will be displayed

Zoom image will be displayed

Zoom image will be displayed

What commands are being executed? Answer in the order they are being executed.
Anwser : whoami, pwd, ls
Which of the listed files do you want?(HINT : Which of the listed files most likely contains the flag? (Just the file name.))
Anwser : root.txt
Man-in-the-Middle: Manipulation
As a pentester, your first approach would be to try to hack Bob’s web server. For the purpose of this room, let’s assume it’s impossible. Also, capturing basic auth credentials won’t help for password reuse or similar attacks.

So, let’s advance our ongoing ARP poisoning attack into a fully-fledged MITM that includes packet manipulation! As Alice’s packets pass through your attacker machine (eve), we can tamper with them.

How can we go about doing this? Ettercap comes with an -F option that allows you to apply filters in the form of specified etterfilter.ef files for the session. These .ef files, however, have to be compiled from etterfilter source filter files (.ecf) first. Their source code syntax is similar to C code. To keep this task more beginner-friendly, we assume it won't matter if Alice detects our manipulation activities. For the sake of this room, we are only going to manipulate her commands and won't be taking any OPSEC precautions.

Which brave command of hers should volunteer for our audacious endeavor? How about… yes, whoami, of course!

Before you copy and paste the filter below, it’s best to understand the etterfilter command and its source file syntax. Consult the man page by either running man etterfilter or browsing the linux.die.net/man/8/etterfilter page.

Zoom image will be displayed

man etterfilter
Now, create a new etterfilter code file named whoami.ecf and try to write a filter matching Alice’s source port and transport protocol as well as replacing whoami data with a reverse shell payload of your choice. To see the solution, click the dropdown arrow:

Zoom image will be displayed

Note: Quotation marks need to be escaped. So, in case you want your filter to replace e.g. whoami with echo -e "whoami\nroot", then the quotation marks around whoami\nroot would have to be escaped like this: replace("whoami", "echo -e \"whoami\nroot\" " )

To see a solution for the reverse shell payload, click the dropdown arrow:

Zoom image will be displayed

Finally, we need to compile the.ecf into an .ef file:

etterfilter whoami.ecf -o whoami.ef

Don’t forget to start your listener (backgrounded). For the upper example above, you could use:

nc -nvlp 6666 &

Not so fast! If anything, we still need to allow the incoming connection through the firewall. Disable ufw or create a corresponding allow rule; otherwise, Bob’s reverse shell will be blocked by the firewall:

ufw allow in on eth1 from 192.168.12.20 to 192.168.12.66 port 6666 proto tcp or completely disable the firewall by running ufw disable

Now, run ettercap specifying your newly created etterfilter file:

ettercap -T -i eth1 -M arp -F whoami.ef

A few seconds after executing this command, you should see the “###### ETTERFILTER: …” message and/or “Connection received on 192.168.12.20 …” in your Netcat output, which means you’ve just caught a reverse shell from Bob! Now, you can quit ettercap (with q), foreground your Netcat listener (with fg), and enjoy your shell!

Zoom image will be displayed

Zoom image will be displayed

Zoom image will be displayed


Note: To restrict ettercap’s ARP poisoning efforts to your actual targets and only display traffic between them, you can specify them as target groups 1 and 2 by using “///”-token annotation after the -M arp option:

ettercap -T -i eth1 -M arp /192.168.12.10// /192.168.12.20// -F whoami.ef

Hint: In case the reverse shell won’t work, try replacing whoami with a suitable cat command to get the flag.

Zoom image will be displayed

Zoom image will be displayed

Zoom image will be displayed

Zoom image will be displayed

What is the root.txt flag?
Anwser : THM{wh4t_an_ev1l_M!tM_u_R}
