## OpenVPN plugin to block all incoming UDP packets via non-VPN interface
When you're connected to the VPN, replies to incoming UDP packets to the ISP interface may go via VPN interface. Technically you can't call it IP address leak, but it allows malicious persons (such as copyright trolls) to identify your real IP address. This OpenVPN plugin will protect you from said routing issue.
### How to use
1. Download `block-incoming-udp-32.dll` for 32 bit system or `block-incoming-udp-64.dll` for 64 bit system
2. Add the following line to your OpenVPN configuration file:  
`plugin block-incoming-udp-32.dll`  
for 32 bit system or  
`plugin block-incoming-udp-64.dll`  
for 64 bit system

### How it works
This plugin implements Windows Filtering Platform userspace filter to block all IPv4 and IPv6 incoming UDP packets which were received neither from LAN subnets nor from Internet to OpenVPN TAP Adapter interface to prevent IP address leak. It works like a temporary firewall which clears its rules upon termination or crash. This is important as you won't get broken internet connection if OpenVPN client suddenly crashes, unlike with other methods.

### More information
[In English](https://medium.com/@ValdikSS/another-critical-vpn-vulnerability-and-why-port-fail-is-bullshit-352b2ebd22e2#.1xoft0v97)  
[In Russian](http://habrahabr.ru/post/273523/)