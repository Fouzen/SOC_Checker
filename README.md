# SOC Checker

The SOC Checker is an automated bash script which is able to execute brute force attacks, backdoor exploit and ARP spoofing on device within the local area network. 

## Dependencies

`hydra`
`metasploit-framework`
`dsniff`

## Usage

The tool scans the local area network for available network devices, upon finding any available devices, it is displayed for the user to pick the target to attack.
Information on target host is displayed and the user can pick 3 types of attack vector. 

![image](https://github.com/Fouzen/SOC_Checker/assets/7608068/aa745c46-0fc7-4280-b8ff-4ae9ee826e3e)

### Brute Force Attack

The tool uses `hydra` to attack services and guess the correct user and password. The user can use their own user and password lists for the brute force attack.

![image](https://github.com/Fouzen/SOC_Checker/assets/7608068/0f2de93d-3d71-4d0e-adb5-94959945436b)

![image](https://github.com/Fouzen/SOC_Checker/assets/7608068/93021fbf-a1f6-44fc-9ba9-34045b5181ef)

### Exploit Attack

When exploit attack option is chosen, the SOC_Checker tool will automatically search and exploit an available vulnerability. The attack is completed when the session has attained root access. 

![image](https://github.com/Fouzen/SOC_Checker/assets/7608068/8d161e59-e824-4b29-89ba-1a8e9410175f)

### Arp Spoofing

The attacker machine shall ARP spoofing messages to target machine and router. Once it is successful, the target machine shall recognize the attacker machine as the router.

![image](https://github.com/Fouzen/SOC_Checker/assets/7608068/df21c6a3-1275-4e51-84ac-cdfb4005e9f9)

Using Wireshark, it shows that ARP Spoofing was successful. 

![image](https://github.com/Fouzen/SOC_Checker/assets/7608068/ec49b01e-8500-4f52-acc2-79eaff47ac64)

# Disclaimer 

SOC_Checker should be used for authorized penetration testing and/or nonprofit educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. The tools and techniques are for educational purposes only, using them for malicious purposes is illegal. Use it ONLY at your own networks and/or with the network owner's permission.
