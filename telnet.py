import getpass
import telnetlib
import time
import keyboard
HOST = "192.168.122.1"  
user =  input("Enter your remote account: ")  
password = getpass.getpass()  

tn = telnetlib.Telnet(HOST, 31152)
print("Telnet..")
keyboard.press_and_release('enter')
print("Telnet..")
tn.read_until(b"firepower login:")
print("Telnet..")
tn.write(user.encode('ascii') + b"\n")
print("Telnet..")
if password:
    tn.read_until(b"Password: ")
    tn.write(password.encode('ascii') + b"\n")
    print("Telnet..")
print("Telnet connection completed!")
tn.read_until(b"Press <ENTER> to display the EULA:")
keyboard.press_and_release('enter')
keyboard.press_and_release('q')
tn.read_until(b"Please enter 'YES' or press <ENTER> to AGREE to the EULA:")
tn.write(b"YES\n")
print("EULA Accepted..")
tn.read_until(b"Enter new password:")
tn.write(b"Admin123\n")
keyboard.press_and_release('enter')
tn.read_until(b"Confirm new password:")
tn.write(b"Admin123\n")
keyboard.press_and_release('enter')
print("New password configured..")
tn.read_until(b"Enter an IPv4 address for the management interface [192.168.45.45]:")
tn.write(b"192.168.1.100\n")
keyboard.press_and_release('enter')
print("Management IP Address configured..")
tn.read_until(b"Enter an IPv4 netmask for the management interface [255.255.255.255]:")
tn.write(b"255.255.255.255\n")
keyboard.press_and_release('enter')
print("Management Netmask configured..")
tn.read_until(b"Enter the IPv4 default gateway for the management interface [192.168.45.1]:")
tn.write(b"192.168.1.1\n")
keyboard.press_and_release('enter')
print("Default gateway IP Address configured..")
tn.read_until(b"Enter a fully qualified hostname for this system [firepower]:")
tn.write(b"ngfw.secure-x.local\n")
keyboard.press_and_release('enter')
print("Entered FQDN..")
tn.read_until(b"Enter a comma-separated list of DNS servers or 'none' []:")
tn.write(b"192.168.1.2\n")
keyboard.press_and_release('enter')
tn.read_until(b"Enter a comma-separated list of search domains or 'none':")
tn.write(b"secure-x.local\n")
keyboard.press_and_release('enter')
tn.read_until(b"Manage the device locally? (yes/no) [yes]:")
tn.write(b"no\n")
keyboard.press_and_release('enter')
print("Wait for two minutes to configure the device")
time.sleep(180)
tn.write(b"show network\n")
tn.write(b"ping system 192.168.1.2\n")
time.sleep(5)
tn.write(b"ping system fmc.secure-x.local\n")
time.sleep(5)
print("Accessing FTD Shell using expert")
tn.write(b"expert\n")
tn.write(b"ping 192.168.1.2\n")
time.sleep(5)
tn.write(b"ping fmc.secure-x.local")
# tn.write(b"ls\n")
tn.write(b"exit\n")
print(tn.read_all().decode('ascii'))
tn.close()