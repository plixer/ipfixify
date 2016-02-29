sudo farpd 192.168.2.32/29
sudo honeyd --disable-webserver -p /etc/honeypot/nmap.prints -f /home/honeynet/honeyd.conf -i eth0 192.168.2.32/29 -l /home/honeynet/connect.log -s /home/honeynet/connect.log
./ipfixify.exe --honeynet 192.168.2.28:2002 --sendto 192.168.2.28:514 --file /home/honeynet/connect.log &
