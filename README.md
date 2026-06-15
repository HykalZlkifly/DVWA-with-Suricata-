# DVWA-with-Suricata-

Suricata SQL Injection

IDS
1st terminal
1) sudo nano /var/lib/suricata/rules/local.rules
2)alert http any any -> any any (msg:"DVWA SQLi - Malicious Keyword Detected (OR/UNION)"; pcre:"/(%27|'|%3D|=|union)/Ui"; sid:1000006; rev:1;)
3) sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -v
4)sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -v
2nd terminal
fast:
tail -f /var/log/suricata/fast.log
live:
sudo tail -f /var/log/suricata/eve.json | grep --color=auto --line-buffered '"event_type":"alert"' | jq

IPS 
1st terminal
1) sudo nano /var/lib/suricata/rules/local.rules
2) 
alert http any any -> any any (msg:"SQL INJECTION SPOTTED - LOGGING ATTACK"; content:"UNION"; nocase; http_uri; sid:1000008; rev:3;)
reject http any any -> any any (msg:"SQL INJECTION DETECTED - IPS REJECT"; content:"UNION"; nocase; http_uri; sid:1000001; rev:10;)
3)sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -v
2nd terminal
fast:
tail -f /var/log/suricata/fast.log
live:
sudo tail -f /var/log/suricata/eve.json | grep --color=auto --line-buffered '"event_type":"alert"' | jq

3rd terminal:
clean
sudo iptables -F
start blocking
sudo iptables -I INPUT -p tcp --dport 80 -m string --algo bm --string "UNION" -j NFQUEUE --queue-num 0 --queue-bypass

Potential if long slumber:

 # 1. Flush out any old stuck rules
sudo iptables -F
sudo ip6tables -F

# 2. Insert detour rules with the bypass safety flag
sudo iptables -I INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0 --queue-bypass
sudo iptables -I OUTPUT -p tcp --sport 80 -j NFQUEUE --queue-num 0 --queue-bypass

#3. sudo suricata -c /etc/suricata/suricata.yaml -q 0 -v


