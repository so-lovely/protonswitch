## Initial setup
```
git clone <url>
python3 -m venv env 
source env/bin/activate
pip install -r requirements.txt
```

To identify iface name, use wireshark 
Make sure protonvpn protol to be set IKEv2

## After turn on vpn
`sudo python3 protonswitch.py on <vpn_ip> <iface>`

## All network interfaces on
`sudo python3 protonswitch.py up`

### Tested on Mac. and go well on unix maybe?

[Click program usage](https://youtu.be/_rYsRuRXgWg?si=v2L2piI_MF21cCkz)
