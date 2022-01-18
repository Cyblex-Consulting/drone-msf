# drone-msf

[Lair](https://github.com/lair-framework/) drone for metasploit.

## How to Use

Export metasploit workspace from within msfconsole.

Import the file to Lair with :
```bash
export LAIR_ID=<LAIR PID>
export LAIR_API_SERVER="https://<EMAIL>:<PASSWORD>.@<LAIR INSTANCE>"
./drone-msf -k <FILE>
```
