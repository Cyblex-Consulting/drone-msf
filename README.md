# drone-msf

[Lair](https://github.com/lair-framework/) drone for metasploit.

## Get the drone

Either build the drone with `go build` or get the pre-built binary from releases.

## How to Use

Export metasploit workspace from within msfconsole in xml format with `db_export`.

Import the file to Lair with :
```bash
export LAIR_ID=<LAIR PID>
export LAIR_API_SERVER="https://<EMAIL>:<PASSWORD>.@<LAIR INSTANCE>"
./drone-msf -k <FILE>
```
