'''

    _,--._.-,   Utku Sen's
   /|_r-,|_ )    _ ____ ____ ___  ____ ____ ___  _ ___  ____
.-.) _;='_/ (.;  | |___ |  | |__] |__| |__/ |  | |   /  |___
 | |'     |/ )  _| |___ |__| |    |  | |  / |__/ |  /__ |___
  L.'-. _.'|-'
 <_`-'|'_.'/               utkusen.com - twitter.com/utkusen
   `'-._( |
    ___   ||,      ___
    | .'-. ||   .-'_. / Çıkar olay
     '._' '.||/.-'_.' Kan dökmek anlaşmaktan daha kolay
        '--``|('--'  Bir mermi bir çiçekten daha ucuza solar
              ||   Bir bomba sanki tüy gibi düşer ve yanmaz asla
              `||,	Sokakta tayfalarla
                ||	 Üçüncü sayfalarda

'''

import dns.resolver
from multiprocessing import Pool
import subprocess
import requests
import ssl
import socket
import whois
from datetime import datetime, timedelta
import psutil
from lxml import etree as et
import os
import platform
import sys
from signal import signal, SIGINT
import xml.etree.ElementTree as ET
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import argparse
from colorama import init
from termcolor import colored
init()

ZONEFILES_API_KEY = ""

if platform.system() == "Darwin":
    chromedriver_path = "/usr/local/bin/chromedriver"
else:
    chromedriver_path = "/usr/bin/chromedriver"

def handler(signal_received, frame):
    sys.exit(0)


with open("tlds.txt", "r") as tlds:
    tld_list = tlds.readlines()

header = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36'}

def generate_combinations(domain):
    print(colored("Creating combinations: ","green"), domain)
    cmd = subprocess.check_output(["python3", "generator.py", domain])
    clean = str(cmd).replace("b'","").replace("'","").replace('b"','').replace('"','')
    domains = clean.split('\\n')[1::]
    print(colored("Total word combinations: ","green"), str(len(domains)))
    with open(domain + ".txt", "a+") as f:
        for i in domains:
            if len(i.split('.')[0]) > 4:
                f.write(i.split('.')[0])
                f.write('\n')
    return(len(domains))


def check_ip(domain):
    global verboseflag
    if "." not in domain:
        global tld_list
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ['8.8.8.8']
        for tld in tld_list:
            try:
                answer = resolver.query(domain.strip()+'.'+tld.replace('\\n','').strip(), 'A')
                with open("out.txt", "a+") as f:
                    f.write(domain.strip()+'.'+tld.replace('\\n','').strip())
                    f.write('\n')
                if verboseflag:
                    print(colored("IP assigned to: ","green") ,domain.strip()+'.'+tld.replace('\\n','').strip())
            except:
                pass
    else:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ['8.8.8.8']
        try:
            answer = resolver.query(domain.strip(), 'A')
            with open("out.txt", "a+") as f:
                f.write(domain.strip())
                f.write('\n')
            if verboseflag:
                print(colored("IP assigned to: ","green") ,domain.strip())
        except:
            pass

def check_webserver(domain):
    flag = False
    try:
        r = requests.get("http://"+domain,timeout=1, headers=header)
        flag = True
    except:
        try:
            r = requests.get("https://" + domain, timeout=1, headers=header)
            flag = True
        except:
            flag = False
    return flag

def check_mailserver(domain):
    mailservers = []
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['8.8.8.8']
    try:
        answer = resolver.query(domain, 'MX')
        for data in answer:
            mailservers.append(str(data.exchange))
    except:
        return ['','']
    return mailservers

def check_nameservers(domain):
    try:
        nameservers = []
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ['8.8.8.8']
        answers = dns.resolver.query(domain, 'NS')
        for data in answers:
            nameservers.append(str(data))
        return nameservers[0:2]
    except:
        return ['','']

def get_website_size(domain):
    try:
        r = requests.get("http://"+domain,timeout=1, allow_redirects=True, headers=header)
    except:
        try:
            r = requests.get("https://" + domain, timeout=1, allow_redirects=True, headers=header)
        except:
            return 0
    return len(r.content)

def website_form_check(domain):
    try:
        r = requests.get("http://"+domain,timeout=1, allow_redirects=True, headers=header)
    except:
        try:
            r = requests.get("https://" + domain, timeout=1, allow_redirects=True, headers=header)
        except:
            return False
    if "<form " in r.text:
        if r.history:
            redir_domain = r.url.split("://")[1].split("/")[0].strip("www.")
            if redir_domain == domain:
                return "false_positive"
            else:
                return True
        else:
            return True
    else:
        return False

def check_certificate(domain):
    try:
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(socket.socket(), server_hostname=domain)
        s.connect((domain, 443))
        cert = s.getpeercert()
        subject = dict(x[0] for x in cert['subject'])
        issued_to = subject['commonName']
        issuer = dict(x[0] for x in cert['issuer'])
        issued_by = issuer['commonName']
        if "CloudFlare" in issued_by or "Let's Encrypt" in issued_by:
            return True
        else:
            return False
    except:
        return False

def alexa_check(domain):
    try:
        r = requests.get("https://data.alexa.com/data?cli=10&dat=s&url=" + domain, headers=header)
        if "REACH RANK" in r.text:
            return False
        else:
            return True
    except:
        return False

def date_check(domain):
    try:
        site = whois.query(domain)
        present = datetime.now()
        past = present - site.creation_date
        if past < timedelta(days=30):
            return True
        else:
            return False
    except:
        return False

def phishing_detect(domain):
    global verboseflag
    global out_xml
    base_score = 50
    valid_domain = domain.strip()
    webserver_flag = check_webserver(valid_domain)
    if webserver_flag:
        base_score += 5
        if verboseflag:
            print(valid_domain + " has webserver.")
        nameservers = check_nameservers(valid_domain)
        cert_flag = check_certificate(valid_domain)
        form_flag = website_form_check(valid_domain)
        if form_flag == "false_positive":
            return False
        if cert_flag:
            base_score += 5
        if form_flag:
            base_score += 15
    alexa_flag = alexa_check(valid_domain)
    if alexa_flag:
        if verboseflag:
            print(valid_domain + " isn't listed in Alexa directory.")
        if webserver_flag:
            base_score += 15
        else:
            base_score += 10
    date_flag = date_check(valid_domain)
    if date_flag:
        if verboseflag:
            print(valid_domain + " created less than 30 days.")
        if webserver_flag:
            base_score += 15
        else:
            base_score += 5
    mx_servers = check_mailserver(valid_domain)
    if mx_servers is not False:
        mx_flag = True
    try:
        if webserver_flag and mx_servers is not False:
            if verboseflag:
                print("Web and Mail servers are detected for: " + valid_domain + " MX servers: " + ' '.join(
                    [str(elem) for elem in mx_servers]) + " Nameservers: " + ' '.join([str(elem) for elem in nameservers]))
        if webserver_flag and mx_servers is False:
            if verboseflag:
                print("Web server is detected for: " + valid_domain + " Nameservers: " + ' '.join(
                    [str(elem) for elem in nameservers]))
        if webserver_flag is False and mx_servers is not False:
            if verboseflag:
                print("Only MX Servers detected for: " + valid_domain + " " + ' '.join([str(elem) for elem in mx_servers]))
    except:
        pass
    if base_score < 70:
        print(valid_domain ,colored(" phishing score: ","magenta") ,colored(str(base_score),"yellow"))
    if base_score < 80 and base_score > 70:
        print(valid_domain, colored(" phishing score: ", "magenta"), colored(str(base_score), "yellow")) #no orange? shame
    if base_score > 80:
        print(valid_domain, colored(" phishing score: ", "magenta"), colored(str(base_score), "red"))
    if base_score > 60:
        try:
            root = et.Element('domain')
            address_node = et.SubElement(root, 'address')
            address_node.text = valid_domain
            name_servers_node = et.SubElement(root, 'name_servers')
            name_servers_node.text =  ' '.join([str(elem) for elem in nameservers])
            mx_servers_node = et.SubElement(root, 'mx_servers')
            mx_servers_node.text = ' '.join([str(elem) for elem in mx_servers])
            date_flag_node = et.SubElement(root, 'date_flag')
            date_flag_node.text = str(date_flag)
            alexa_flag_node = et.SubElement(root, 'alexa_flag')
            alexa_flag_node.text = str(alexa_flag)
            webserver_flag_node = et.SubElement(root, 'webserver_flag')
            webserver_flag_node.text = str(webserver_flag)
            certificate_flag_node = et.SubElement(root, 'certificate_flag')
            certificate_flag_node.text = str(cert_flag)
            form_flag_node = et.SubElement(root, 'form_flag')
            form_flag_node.text = str(form_flag)
            phishing_score_node = et.SubElement(root, 'phishing_score')
            phishing_score_node.text = str(base_score)
            result = et.tostring(root, pretty_print=True, encoding="utf-8").decode("utf-8")
            with open(out_xml, "a+") as f:
                f.write(result)
            with open("phishes.txt", "a+") as f:
                if form_flag:
                    f.write(valid_domain+",t")
                else:
                    f.write(valid_domain + ",f")
                f.write('\n')
        except Exception as e:
            pass

    else:
        return False

def login_fill(url,username,password):

    global chromedriver_path
    chrome_options = webdriver.ChromeOptions()
    chrome_options.add_argument("no-sandbox")
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("log-level=3")
    chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
    driver = webdriver.Chrome(chromedriver_path, options=chrome_options)
    driver.get(url)
    delay = 5
    try:
        WebDriverWait(driver, delay).until(
            EC.presence_of_element_located((By.TAG_NAME, "input")))
    except TimeoutException:
        pass
    inputs = driver.find_elements_by_css_selector("input")
    for item in inputs:
        try:
            if item.is_displayed():
                item.send_keys(username)
        except:
            pass
    pass_inputs = driver.find_elements_by_css_selector("input[type='password']")
    for item in pass_inputs:
        if item.is_displayed():
            item.clear()
            actions = ActionChains(driver)
            actions.click(item).send_keys(Keys.END).key_down(Keys.SHIFT).send_keys(Keys.HOME).key_up(
                Keys.SHIFT).send_keys(Keys.BACK_SPACE).send_keys("").perform()
            item.send_keys(password)
    for item in pass_inputs:
        try:
            if item.is_displayed():
                item.click()
                item.send_keys(Keys.ENTER)
        except:
            pass
    driver.quit()

def action(domain,type,userlist=None,passlist=None,formfill=False):
    global base_domain
    global verboseflag
    global out_xml
    base_domain = domain
    print("Action started for: " + domain)
    print("Results will be written to: " +domain+".xml")
    comb_number = generate_combinations(domain)
    with open(domain + ".txt", "r") as f:
        domains = f.readlines()
    if type == "brute":
        print("Total tlds: "+str(len(tld_list)))
        print("Number of total domains to check: "+str(comb_number*len(tld_list)))
        print("This will take a while..")
        p = Pool(processes=psutil.cpu_count(logical = True)*2)
        p.map(check_ip, domains)
        p.close()
        p.join()
    elif type == "incremental":
        old_domains = []
        if os.path.isfile(out_xml):
            tree = ET.parse(out_xml)
            root = tree.getroot()
            for child in root:
                for i in child:
                    if i.tag == "address":
                        old_domains.append((i.text.strip()))
            with open("out.txt","a+") as f:
                for i in old_domains:
                    f.write(i)
                    f.write('\n')
        else:
            print(colored("XML file does not exists. Please run a daily scan first","red"))
            sys.exit(1)
    elif type == "daily" or type == "incremental":
        r = requests.get("https://zonefiles.io/a/"+ZONEFILES_API_KEY+"/update/1")
        print(colored("Number of domains registered in last 24h: ","green") , str(r.text.count('\n')))
        for i in domains:
            for j in r.text.splitlines():
                if i.strip() in j:
                    print(colored("Domain is registered!: ","cyan") , j.strip())
                    check_ip((j))
    else:
        print(colored("Wrong type is provided","red"))
        sys.exit(1)
    with open("out.txt","r") as f:
        valid_domains = f.readlines()
    n = Pool(processes=psutil.cpu_count(logical = True)*2)
    n.map(phishing_detect, valid_domains)
    n.close()
    n.join()
    with open(out_xml, "a+") as f:
        f.write("</root>")
    if formfill:
        print(colored("Starting to fill login forms..","cyan"))
        if userlist is None or passlist is None:
            print(colored("Please provide username and password lists","red"))
            sys.exit(1)
        target_domains = []
        tree = ET.parse(out_xml)
        root = tree.getroot()
        for child in root:
            for i in child:
                if i.tag == "address":
                    address = i.text
                if i.tag == "phishing_score":
                    score = int(i.text)
                elif i.tag == "form_flag":
                    if i.text == "True" and score > 84:
                        target_domains.append(address.strip())
        with open(userlist, "r") as f:
            usernames = f.readlines()
        with open(passlist, "r") as f:
            passwords = f.readlines()
        for i in target_domains:
            print("Jeopardizing: " + i)
            try:
                r = requests.get("http://" + i, timeout=5, allow_redirects=True, headers=header)
                url = r.url
            except:
                try:
                    r = requests.get("https://" + domain, timeout=1, allow_redirects=True, headers=header)
                    url = r.url
                except:
                    continue
            for u, p in zip(usernames, passwords):
                if verboseflag:
                    print("Sending combination: " + u.strip() + "/" + p.strip())
                login_fill(url,u.strip(),p.strip())

    print(colored("Removing the temporary files","cyan"))
    print(colored("Finished","green"))
    try:
        os.remove(domain+".txt")
        os.remove("out.txt")
        os.remove("phishes.txt")
    except Exception as e:
        print(e)

signal(SIGINT, handler)

parser = argparse.ArgumentParser()
parser.add_argument('--domain', action='store', dest='domain', help='Domain', required=True)
parser.add_argument('--type', action='store', dest='type', help='brute,daily,incremental', required=True)
parser.add_argument('-U', action='store', dest='userlist', help="userlist", default=None)
parser.add_argument('-P', action='store', dest='passlist', help="passlist", default=None)
parser.add_argument('-v', action='store_true', dest='verbose', help="verbose", default=None)
argv = parser.parse_args()


if argv.type != "incremental":
    with open(argv.domain+".xml", "w+") as f:
        f.write("<root>")
        f.write("\n")

try:
    os.remove("out.txt")
    os.remove("phishes.txt")
    os.remove(argv.domain+".txt")
except:
    pass

fillflag = False
try:
    if argv.userlist is not None and argv.passlist is not None:
        fillflag = True
except:
    pass

verboseflag = False
try:
    if argv.verbose:
        verboseflag = True
except:
    pass

out_xml = argv.domain + ".xml"

if __name__ == '__main__':
    action(argv.domain,argv.type,argv.userlist,argv.passlist,fillflag)

