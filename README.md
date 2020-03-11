## Introduction

Jeopardize tool is developed to provide basic threat intelligence&response capabilities against phishing domains at the minimum cost as possible. It detects registered phishing domain candidates (typosquatting, homograph etc.), analyzes them and assigns a risk score to them. After then, it sends valid-looking credentials to the login forms on those phishing sites.

*Why?* Imagine this scenario: Attacker registers a phishing domain, acmebnak.com (Typosquatting of acmebank), copies the original acmebank.com's login form there and advertises this domain via sponsored tweets. This ad and the domain probably will be marked as phishing in the next day but the attacker has already harvested credentials from users. Taking it down after this won't help the affected users. Jeopardize provides a proactive solution to this problem. It jeopardizes the phishing form with valid-looking credentials to confuse the attacker. This will buy organizations some time to take precautions.


```
  ATTACKER+-----advertises+
                          |                                    +---------------+
                          |                                    |               |
                 +--------v-------+   +----------------+       |               |
                 |twitter.com/ads |   |acmebnak.com    |       | 549233/ahs72 +------>FAKE
                 +----------------+   +----------------+       |               |
                 |                |   |                |       | 398273/pass1 +------>FAKE
                 |  AcmeBank      +-->+  username:     +-------+               |
                 |  Tax Refunds   |   |  password:     |       | 393823/sm283 +------>LEGIT
                 |                |   |                |       |               |
                 +--------^-------+   +----------------+       | 394837/azerb +------>FAKE
                          |                  ^                 |               |
  VICTIM USER+-----clicks-+                  |sends            |               |
                                             |fake creds       +---------------+
                                             +
                                         JEOPARDIZE
```


## How it Works?

### 1- Generating the combinations
Jeopardize generates different word combinations with a given domain. ([dnstwist](https://github.com/elceef/dnstwist) helps here) For example, if the given domain is acmebank.com, combinations
would be acmebnak, acmeban, amcebank etc. If your domain has a short or generic name (for example: aa.com) This tool
won't help you. It works best for unique names.

### 2- Detecting Registered Domains 
Jeopardize has two different detection methods to identify registered domains:

**Brute:** Jeopardize combines the generated words (acmebnak, amcebank etc.) with all TLDs (com,net,xyz,live etc.) and does
whois query for all of them. *Pros:* Doesn't require any API key, totally free. / *Cons:* Takes lots of time.

**Dailly** With given Zonefiles.io API Key, Jeopardize scrapes all domains registered in the last 24 Hours and searches
them for the generated words (acmebnak, amcebank etc.). *Pros:* Fast, can be used as a daily threat intelligence easily.
*Cons:* Requires Zonefiles.io API Key (Pro edition)

### 3- Analyzing the Domains 

Detected domains are already suspicious. But there are factors that increase the likelihood of being a phishing domain. Also, we need to analyze if any phishing page is installed on that domain so that we can take actions against to them. Jeopardize checks the following elements of the registered domains:

- **IP:** If any IP address is assigned to the domain. If yes, the phishing risk score will increase.
- **Web Server:** If a web server is installed on that domain. If yes, the phishing risk score will increase.
- **Nameservers:** Checking the nameservers. If it uses Cloudflare, the phishing risk score will increase (no offense)
- **Website Size:** Checking the size of the website. Phishing pages usually contain different images, css
and js files. The phishing risk score will increase if it's above a predefined threshold.
- **Login Form:** If a login form is identified at the website. If yes, the phishing risk score will increase.
- **SSL Certificate:** Checking the CA of the SSL certificate. If it's issued by a CA other than Cloudflare or LetsEncrypt,
the phishing risk score will "decrease". 
- **Registration Date:** Checking the registration date of the domain. If it's newer than one month, the phishing risk score will
increase.
- **Alexa Ranking:** Checking the Alexa ranking of the domain. If it's not listed in there, the phishing risk score will increase.

### 4- Jeopardizing Login Forms
If the phishing score is high and the website has a login form, Jeopardize will fill it automatically with the provided username/password list.

### Saving the Results
It saves the information of detected phishing domains to an XML file. For example:

```
<domain>
  <address>acmebnak.com</address>
  <name_servers>ns1.cloudflare.com ns2.cloudflare.com</name_servers>
  <mx_servers> </mx_servers>
  <date_flag>True</date_flag>
  <alexa_flag>False</alexa_flag>
  <webserver_flag>True</webserver_flag>
  <certificate_flag>False</certificate_flag>
  <form_flag>True</form_flag>
  <phishing_score>85</phishing_score>
</domain>
```
**

## Installation
Jeopardize requires Python3 to work and tested on macOS, Ubuntu 18.04 and Debian based Linux systems. First, clone the repo:

`git clone https://github.com/utkusen/jeopardize.git`

Go inside the folder

`cd jeopardize`

Install required libraries

`pip3 install -r requirements.txt`

You also need to install chromedriver for selenium (Required for form filling. I you won't use it, don't need to install)

**on Ubuntu:** Run `sudo apt install chromium-chromedriver`

**on Kali:** Run `pip3 install chromedriver-binary`

**on macOS:** Run `brew cask install chromedriver`

If you want to integrate Zonefiles.io API, open `jeopardize.py` with a text editor, replace `ZONEFILES_API_KEY = ""` with your own key. 

You are good to go!

## Usage

**Note to macOS Users:**  It seems macOS restricts multithreading as a security mechanism. You need to run following command before running
the tool: `export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` for more info about this issue, please check [here](https://stackoverflow.com/questions/50168647/multiprocessing-causes-python-to-crash-and-gives-an-error-may-have-been-in-progr/52230415)

You need to provide your domain for phishing checking with `--domain` parameter. You also need to provide `--type`(brute,daily,incremental) as registered domain detection method. 

**Example command:** `python3 jeopardize.py --domain facebook.com --type brute`

**What it does?:** Combines words combinations of facebook (fcabook, facebkook etc.) with all TLDs(com,net,org,xyz) and does
whois query for all of them. Results will be saved to facebook.com.xml file. *This doesn't fill the login forms of the detected domains.*

**Example command:** `python3 jeopardize.py --domain facebook.com --type daily`

**What it does?:** Scrapes all domains registered in the last 24 Hours with Zonefiles.io API and searches
them for the generated words (fcabook, facebkook etc.) 

**Example command:** `python3 jeopardize.py --domain facebook.com --type incremental`

**What it does?:** It takes a previously generated XML file (facebook.com.xml), scrapes domains in it and updates their data, also does regular daily scan. 

If you want to fill login forms of the detected phishing domains, provide a username list with `-U` and password list with `-P` parameter

**Example command:** `python3 jeopardize.py --domain facebook.com --type daily -U user.txt -P pass.txt`

If you want to activate verbose mode, add `-v` parameter at the end of the command.

