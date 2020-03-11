
# -*- coding: utf-8 -*-

#Part of: https://github.com/elceef/dnstwist/blob/master/dnstwist.py

import re
import sys
import socket
import signal
import time
import argparse
import threading
from random import randint
from os import path


try:
    import queue
except ImportError:
    import Queue as queue

try:
    import requests
    MODULE_REQUESTS = True
except ImportError:
    MODULE_REQUESTS = False
    pass

DIR = path.abspath(path.dirname(sys.argv[0]))


REQUEST_TIMEOUT_DNS = 5
REQUEST_TIMEOUT_HTTP = 5
REQUEST_TIMEOUT_SMTP = 5
THREAD_COUNT_DEFAULT = 10

if sys.platform != 'win32' and sys.stdout.isatty():
    FG_RND = '\x1b[3%dm' % randint(1, 8)
    FG_RED = '\x1b[31m'
    FG_YEL = '\x1b[33m'
    FG_GRE = '\x1b[32m'
    FG_MAG = '\x1b[35m'
    FG_CYA = '\x1b[36m'
    FG_BLU = '\x1b[34m'
    FG_RST = '\x1b[39m'
    ST_BRI = '\x1b[1m'
    ST_RST = '\x1b[0m'
else:
    FG_RND = ''
    FG_RED = ''
    FG_YEL = ''
    FG_GRE = ''
    FG_MAG = ''
    FG_CYA = ''
    FG_BLU = ''
    FG_RST = ''
    ST_BRI = ''
    ST_RST = ''


def p_cli(data):
    global args
    if args.format == 'cli':
        sys.stdout.write(data.encode('utf-8'))
        sys.stdout.flush()


def p_err(data):
    sys.stderr.write(path.basename(sys.argv[0]) + ': ' + data)
    sys.stderr.flush()


def p_csv(data):
    global args
    if args.format == 'csv':
        sys.stdout.write(data)


def p_json(data):
    global args
    if args.format == 'json':
        sys.stdout.write(data)


def bye(code):
    sys.stdout.write(FG_RST + ST_RST)
    sys.exit(code)


def sigint_handler(signal, frame):
    sys.stdout.write('\nStopping threads... ')
    sys.stdout.flush()
    for worker in threads:
        worker.stop()
    time.sleep(1)
    sys.stdout.write('Done\n')
    bye(0)


class UrlParser():

    def __init__(self, url):
        if '://' not in url:
            self.url = 'http://' + url
        else:
            self.url = url
        self.scheme = ''
        self.authority = ''
        self.domain = ''
        self.path = ''
        self.query = ''

        self.__parse()

    def __parse(self):
        re_rfc3986_enhanced = re.compile(
        r'''
        ^
        (?:(?P<scheme>[^:/?#\s]+):)?
        (?://(?P<authority>[^/?#\s]*))?
        (?P<path>[^?#\s]*)
        (?:\?(?P<query>[^#\s]*))?
        (?:\#(?P<fragment>[^\s]*))?
        $
        ''', re.MULTILINE | re.VERBOSE
        )

        m_uri = re_rfc3986_enhanced.match(self.url)

        if m_uri:
            if m_uri.group('scheme'):
                if m_uri.group('scheme').startswith('http'):
                    self.scheme = m_uri.group('scheme')
                else:
                    self.scheme = 'http'
            if m_uri.group('authority'):
                self.authority = m_uri.group('authority')
                self.domain = self.authority.split(':')[0].lower()
                if not self.__validate_domain(self.domain):
                    raise ValueError('Invalid domain name.')
            if m_uri.group('path'):
                self.path = m_uri.group('path')
            if m_uri.group('query'):
                if len(m_uri.group('query')):
                    self.query = '?' + m_uri.group('query')

    def __validate_domain(self, domain):
        if len(domain) > 255:
            return False
        if domain[-1] == '.':
            domain = domain[:-1]
        allowed = re.compile('\A([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\Z', re.IGNORECASE)
        return allowed.match(domain)

    def get_full_uri(self):
        return self.scheme + '://' + self.domain + self.path + self.query


class DomainFuzz():

    def __init__(self, domain):
        self.domain, self.tld = self.__domain_tld(domain)
        self.domains = []
        self.qwerty = {
        '1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7', '9': '0oi8', '0': 'po9',
        'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
        'a': 'qwsz', 's': 'edxzaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'ikmnhu', 'k': 'olmji', 'l': 'kop',
        'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
        }
        self.qwertz = {
        '1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7zt5', '7': '8uz6', '8': '9iu7', '9': '0oi8', '0': 'po9',
        'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6zgfr5', 'z': '7uhgt6', 'u': '8ijhz7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
        'a': 'qwsy', 's': 'edxyaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'zhbvft', 'h': 'ujnbgz', 'j': 'ikmnhu', 'k': 'olmji', 'l': 'kop',
        'y': 'asx', 'x': 'ysdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
        }
        self.azerty = {
        '1': '2a', '2': '3za1', '3': '4ez2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7', '9': '0oi8', '0': 'po9',
        'a': '2zq1', 'z': '3esqa2', 'e': '4rdsz3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0m',
        'q': 'zswa', 's': 'edxwqz', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'iknhu', 'k': 'olji', 'l': 'kopm', 'm': 'lp',
        'w': 'sxq', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhj'
        }
        self.keyboards = [ self.qwerty, self.qwertz, self.azerty ]

    def __domain_tld(self, domain):
        domain = domain.rsplit('.', 2)

        if len(domain) == 2:
            return domain[0], domain[1]

        if DB_TLD:
            cc_tld = {}
            re_tld = re.compile('^[a-z]{2,4}\.[a-z]{2}$', re.IGNORECASE)

            for line in open(FILE_TLD):
                line = line[:-1]
                if re_tld.match(line):
                    sld, tld = line.split('.')
                    if not tld in cc_tld:
                        cc_tld[tld] = []
                    cc_tld[tld].append(sld)

            sld_tld = cc_tld.get(domain[2])
            if sld_tld:
                if domain[1] in sld_tld:
                    return domain[0], domain[1] + '.' + domain[2]

        return domain[0] + '.' + domain[1], domain[2]

    def __validate_domain(self, domain):
        if len(domain) > 255:
            return False
        if domain[-1] == '.':
            domain = domain[:-1]
        allowed = re.compile('\A([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\Z', re.IGNORECASE)
        return allowed.match(domain)

    def __filter_domains(self):
        seen = set()
        filtered = []

        for d in self.domains:
            #if not self.__validate_domain(d['domain-name']):
                #p_err("debug: invalid domain %s\n" % d['domain-name'])
            if self.__validate_domain(d['domain-name']) and d['domain-name'] not in seen:
                seen.add(d['domain-name'])
                filtered.append(d)

        self.domains = filtered

    def __bitsquatting(self):
        result = []
        masks = [1, 2, 4, 8, 16, 32, 64, 128]
        for i in range(0, len(self.domain)):
            c = self.domain[i]
            for j in range(0, len(masks)):
                b = chr(ord(c) ^ masks[j])
                o = ord(b)
                if (o >= 48 and o <= 57) or (o >= 97 and o <= 122) or o == 45:
                    result.append(self.domain[:i] + b + self.domain[i+1:])

        return result

    def __homoglyph(self):
        glyphs = {
        'a': [u'à', u'á', u'â', u'ã', u'ä', u'å', u'ɑ', u'а', u'ạ', u'ǎ', u'ă', u'ȧ', u'ӓ'],
        'b': ['d', 'lb', 'ib', u'ʙ', u'Ь', u'b̔', u'ɓ', u'Б'],
        'c': [u'ϲ', u'с', u'ƈ', u'ċ', u'ć', u'ç'],
        'd': ['b', 'cl', 'dl', 'di', u'ԁ', u'ժ', u'ɗ', u'đ'],
        'e': [u'é', u'ê', u'ë', u'ē', u'ĕ', u'ě', u'ė', u'е', u'ẹ', u'ę', u'є', u'ϵ', u'ҽ'],
        'f': [u'Ϝ', u'ƒ', u'Ғ'],
        'g': ['q', u'ɢ', u'ɡ', u'Ԍ', u'Ԍ', u'ġ', u'ğ', u'ց', u'ǵ', u'ģ'],
        'h': ['lh', 'ih', u'һ', u'հ', u'Ꮒ', u'н'],
        'i': ['1', 'l', u'Ꭵ', u'í', u'ï', u'ı', u'ɩ', u'ι', u'ꙇ', u'ǐ', u'ĭ'],
        'j': [u'ј', u'ʝ', u'ϳ', u'ɉ'],
        'k': ['lk', 'ik', 'lc', u'κ', u'ⲕ', u'κ'],
        'l': ['1', 'i', u'ɫ', u'ł'],
        'm': ['n', 'nn', 'rn', 'rr', u'ṃ', u'ᴍ', u'м', u'ɱ'],
        'n': ['m', 'r', u'ń'],
        'o': ['0', u'Ο', u'ο', u'О', u'о', u'Օ', u'ȯ', u'ọ', u'ỏ', u'ơ', u'ó', u'ö', u'ӧ'],
        'p': [u'ρ', u'р', u'ƿ', u'Ϸ', u'Þ'],
        'q': ['g', u'զ', u'ԛ', u'գ', u'ʠ'],
        'r': [u'ʀ', u'Г', u'ᴦ', u'ɼ', u'ɽ'],
        's': [u'Ⴝ', u'Ꮪ', u'ʂ', u'ś', u'ѕ'],
        't': [u'τ', u'т', u'ţ'],
        'u': [u'μ', u'υ', u'Ս', u'ս', u'ц', u'ᴜ', u'ǔ', u'ŭ'],
        'v': [u'ѵ', u'ν', u'v̇'],
        'w': ['vv', u'ѡ', u'ա', u'ԝ'],
        'x': [u'х', u'ҳ', u'ẋ'],
        'y': [u'ʏ', u'γ', u'у', u'Ү', u'ý'],
        'z': [u'ʐ', u'ż', u'ź', u'ʐ', u'ᴢ']
        }

        result_1pass = set()

        for ws in range(1, len(self.domain)):
            for i in range(0, (len(self.domain)-ws)+1):
                win = self.domain[i:i+ws]
                j = 0
                while j < ws:
                    c = win[j]
                    if c in glyphs:
                        win_copy = win
                        for g in glyphs[c]:
                            win = win.replace(c, g)
                            result_1pass.add(self.domain[:i] + win + self.domain[i+ws:])
                            win = win_copy
                    j += 1

        result_2pass = set()

        for domain in result_1pass:
            for ws in range(1, len(domain)):
                for i in range(0, (len(domain)-ws)+1):
                    win = domain[i:i+ws]
                    j = 0
                    while j < ws:
                        c = win[j]
                        if c in glyphs:
                            win_copy = win
                            for g in glyphs[c]:
                                win = win.replace(c, g)
                                result_2pass.add(domain[:i] + win + domain[i+ws:])
                                win = win_copy
                        j += 1

        return list(result_2pass)

    def __hyphenation(self):
        result = []

        for i in range(1, len(self.domain)):
            result.append(self.domain[:i] + '-' + self.domain[i:])

        return result

    def __insertion(self):
        result = []

        for i in range(1, len(self.domain)-1):
            for keys in self.keyboards:
                if self.domain[i] in keys:
                    for c in keys[self.domain[i]]:
                        result.append(self.domain[:i] + c + self.domain[i] + self.domain[i+1:])
                        result.append(self.domain[:i] + self.domain[i] + c + self.domain[i+1:])

        return list(set(result))

    def __omission(self):
        result = []

        for i in range(0, len(self.domain)):
            result.append(self.domain[:i] + self.domain[i+1:])

        n = re.sub(r'(.)\1+', r'\1', self.domain)

        if n not in result and n != self.domain:
            result.append(n)

        return list(set(result))

    def __repetition(self):
        result = []

        for i in range(0, len(self.domain)):
            if self.domain[i].isalpha():
                result.append(self.domain[:i] + self.domain[i] + self.domain[i] + self.domain[i+1:])

        return list(set(result))

    def __replacement(self):
        result = []

        for i in range(0, len(self.domain)):
            for keys in self.keyboards:
                if self.domain[i] in keys:
                    for c in keys[self.domain[i]]:
                        result.append(self.domain[:i] + c + self.domain[i+1:])

        return list(set(result))

    def __subdomain(self):
        result = []

        for i in range(1, len(self.domain)):
            if self.domain[i] not in ['-', '.'] and self.domain[i-1] not in ['-', '.']:
                result.append(self.domain[:i] + '.' + self.domain[i:])

        return result

    def __transposition(self):
        result = []

        for i in range(0, len(self.domain)-1):
            if self.domain[i+1] != self.domain[i]:
                result.append(self.domain[:i] + self.domain[i+1] + self.domain[i] + self.domain[i+2:])

        return result

    def __vowel_swap(self):
        vowels = 'aeiou'
        result = []

        for i in range(0, len(self.domain)):
            for vowel in vowels:
                if self.domain[i] in vowels:
                    result.append(self.domain[:i] + vowel + self.domain[i+1:])

        return list(set(result))

    def __addition(self):
        result = []

        for i in range(97, 123):
            result.append(self.domain + chr(i))

        return result

    def generate(self):
        self.domains.append({ 'fuzzer': 'Original*', 'domain-name': self.domain + '.' + self.tld })

        for domain in self.__addition():
            self.domains.append({ 'fuzzer': 'Addition', 'domain-name': domain + '.' + self.tld })
        for domain in self.__bitsquatting():
            self.domains.append({ 'fuzzer': 'Bitsquatting', 'domain-name': domain + '.' + self.tld })
        for domain in self.__homoglyph():
            self.domains.append({ 'fuzzer': 'Homoglyph', 'domain-name': domain + '.' + self.tld })
        for domain in self.__hyphenation():
            self.domains.append({ 'fuzzer': 'Hyphenation', 'domain-name': domain + '.' + self.tld })
        for domain in self.__insertion():
            self.domains.append({ 'fuzzer': 'Insertion', 'domain-name': domain + '.' + self.tld })
        for domain in self.__omission():
            self.domains.append({ 'fuzzer': 'Omission', 'domain-name': domain + '.' + self.tld })
        for domain in self.__repetition():
            self.domains.append({ 'fuzzer': 'Repetition', 'domain-name': domain + '.' + self.tld })
        for domain in self.__replacement():
            self.domains.append({ 'fuzzer': 'Replacement', 'domain-name': domain + '.' + self.tld })
        for domain in self.__subdomain():
            self.domains.append({ 'fuzzer': 'Subdomain', 'domain-name': domain + '.' + self.tld })
        for domain in self.__transposition():
            self.domains.append({ 'fuzzer': 'Transposition', 'domain-name': domain + '.' + self.tld })
        for domain in self.__vowel_swap():
            self.domains.append({ 'fuzzer': 'Vowel-swap', 'domain-name': domain + '.' + self.tld })

        if '.' in self.tld:
            self.domains.append({ 'fuzzer': 'Various', 'domain-name': self.domain + '.' + self.tld.split('.')[-1] })
            self.domains.append({ 'fuzzer': 'Various', 'domain-name': self.domain + self.tld })
        if '.' not in self.tld:
            self.domains.append({ 'fuzzer': 'Various', 'domain-name': self.domain + self.tld + '.' + self.tld })
        if self.tld != 'com' and '.' not in self.tld:
            self.domains.append({ 'fuzzer': 'Various', 'domain-name': self.domain + '-' + self.tld + '.com' })

        self.__filter_domains()



class DomainThread(threading.Thread):

    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.jobs = queue
        self.kill_received = False

        self.ssdeep_orig = ''
        self.domain_orig = ''

        self.uri_scheme = 'http'
        self.uri_path = ''
        self.uri_query = ''

        self.option_extdns = False
        self.option_geoip = False
        self.option_whois = False
        self.option_ssdeep = False
        self.option_banners = False
        self.option_mxcheck = False

    

    def stop(self):
        self.kill_received = True

    @staticmethod
    def answer_to_list(answers):
        return sorted(list(map(lambda record: str(record).strip(".") if len(str(record).split(' ')) == 1 else str(record).split(' ')[1].strip('.'), answers)))

    def run(self):
        while not self.kill_received:
            domain = self.jobs.get()

            domain['domain-name'] = domain['domain-name'].encode('idna')

            if self.option_extdns:
                resolv = dns.resolver.Resolver()
                resolv.lifetime = REQUEST_TIMEOUT_DNS
                resolv.timeout = REQUEST_TIMEOUT_DNS
                if args.nameservers:
                    resolv.nameservers = args.nameservers.split(",")
                if args.port:
                    resolv.port = args.port
                try:
                    domain['dns-ns'] = self.answer_to_list(resolv.query(domain['domain-name'], 'NS'))
                except DNSException:
                    pass

                if 'dns-ns' in domain or len(domain['domain-name'].split('.')) > 1:
                    try:
                        domain['dns-a'] = self.answer_to_list(resolv.query(domain['domain-name'], 'A'))
                    except DNSException:
                        pass

                    try:
                        domain['dns-aaaa'] = self.answer_to_list(resolv.query(domain['domain-name'], 'AAAA'))
                    except DNSException:
                        pass

                    try:
                        domain['dns-mx'] = self.answer_to_list(resolv.query(domain['domain-name'], 'MX'))
                    except DNSException:
                        pass
            else:
                try:
                    ip = socket.getaddrinfo(domain['domain-name'], 80)
                except Exception:
                    pass
                else:
                    domain['dns-a'] = list()
                    domain['dns-aaaa'] = list()
                    for j in ip:
                        if '.' in j[4][0]:
                            domain['dns-a'].append(j[4][0])
                        if ':' in j[4][0]:
                            domain['dns-aaaa'].append(j[4][0])
                    domain['dns-a'] = sorted(domain['dns-a'])
                    domain['dns-aaaa'] = sorted(domain['dns-aaaa'])


            domain['domain-name'] = domain['domain-name'].decode('idna')

            self.jobs.task_done()

def one_or_all(answers):
    if args.all:
        result = ';'.join(answers)
    else:
        if len(answers):
            result = answers[0]
        else:
            result = ''
    return result



def generate_idle(domains):
    output = ''

    for domain in domains:
        output += '%s\n' % domain.get('domain-name').encode('idna')

    return output



def main():
    signal.signal(signal.SIGINT, sigint_handler)

    parser = argparse.ArgumentParser(
    add_help = True

    )

    parser.add_argument('domain', help='domain ')
    parser.add_argument('-f', '--format', type=str, choices=['idle'], default='idle', help='output format')


    if len(sys.argv) < 2:
        sys.stdout.write('%sdnstwist %s by <%s>%s\n\n' % (ST_BRI, __version__, __email__, ST_RST))
        parser.print_help()
        bye(0)

    global args
    args = parser.parse_args()


    args.threads = THREAD_COUNT_DEFAULT

    try:
        url = UrlParser(args.domain)
    except ValueError as err:
        p_err('error: %s\n' % err)
        bye(-1)

    dfuzz = DomainFuzz(url.domain)
    dfuzz.generate()
    domains = dfuzz.domains


    if args.format == 'idle':
        sys.stdout.write(generate_idle(domains))
        bye(0)

    jobs = queue.Queue()

    global threads
    threads = []

    for i in range(len(domains)):
        jobs.put(domains[i])

    for i in range(args.threads):
        worker = DomainThread(jobs)
        worker.setDaemon(True)

        worker.uri_scheme = url.scheme
        worker.uri_path = url.path
        worker.uri_query = url.query

        worker.domain_orig = url.domain


        worker.start()
        threads.append(worker)

    qperc = 0
    while not jobs.empty():
        p_cli('.')
        qcurr = 100 * (len(domains) - jobs.qsize()) / len(domains)
        if qcurr - 15 >= qperc:
            qperc = qcurr
            p_cli('%u%%' % qperc)
        time.sleep(1)

    for worker in threads:
        worker.stop()

    hits_total = sum('dns-ns' in d or 'dns-a' in d for d in domains)
    hits_percent = 100 * hits_total / len(domains)


    if domains:
        if args.format == 'csv':
            p_csv(generate_csv(domains))
        elif args.format == 'json':
            p_json(generate_json(domains))
        else:
            p_cli(generate_cli(domains))

    bye(0)


if __name__ == '__main__':
    main()
