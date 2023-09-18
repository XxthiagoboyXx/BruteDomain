import time

import requests
import argparse
import threading
from enum import Enum
from collections import defaultdict

output_info = []
#output_info = defaultdict(list)
hosts = set()
domains = []
wordlist_global = []
wordlists_specific = []
wordlist_subdomains = []

subdomains = []

VERBOSITY = True


class Color(Enum):
    GREEN = "1;32;40"
    RED = "1;31;40"
    BLUE = "1;34;40"
    BROWN = "0;33;40"
    YELLOW = "1;33;40"
    GREY = "1;30;47"

def print_color(text, color):
    print(f"\033[{color.value}m{text}\033[m")


def handle_threads():
    print('domainsssss: ', domains)
    print('wordlist_globalalal: ', wordlist_global)

    threads = []
    num_threads = min(len(domains), threading.active_count())
    print(f'Threads used: {num_threads}')

    if args.brute_subdomains or args.brute_subdomains_pages:
        for domain in domains:
            thread = threading.Thread(target=check_subdomains, args=(domain,))
            threads.append(thread)

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()
        threads = []

    if args.wordlist_global_pages or args.wordlist_specific_pages:
        for domain in domains:
            thread = threading.Thread(target=check_response_not_404, args=(domain,))
            threads.append(thread)

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()


def check_subdomains(domain):
    global output_info

    for word in wordlist_subdomains:
        full_path = f'https://{word}.{domain}'
        try:
            response = requests.get(full_path)
            response.raise_for_status()
            if VERBOSITY:
                print(f'{full_path}, Status: {response.status_code}')
            if response.status_code != 404:
                print_color(f'[+] Page found -> {full_path}', Color.GREEN)
                output_info.append(full_path)
            print('aquiii')
            subdomains.append(full_path)
        except requests.exceptions.RequestException as re:
            str_exception = str(re)
            if VERBOSITY:
                if 'Not Found' in str_exception or '404' in str_exception:
                    print_color(f'[-] Not found -> {full_path}', Color.RED)
                    #output_info[domain].append(full_path)
                elif 'Failed to resolve \'' in str_exception:
                    unresolved_host = str_exception.split('Failed to resolve \'')[1].split('\'')[0]
                    print_color(f'[++] New third-party host -> {unresolved_host}', Color.BLUE)

                    #output_info.append(full_path)
                    #output_info.append(unresolved_host)
                    #output_info['unresolved_hosts'].add(unresolved_host)
                    #output_info['unresolved_hosts'].append(unresolved_host)
                else:
                    print(f'EXCEPTION: {re}')
                    subdomains.append(full_path)
            else:
                if 'Failed to resolve Found' in str_exception:
                    unresolved_host = str_exception.split('Failed to resolve \'')[1].split('\'')[0]
                    print_color(f'[++] New third-party host -> {unresolved_host}', Color.BROWN)
                    output_info.append(full_path)
                    output_info.append(unresolved_host)
                    #output_info['unresolved_hosts'].add(unresolved_host)
                    #output_info['unresolved_hosts'].append(unresolved_host)


        time.sleep(0.2)

def check_response_not_404(domain):

    global output_info

    for word in wordlist_global:
        full_path = f'https://{domain}/{word}'
        try:
            response = requests.get(full_path)
            response.raise_for_status()
            if VERBOSITY:
                print(f'{full_path}, Status: {response.status_code}')
            if response.status_code != 404:
                print_color(f'[+] Page found -> {full_path}', Color.GREEN)
                output_info.append(full_path)
        except requests.exceptions.RequestException as re:
            str_exception = str(re)
            if VERBOSITY:
                if 'Not Found' in str_exception or '404' in str_exception:
                    print_color(f'[-] Not found -> {full_path}', Color.RED)
                    #output_info[domain].append(full_path)
                elif 'Failed to resolve \'' in str_exception:
                    unresolved_host = str_exception.split('Failed to resolve \'')[1].split('\'')[0]
                    print_color(f'[++] New third-party host -> {unresolved_host}', Color.BROWN)
                    output_info.append(full_path)
                    output_info.append(unresolved_host)
                    #output_info['unresolved_hosts'].add(unresolved_host)
                    #output_info['unresolved_hosts'].append(unresolved_host)
                else:
                    print(f'EXCEPTION: {re}')
            else:
                if 'Failed to resolve Found' in str_exception:
                    unresolved_host = str_exception.split('Failed to resolve \'')[1].split('\'')[0]
                    print_color(f'[++] New third-party host -> {unresolved_host}', Color.BROWN)
                    output_info.append(full_path)
                    output_info.append(unresolved_host)
                    #output_info['unresolved_hosts'].add(unresolved_host)
                    #output_info['unresolved_hosts'].append(unresolved_host)


        time.sleep(0.2)

def manipulate_files():
    #if args.subd

    global domains
    global wordlist_global
    global wordlists_specific

    if args.domain_list:
        with open(args.domain_list, 'r') as file:
            domains = file.readlines()

        domains = [domain.strip() for domain in domains]
        print(f'os domínios: {domains}')

    if args.wordlist_global_pages:
        with open(args.wordlist_global_pages, 'r') as file:
            wordlist_global = file.readlines()

        wordlist_global = [word.strip() for word in wordlist_global]
        print(f'os diretorios: {wordlist_global}')

def main():
    manipulate_files()

    handle_threads()
    # check_reponse_person() #one domainlist and one wordlist
    #check_response_not_404()

    print(output_info)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A tool to assist in discovering subdomains and directories in a pentest')
    parser.add_argument('-dL', '--domain-list', required=True, help='File domains Path')
    parser.add_argument('-wG', '--wordlist-global-pages', required=False, help='File Wordlist Path: used to all domains lists')
    parser.add_argument('-wS', '--wordlist-specific-pages', required=False, help='File Wordlist Path: used for the respective domain. Example: -dL domains1.txt domains2.txt -wS wordlist_to_d1.txt wordlist_to_d2.txt')
    #parser.add_argument('-sF', '--subdomain-finder', required=False,
                        #help='File Wordlist Subdomain Path: used to all domains lists')
    parser.add_argument('-bS', '--brute-subdomains', required=False, help='File Wordlist Subdomains: search only subdomains.') #procurar páginas para os subdomínios encontrados (automáticamente utiliza a tag -sF)
    parser.add_argument('-bSP', '--brute-subdomains-pages', required=False,
                        help='File Wordlist Subdomains: search subdomains and pages for the found subdomains (automatically uses the -bS tag).')  # procurar páginas para os subdomínios encontrados (automáticamente utiliza a tag -sF)

    args = parser.parse_args(
        ['-dL', 'domains.txt',
         '-wG', 'wordlist.txt',
         '-bS', 'wordlist.txt'
         ]
    )
    '''
    try:
        response = requests.get(f'https://aaaaa.globo.com')
        response.raise_for_status()

        print(f'Status: {response.status_code}')
        #if response.status_code != 404:
        #    print_color(f'[+] Page found -> {full_path}', Color.GREEN)
        #    output_info.append(full_path)
    except requests.exceptions.RequestException as re:
        str_exception = str(re)
        print(re)
    exit()
    '''

    main()