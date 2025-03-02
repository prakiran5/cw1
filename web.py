import tkinter as tk 

from tkinter import scrolledtext, messagebox 

from colorama import Fore, Style 

import requests 

import re 

import sys 

from datetime import datetime 

def is_valid_url(url): 

regex = re.compile( 
 
    r'^(?:http|ftp)s?://'  # http:// or https:// 
 
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain... 
 
    r'localhost|'  # localhost 
 
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ip 
 
    r'(?::\d+)?'  # optional port 
 
    r'(?:/?|[/?]\S+)$', re.IGNORECASE) 
 
return re.match(regex, url) is not None 
  

def lil_nikto_scan(url, output_text): 

try: 
 
    if is_valid_url(url): 
 
        response = requests.get(url) 
 
    else: 
 
        output_text.insert(tk.END, f"{Fore.RED}[!] Incorrect url format{Style.RESET_ALL}\n") 
 
        return 
 
except requests.exceptions.RequestException as e: 
 
    output_text.insert(tk.END, f"{Fore.RED}[!] Error while operating : {e}{Style.RESET_ALL}\n") 
 
    return 
 
 
 
server = response.headers.get("Server") 
 
x_powered_by = response.headers.get("X-Powered-By") 
 
 
 
if server is not None: 
 
    output_text.insert(tk.END, f"{Fore.GREEN}[+] Webserver: {server}{Style.RESET_ALL}\n") 
 
if x_powered_by is not None: 
 
    output_text.insert(tk.END, f"{Fore.GREEN}[+] Webserver uses:  {x_powered_by}{Style.RESET_ALL}\n") 
 
 
 
if "Content-Encoding" in response.headers: 
 
    output_text.insert(tk.END, f"{Fore.YELLOW}[-] The server supports compression{Style.RESET_ALL}\n") 
 
else: 
 
    output_text.insert(tk.END, f"{Fore.YELLOW}[-] The server doesn't support compression{Style.RESET_ALL}\n") 
 
 
 
if "Content-Type" in response.headers: 
 
    ct = response.headers.get("Content-Type") 
 
    output_text.insert(tk.END, f"{Fore.YELLOW}[-] Content-Type found: {ct}{Style.RESET_ALL}\n") 
 
 
 
version_regex = re.compile(r"\d+\.\d+(\.\d+)?") 
 
for header in response.headers: 
 
    match = version_regex.search(response.headers[header]) 
 
    if match: 
 
        output_text.insert(tk.END, f"{Fore.GREEN}[+] Version found : {match.group(0)} {Style.RESET_ALL}\n") 
 
 
 
if response.status_code in [301, 302]: 
 
    loca_header = response.headers.get("Location") 
 
    output_text.insert(tk.END, f"{Fore.GREEN}[+] Target URL uses redirection towards : {loca_header}{Style.RESET_ALL}\n") 
 
else: 
 
    output_text.insert(tk.END, f"{Fore.YELLOW}[-] Target URL don't use any redirection{Style.RESET_ALL}\n") 
 
 
 
if response.status_code == 401: 
 
    output_text.insert(tk.END, f"{Fore.YELLOW}[-] Target URL is protected by a basic HTTP authentication{Style.RESET_ALL}\n") 
 
else: 
 
    output_text.insert(tk.END, f"{Fore.YELLOW}[-] Target URL isn't protected by a basic HTTP authentication{Style.RESET_ALL}\n") 
  

def scan_url(): 

url = url_entry.get() 
 
if not url: 
 
    messagebox.showwarning("Input Error", "Please enter a URL to scan") 
 
    return 
 
 
 
if not is_valid_url(url): 
 
    messagebox.showerror("Invalid URL", "Invalid URL format entered.") 
 
    return 
 
 
 
output_text.delete(1.0, tk.END) 
 
output_text.insert(tk.END, f"Scanning: {url}\n") 
 
output_text.insert(tk.END, f"Started at: {datetime.now()}\n") 
 
output_text.insert(tk.END, "-" * 60 + "\n") 
 
lil_nikto_scan(url, output_text) 
  

Create main window 

root = tk.Tk() 

root.title("Web Vulnerability Scanner") 

root.geometry("800x600") 

URL input section 

url_label = tk.Label(root, text="Enter URL:") 

url_label.pack(pady=10) 

url_entry = tk.Entry(root, width=60) 

url_entry.pack(pady=10) 

scan_button = tk.Button(root, text="Scan URL", width=20, command=scan_url) 

scan_button.pack(pady=20) 

ScrolledText for output 

output_text = scrolledtext.ScrolledText(root, width=90, height=20) 

output_text.pack(padx=10, pady=10) 

Run the application 

root.mainloop() 

 
