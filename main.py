import socket
import whois
import requests
import nmap
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from bs4 import BeautifulSoup
import validators
 
 
# Function to browse for subdomain wordlist
def browse_wordlist():
   global wordlist_path
   wordlist_path = filedialog.askopenfilename(title="Select Subdomain Wordlist")
   if wordlist_path:
       output_text.insert(tk.END, f"Selected wordlist: {wordlist_path}\n")
 
 
# Function to start the scan in a new thread
def start_scan_thread():
   thread = threading.Thread(target=start_scan)
   thread.start()
 
 
# Function to start the scan process
def start_scan():
   domain = domain_entry.get()
   if not domain:
       messagebox.showwarning("Input Error", "Please enter a domain.")
       return
 
 
   output_text.insert(tk.END, f"Starting scan for {domain}...\n")
 
 
   # Get the IP address
   try:
       ip = socket.gethostbyname(domain)
       output_text.insert(tk.END, f"IP Address of {domain}: {ip}\n")
   except Exception as e:
       output_text.insert(tk.END, f"Error: Could not retrieve IP for {domain}: {e}\n")
       return
 
 
   # WHOIS Information
   output_text.insert(tk.END, f"\nFetching WHOIS information for {domain}...\n")
   try:
       domain_info = whois.whois(domain)
       output_text.insert(tk.END, f"{domain_info}\n")
   except Exception as e:
       output_text.insert(tk.END, f"Error: Could not retrieve WHOIS information: {e}\n")
 
 
   # Subdomain Enumeration
   if wordlist_path:
       output_text.insert(tk.END, "\nEnumerating subdomains...\n")
       enumerate_subdomains(domain, wordlist_path)
 
 
   # Web Technology Fingerprinting (Alternative)
   output_text.insert(tk.END, "\nFingerprinting web technologies...\n")
   fingerprint_web_technologies(domain)
 
 
   # XSS Detection
   output_text.insert(tk.END, "\nDetecting XSS vulnerabilities...\n")
   detect_xss(domain)
 
 
   # Open Redirect Detection
   output_text.insert(tk.END, "\nDetecting Open Redirect vulnerabilities...\n")
   detect_open_redirect(domain)
 
 
   # OS Fingerprinting and Service Detection
   output_text.insert(tk.END, "\nRunning OS and service detection...\n")
   os_fingerprinting(ip)
 
 
# Function to enumerate subdomains
def enumerate_subdomains(domain, wordlist_path):
   with open(wordlist_path, 'r') as file:
       subdomains = file.read().splitlines()
 
 
   for subdomain in subdomains:
       url = f"http://{subdomain}.{domain}"
 
 
       # Validate the URL before making the request
       if not validators.url(url):
           output_text.insert(tk.END, f"Invalid URL: {url}\n")
           continue
 
 
       try:
           response = requests.get(url)
           if response.status_code == 200:
               output_text.insert(tk.END, f"Found subdomain: {url}\n")
           else:
               output_text.insert(tk.END, f"No subdomain found at: {url} (Status code: {response.status_code})\n")
       except requests.ConnectionError:
           output_text.insert(tk.END, f"Connection error: Could not connect to {url}\n")
       except requests.exceptions.InvalidURL:
           output_text.insert(tk.END, f"Error: Invalid URL detected for {url}\n")
       except Exception as e:
           output_text.insert(tk.END, f"Unexpected error with {url}: {e}\n")
 
 
# Function to fingerprint web technologies (Alternative Approach)
def fingerprint_web_technologies(domain):
   try:
       url = f"http://{domain}"
       response = requests.get(url)
 
 
       # Check headers for web technologies
       server = response.headers.get('Server')
       x_powered_by = response.headers.get('X-Powered-By')
       set_cookie = response.headers.get('Set-Cookie')
 
 
       output_text.insert(tk.END, f"Server: {server}\n")
       output_text.insert(tk.END, f"X-Powered-By: {x_powered_by}\n")
 
 
       # Simple check for popular CMS by cookies
       if set_cookie:
           if "wp" in set_cookie.lower():
               output_text.insert(tk.END, "Detected CMS: WordPress\n")
           elif "drupal" in set_cookie.lower():
               output_text.insert(tk.END, "Detected CMS: Drupal\n")
           elif "joomla" in set_cookie.lower():
               output_text.insert(tk.END, "Detected CMS: Joomla\n")
 
 
       # Parsing HTML to detect common meta tags or scripts
       soup = BeautifulSoup(response.text, 'html.parser')
       if soup.find("meta", {"name": "generator"}):
           generator = soup.find("meta", {"name": "generator"})['content']
           output_text.insert(tk.END, f"Detected by meta generator tag: {generator}\n")
 
 
   except Exception as e:
       output_text.insert(tk.END, f"Error: Could not fingerprint technologies: {e}\n")
 
 
# Function to detect XSS vulnerability
def detect_xss(domain):
   xss_payload = "<script>alert('XSS')</script>"
   test_url = f"http://{domain}/?q={xss_payload}"
   try:
       response = requests.get(test_url)
       if xss_payload in response.text:
           output_text.insert(tk.END, f"Potential XSS vulnerability found at {test_url}\n")
       else:
           output_text.insert(tk.END, f"No XSS vulnerability detected at {test_url}\n")
   except Exception as e:
       output_text.insert(tk.END, f"Error testing XSS: {e}\n")
 
 
# Function to detect open redirect vulnerability
def detect_open_redirect(domain):
   open_redirect_payload = "http://evil.com"
   test_url = f"http://{domain}/?redirect={open_redirect_payload}"
   try:
       response = requests.get(test_url, allow_redirects=False)
       if response.status_code == 302 and response.headers.get('Location') == open_redirect_payload:
           output_text.insert(tk.END, f"Potential Open Redirect vulnerability found at {test_url}\n")
       else:
           output_text.insert(tk.END, f"No Open Redirect vulnerability detected at {test_url}\n")
   except Exception as e:
       output_text.insert(tk.END, f"Error testing Open Redirect: {e}\n")
 
 
 
 
# Function to perform OS fingerprinting and service detection
def os_fingerprinting(ip):
   try:
       scanner = nmap.PortScanner()
       scan_result = scanner.scan(ip, arguments='-O')
       os_fingerprint = scan_result['scan'][ip].get('osmatch', [])
       for os_info in os_fingerprint:
           output_text.insert(tk.END, f"Detected OS: {os_info['name']} - Accuracy: {os_info['accuracy']}%\n")
   except Exception as e:
       output_text.insert(tk.END, f"Error during OS fingerprinting: {e}\n")
 
 
 
 
# Main GUI setup
root = tk.Tk()
root.title("Reconnaissance and Vulnerability Scanner - The Pycodes")
 
 
# GUI Elements
domain_label = tk.Label(root, text="Enter the Domain:")
domain_label.pack()
 
 
domain_entry = tk.Entry(root, width=50)
domain_entry.pack()
 
 
subdomain_label = tk.Label(root, text="Select Subdomain Wordlist:")
subdomain_label.pack()
 
 
subdomain_button = tk.Button(root, text="Browse", command=browse_wordlist)
subdomain_button.pack()
 
 
scan_button = tk.Button(root, text="Start Scan", command=start_scan_thread)
scan_button.pack()
 
 
# Adding the scrolled text widget for output with a scrollbar
output_text = scrolledtext.ScrolledText(root, height=20, width=80, wrap=tk.WORD)
output_text.pack()
 
 
# Global variable to store file path for subdomain wordlist
wordlist_path = None
 
 
# Run the GUI loop
root.mainloop()
