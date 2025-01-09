#!/bin/bash

# Set variables
domain=$1
subdomain_file="subdomains.txt"
alive_subdomains_file="subdomains_alive.txt"
all_urls_file="allurls.txt"
js_files="js.txt"
final_report="final_report.txt"

# Subdomain discovery
echo "[*] Running subfinder for $domain..."
subfinder -d $domain -all -recursive -o $subdomain_file

# Check alive subdomains
echo "[*] Checking alive subdomains..."
cat $subdomain_file | ./go/bin/httpx -silent -ports 80,443,8080,8000,8888 -threads 200 -o $alive_subdomains_file

# Crawl URLs
echo "[*] Crawling URLs with katana..."
./go/bin/katana -u $alive_subdomains_file -d 6 -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o $all_urls_file

# Grep sensitive files
echo "[*] Grepping for sensitive files..."
grep -E "\.txt|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.json|\.gz|\.rar|\.zip|\.config" $all_urls_file > sensitive_files.txt

# Grep JS files
echo "[*] Grepping for JS files..."
grep -E "\.js$" $all_urls_file > $js_files

# JS files analysis
echo "[*] Analyzing JS files with nuclei..."
./go/bin/nuclei -up
cat $js_files | ./go/bin/nuclei -t ~/nuclei-templates/http/exposures/

# XSS scanning
echo "[*] Scanning for XSS..."
echo $domain | ./go/bin/katana -ps | grep -E "\.js$" | ./go/bin/nuclei -t ~/nuclei-templates/http/exposures/ -c 30

# Scan for configurations
echo "[*] Running dirsearch for configurations..."
dirsearch -u $domain -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,py,rb,php,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,lock,log,rar,sql.gz,sql.zip,tar,tar.bz2,tar.gz,txt,wadl,zip,.log,.xml,.js,.json --random-agent --recursive -R 3 -t 20 --exclude-status=404 --follow-redirects --delay=0.1

# Subdomain takeover
echo "[*] Checking for subdomain takeover..."
subzy run --targets $subdomain_file --concurrency 100 --hide_fails --verify_ssl

# CORS misconfigurations
echo "[*] Checking for CORS misconfigurations..."
python3 corsy.py -i $alive_subdomains_file -t 10 --headers "User-Agent: GoogleBot\nCookie: SESSION=Hacked"

# Vulnerability scanning with nuclei
echo "[*] Running nuclei for vulnerability scanning..."
./go/bin/nuclei -list $alive_subdomains_file -t ~/nuclei-templates/
./go/bin/nuclei -list $alive_subdomains_file -tags cves,osint,tech
cat $all_urls_file | gf lfi | ./go/bin/nuclei -tags lfi
#cat $all_urls_file | gf redirect | openredirex -p ~/openRedirect

# Generate final report
echo "[*] Generating final report..."
cat sensitive_files.txt >> $final_report
cat $js_files >> $final_report
echo "[*] Bug hunting completed. Check $final_report for results."
