#----- AWS -------

s3ls(){
aws s3 ls s3://$1
}

s3cp(){
aws s3 cp $2 s3://$1 
}

#---- Content discovery ----
thewadl(){ #this grabs endpoints from a application.wadl and puts them in yahooapi.txt
curl -s $1 | grep path | sed -n "s/.*resource path=\"\(.*\)\".*/\1/p" | tee -a ~/tools/dirsearch/db/yahooapi.txt
}

#----- recon -----
crtndstry(){
./tools/crtndstry/crtndstry $1
}

#runs amass passively and saves to json
am(){ 
amass enum --passive -d $1 -json $1.json
jq .name $1.json | sed "s/\"//g"| httprobe -c 60 | tee -a $1-domains.txt
}

#runs httprobe on all the hosts from certspotter
certprobe(){ 
curl -s https://crt.sh/\?q\=\%.$1\&output\=json | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | httprobe | tee -a ./all.txt
}

mscan(){ #runs masscan
sudo masscan -p4443,2075,2076,6443,3868,3366,8443,8080,9443,9091,3000,8000,5900,8081,6000,10000,8181,3306,5000,4000,8888,5432,15672,9999,161,4044,7077,4040,9000,8089,443,744$}
}

certspotter(){ 
curl -s https://certspotter.com/api/v0/certs\?domain\=$1 | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u | grep $1
} #h/t Michiel Prins

crtsh(){
curl -s https://crt.sh/?Identity=%.$1 | grep ">*.$1" | sed 's/<[/]*[TB][DR]>/\n/g' | grep -vE "<|^[\*]*[\.]*$1" | sort -u | awk 'NF'
}

certnmap(){
curl https://certspotter.com/api/v0/certs\?domain\=$1 | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u | grep $1  | nmap -T5 -Pn -sS -i - -$
} #h/t Jobert Abma

ipinfo(){
curl http://ipinfo.io/$1
}


#------ Tools ------
dirsearch(){ #runs dirsearch and takes host and extension as arguments
python3 ~/tools/dirsearch/dirsearch.py -u $1 -e $2 -t 50 -b 
}

sqlmap(){
python ~/tools/sqlmap*/sqlmap.py -u $1 
}

ncx(){
nc -l -n -vv -p $1 -k
}

crtshdirsearch(){ #gets all domains from crtsh, runs httprobe and then dir bruteforcers
curl -s https://crt.sh/?q\=%.$1\&output\=json | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | httprobe -c 50 | grep https | xargs -n1 -I{} python3 ~/tools/dirsearch/dirsearch.py -u {} -e $2 -t 50 -b 
}

tlds(){
value=$(echo $1|cut -f1 -d.)
echo $value
sed -e "s/^/$value./" ~/tools/dnscan/tlds.txt | filter-resolved
}

urlscanio(){
  path=$(pwd)
  cd $path
  echo "Running urlscanio"
  gron "https://urlscan.io/api/v1/search/?q=domain:$1"  | grep 'url' | gron --ungron | tee $1urlio.txt
  echo "done"
}

substakeover() {
subfinder -d $1 >> hosts | assetfinder -subs-only $1 >> hosts | amass enum -norecursive -noalts -d $1 >> hosts | subjack -w hosts -t 100 -timeout 30 -ssl -c ~/subjack/fingerprints.json -v 3 >> takeover 
}

#check known subs for takeovers
checkcnames(){
	while read sub;do
		host -t CNAME "$domain" | grep 'alias for' | awk '{print $NF}' |
		while read cname; do
			if ! host "$cname" &> /dev/null; then
				"echo "$cname" doesn't resolve ($domain)"
			fi
		done
	done
}

#brute subs and check cnames
brutecnames(){
	domain=$1
	while read sub;do
		host -t CNAME "$sub.$domain" | grep 'alias for' | awk '{print $NF}' |
		while read cname; do
			if ! host "$cname" &> /dev/null; then
				"echo "$cname" doesn't resolve ($sub.$domain)"
			fi
		done
	done
}

visualRecon(){
	path=$(pwd)
	cd $path
	mkdir visual && cd "$_"
	python ~/tools/Sublist3r/sublist3r.py -d $1 -t 100 -v -o subs.txt
	assetfinder --subs-only $1 --threads 100 >> subs.txt
	cat subs.txt | sort -u -o subs.txt
	cat subs.txt | httprobe | aquatone -chrome-path /snap/bin/chromium -out aqua_out -silent
	echo "Done"

}

bruteD(){
	domain=$1
	while read sub; do
		if host "$sub.$domain" &> /dev/null; then
			echo "$sub.$domain"
		fi
	done
}

#grep -HnroiE '<title>(.*)</title>'
fetchAll(){
	path=$(pwd)
	cd $path
	mkdir -p allThings

	while read url; do
		filename=$(echo "$url" | md5sum | awk '{print $1}')
		filename="allThings/filename"
		curl -sk "$url" -o "$filename" &> /dev/null
		echo "$filename $url" >> index
	done
}

Blc() {
subfinder -d $1 | httprobe | waybackurls | egrep -iv ".(jpg|gif|css|png|woff|pdf|svg|js)" | burl | tee brokenlink.txt
}

fastRecon(){
	path=$(pwd)
	cd $path
	echo "create unique folders"
	mkdir $1; cd $1; mkdir screens;

	echo "#enumerating subdomains"
	subfinder -d $1 -silent -t 30 -o $1_domains;

	echo "#Fast port scanning"
	#naabu -hL $1_domains -silent -t 30 -o $1_ports;
	sudo ~/go/bin/naabu -hL $1_domains  -t 30 -o $1_ports

	echo "# find web servers on open ports"
	cat $1_ports | httprobe -c 30 > $1_schemes;

	echo "#scan for subdomains takeover"
	nuclei -c 30 -t ~/tools/nuclei-templates/subdomain-takeover/detect-all-takeovers.yaml -silent -o $1_takeovers -l $1_schemes;

	echo "# Get ips and cnames"
	dnsprobe -l $1_domains -o  $1_ips -silent;
	dnsprobe -l $1_domains -r CNAME -o $1_cnames -silent;

	echo "#Taking screenshot"
	gowitness file --source $1_schemes -d ./screens/ -chrome-path /snap/bin/chromium
	gowitness report generate;  

}