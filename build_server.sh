#!/bin/bash
while true
do
    read -p "please input httpdns server port number: " server_port
    [[ $server_port -le 65535 && $server_port -gt 0 ]] && break
    echo "please input port number 1-65535"
done
read -p "please input upper ip(default is 114.114.114.114): " upperip

cd
yum -y update && PM=yum || apt-get -y update && PM=apt-get || exec echo "not support OS."
$PM -y install gcc curl psmisc
curl -O -k https://raw.githubusercontent.com/mmmdbybyd/httpDNS/master/http-dns-server.c || \
exec echo "download source code failed."
gcc -o httpdns -O3 http-dns-server.c || exec echo "compiled failed."
strip httpdns
rm -f http-dns-server.c
echo "
while true
do
    cd /etc
    curl -k https://raw.githubusercontent.com/sy618/hosts/master/FQ >_hosts
    curl -k https://raw.githubusercontent.com/vokins/yhosts/master/hosts >>_hosts
    curl -k https://raw.githubusercontent.com/sy618/hosts/master/p >>_hosts
    curl -k https://raw.githubusercontent.com/sy618/hosts/master/y >>_hosts
    killall -q -9 httpdns
    cd
    ./httpdns -l $server_port -H /etc/_hosts -u ${upperip:-114.114.114.114}
    sleep 86400 #a day
done
" >updatehosts.sh
chmod +x updatehosts.sh
nohup ./updatehosts.sh &>/dev/null &
ps -A | grep -q httpdns && echo "success." || echo "failed."
