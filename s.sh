#!/bin/bash
hihyV="0.4.2.a"
function echoColor() {
        case $1 in
                # red
        "red")
                echo -e "\033[31m${printN}$2 \033[0m"
                ;;
                # sky blue
        "skyBlue")
                echo -e "\033[1;36m${printN}$2 \033[0m"
                ;;
                # green
        "green")
                echo -e "\033[32m${printN}$2 \033[ 0m"
                ;;
                # white
        "white")
                echo -e "\033[37m${printN}$2 \033[0m"
                ;;
        "magenta")
                echo -e "\033[31m${printN}$2 \033[ 0m"
                ;;
                # yellow
        "yellow")
                echo -e "\033[33m${printN}$2 \033[0m"
                ;;
        # purple
    "purple")
        echo -e "\033[1;;35m${printN }$2 \033[0m"
        ;;
        #
    "yellowBlack")
        # Yellow text on black
        echo -e "\033[1;33;40m${printN}$2 \033[0m"
        ;;
        "greenWhite")
                # Green background white text
                echo -e "\033[42;37m${printN}$2 \033[0m"
                ;;
        esac
}

function checkSystemForUpdate() {
        if [[ -n $(find /etc -name "redhat-release") ]] || grep </proc/version -q -i "centos"; then
                mkdir -p /etc/yum.repos.d

                if [[ -f "/etc/centos-release" ]]; then
                        centosVersion=$(rpm -q centos-release | awk -F "[-]" '{print $3}' | awk -F "[.]" '{print $1}')

                        if [[ -z "${centosVersion}" ]] && grep </etc/centos-release -q -i "release 8"; then
                                centosVersion=8
                        fi
                fi

                release="centos"
                inst allType='yum -y -q install'
                removeType='yum -y -q remove'
                upgrade="yum update -y --skip-broken"

        elif grep </etc/issue -q -i "debian" && [[ -f "/etc/issue" ]] || grep </etc/issue -q -i "debian" && [[ -f "/proc/version" ]]; then
                release="debian"
                installType='apt - y -q install'
                upgrade="apt update"
                updateReleaseInfoChange='apt-get --allow-releaseinfo-change update'
                removeType='apt -y -q autoremove'

        elif grep </etc/issue -q -i "ubuntu" && [[ -f "/etc/issue" ]] || grep </etc/issue -q -i "ubuntu" && [[ -f "/proc/version" ]]; then
                release="ubuntu"
                installType= 'apt -y -q install'
                upgrade="apt update"
                updateReleaseInfoChange='apt-get --allow-releaseinfo-change update'
                removeType='apt -y -q autoremove'
                if grep </etc/issue -q -i "16."; then
                        release=
                fi
        fi

        if [[ -z ${release} ]]; then
                echoColor red "\nThis script does not support this system, please feedback the log below to the developer\n"
                echoColor yellow "$ (cat /etc/issue)"
                echoColor yellow "$(cat /proc/version)"
                exit 0
        fi
    echoColor purple "\nUpdate.wait..."
    ${upgrade}
    echoColor purple "\nDone.\nInstall wget curl lsof"
        echoColor green "*wget"
        if ! [ -x "$(command -v wget)" ]; then
                ${installType} "wget"
        else
                echoColor purple 'Installed.Ignore.' >&2
        fi
        echoColor green "*curl "
        if ! [ -x "$(command -v curl)" ]; then
                ${installType} "curl"
        else
                echoColor purple 'Installed.Ignore.' >&2
        fi
        echoColor green "*lsof"
        if ! [ -x "$ (command -v lsof)" ]; then
                ${installType} "lsof"
        else
                echoColor purple 'Installed.Ignore.' >&2
        fi
    echoColor purple "\nDone."
    
}

function uninstall(){
    bash <(curl -fsSL https://git.io/rmhysteria.sh)
}

function reinstall(){
    bash <(curl -fsSL https://git.io/rehysteria.sh)
}

function printMsg(){
        cp -P /etc/hihy/result/hihyClient.json ./config.json
        cp -P /etc/hihy/result/metaHys.yaml ./metaHys.yaml
        echo ""
        echoColor purple "1* [v2rayN /nekoray/hihy_cmd] Use hysteria core to directly run "
        echoColor green " client configuration file output to: `pwd`/config.json (directly download the generated configuration file [recommended] / copy and paste the configuration below to local)"
        echoColor green "Tips: The client only enables http(8888) and socks5(8889) proxies by default! For other methods, please refer to the hysteria documentation to modify the client config.json"
        echoColor purple "↓************* ************************↓↓↓copy↓↓↓************************ **********↓"
        cat ./config.json
        echoColor purple "↑**************************** ******↑↑↑copy↑↑↑************************************↑\n"
        url =`cat /etc/hihy/result/url.txt`
        echoColor purple "2* [Shadowrocket/Sagernet/Passwall] One-click link:"
        echoColor green ${url}
        echo -e "\n"
        echoColor purple "3* [ Clash.Meta] Recommended! The configuration file has been output in `pwd`/metaHys.yaml, please download it to the client to use (beta)"
}

function hihy(){
        if [ ! -f "/usr/bin/hihy" ]; then
                  wget -q -O /usr/bin/hihy --no-check-certificate https://raw.githubusercontent.com/emptysuns/Hi_Hysteria/main/server/install.sh
                chmod +x /usr/bin/hihy
        fi        
}

function changeIp64(){
    if [ ! -f "/etc/hihy/conf/hihyServer.json" ]; then
                  echoColor red "Hihy is not installed normally!"
        exit
        fi 
        now=`cat /etc/hihy/conf/hihyServer.json | grep "resolve_preference"`
    case ${now} in 
                *"64"*)
                        echoColor purple "Current ipv6 priority"
            echoColor yellow " -> set ipv4 priority higher than ipv6?(Y/N, default N)"
            read input
            if [ -z "${input}" ];then
                echoColor green "Ignore."
                exit
            else
                sed -i 's /"resolve_preference": "64"/"resolve_preference": "46"/g' /etc/hihy/conf/hihyServer.json
                systemctl restart hihy
                echoColor green "Done.Ipv4 first now."
            fi
            
                ;;
                *"46"*)
                        echoColor purple "current ipv4 priority"
            echoColor yellow " -> set ipv6 priority higher than ipv4?(Y/N, default N)"
            read input
            if [ -z "${input}" ] ;then
                echoColor green "Ignore."
                exit
            else
                sed -i 's/"resolve_preference": "46",/"resolve_preference": "64",/g' /etc/hihy/conf/hihyServer.json
                systemctl restart hihy
                echoColor green "Done.Ipv6 first now."
            fi
        ;;
        esac
}

function getPortBindMsg(){
        # $1 type UDP or TCP
        # $2 port
        msg=`lsof -i:${2} | grep ${1}`
        if [ "$ {msg}" == "" ];then
                return
        else        
                                command=`echo ${msg} | awk '{print $1}'`
                                  pid=`echo ${msg} | awk '{print $2}'`
                                  name=`echo ${msg} | awk '{print $9}'`
                          echoColor purple "Port: ${1}/${2} has been occupied by ${command}(${name}), process pid is: ${pid}."
                                  echoColor green "Whether the port is occupied automatically? (y/N)"
                                read bindP
                                if [ -z "${bindP}" ];then
                                        echoColor red "Exit the installation because the port is occupied. Please manually close or replace the port... "
                                        if [ "${1}" == "TCP" ] && [ "${2}" == "80" ] || [ "${1}" == "TCP" ] && [ "${2 }" == "443" ];then
                                                echoColor "If the port ${1}/${2} cannot be closed on demand, please use other certificate acquisition methods"
                                        fi
                                        exit
                                elif [ "${bindP}" == "y" ] || [ "${bindP}" == "Y" ];then
                                        kill -9 ${pid}
                                        echoColor green "Port unbind successfully..."
                                else
                                        echoColor red "Exit the installation because the port is occupied. Please manually Close or change port..."
                                        if [ "${1}" == "TCP" ] && [ "${2}" == "80" ] || [ "${1}" == "TCP" ] && [ "${2}" == "443" ];then
                                                echoColor "If you can't close the ${1}/${2} port, please use another certificate acquisition method"
                                        fi
                                        exit
                                fi
        fi
}

function setHysteriaConfig (){
        mkdir -p /etc/hihy/bin /etc/hihy/conf /etc/hihy/cert /etc/hihy/result /etc/hihy/acl
        echoColor yellowBlack "Start configuration:"
        echo -e "\033[ 32m Please select the certificate application method:\n\n\033[0m\033[33m\033[01m1, use ACME to apply (recommended, need to open tcp 80/443)\n2, use local certificate file\n3, self-signed certificate \033[0m\033[32m\n\nInput serial number:\033[0m"
    read certNum
        useAcme=false useLocalCert
        =false
        if [ -z "${certNum}" ] || [ "${certNum}" == "3" ];then
                echoColor green "Please enter the domain name of the self-signed certificate (default: wechat.com):"
                re ad domain
                if [ -z "${domain}" ];then
                        domain="wechat.com"
                fi
                ip=`curl -4 -s -m 8 ip.sb`
                cert="/etc/hihy/cert/${ domain}.crt"
                key="/etc/hihy/cert/${domain}.key"
                useAcme=false
                echoColor purple "\nYou have selected self-signed ${domain} certificate encryption. Public network ip:"`echoColor red ${ip}`"\n"
    elif [ "${certNum}" == "2" ];then
                echoColor green "Please enter the path of the certificate cert file (fullchain required):"
                read cert
                while :
                do
                        if [ ! -f "${cert}" ];then
                                echoColor red "\nThe path does not exist, please re-enter!"
                                echoColor green "Please enter the path of the certificate cert file (fullchain required):"
                                read cert
                        else
                                break
                        fi
                done
                echoColor green "Please enter the certificate key file path:"
                read key
                while :
                do
                        if [ ! -f "${key}" ];then
                                echoColor red "\nThe path does not exist, please re-enter!"
                                echoColor green "Please enter the certificate key file path:"
                                read key
                        else
                                break
                        fi
                done
                echoColor green "Please enter the selected certificate domain name:"
                read domain
                while :
                do
                        if [ -z "${domain}" ];then
                                echoColor red "\nThis option cannot be empty, please re-enter!"
                                echoColor green "Please enter the selected certificate domain name:"
                                read domain
                        else
                                break
                        fi
                done
                useAcme=false useLocalCert
                =true
                echoColor purple "\nYou have chosen to use local ${domain} certificate encryption.\n"
    else 
            echoColor green "Please enter the domain name (it needs to be correctly resolved to this machine, and the CDN must be closed):"
                read domain
                while :
                do
                        if [ -z "${domain}" ];then
                                echoColor red "\nThis option cannot be empty, please try again Enter!"
                                echoColor green "Please enter the domain name (it needs to be correctly resolved to the local machine, close the CDN):"
                                read domain
                        else
                                break
                        fi
                done
                useAcme=true
                echoColor purple "\nYou have chosen to use ACME to automatically issue a trusted ${domain} Certificate encryption.\n"
    fi

        while :
        do
                echoColor green "Please enter the port you want to open, this port is the server port, 10000-65535 is recommended. (default random)"
                read port
                if [ -z "${port}" ];then
                        port=$(($(od -An -N2 -i /dev/random) % (65534 - 10001) + 10001))
                        echo -e "random port:"`echoColor red ${port}`"\ n"
                fi
                pIDa=`lsof -i :${port}|grep -v "PID" | awk '{print $2}'`
                if [ "$pIDa" != "" ];
                then
                        echoColor red "port ${port } Occupied, PID: ${pIDa}! Please re-enter or run kill -9 ${pIDa} and then reinstall!"
                else
                        break
                fi
        done
    echo -e "\033[32mSelect protocol type:\n\n\033 [0m\033[33m\033[01m1, udp(QUIC)\n2, faketcp\n3, wechat-video (enter by default)\033[0m\033[32m\n\nInput serial number:\033[0m"
    read protocol
        ut=
    if [ -z "${protocol}" ] || [ $protocol == "3" ];then
                protocol="wechat-video"
                ut="udp"
    elif [ $protocol == "2" ] ;then
                protocol="faketcp"
                ut="tcp"
    else 
            protocol="udp"
                ut="udp"
    fi
    echo -e "Transmission protocol:"`echoColor red ${protocol}`"\n"

    echoColor green "Please enter your average delay to this server, which is related to the forwarding speed (default 200,unit:ms):"
    read delay
    if [ -z "${delay}" ];then
        delay=200
    echo -e "delay:`echoColor red ${delay}`ms\n"
    fi
    echo -e "\ n Expected speed, this is the peak speed of the client, and the server is not limited by default." `echoColor red Tips: The script will automatically *1.10 do redundancy, your expectations are too low or too high will affect the forwarding efficiency, please fill in truthfully!`
    echoColor green "Please enter the desired downlink speed of the client: (default 50, unit: mbps):"
    read download
    if [ -z "${download}" ];then
        download=50
    echo -e "Client downlink speed:" `echoColor red ${download}`"mbps\n"
    fi
    echo -e "\033[32m Please enter the desired uplink speed of the client (default 10, unit: mbps):\033[0m" 
    read upload
    if [ -z "${upload}" ];then
        upload=10
    echo -e "Upload speed of client: "`echoColor red ${upload}`"mbps\n"
    fi
        auth_str=""
        echoColor green "Please enter the authentication password:"
        read auth_str
        while :
        do
                if [ -z "${auth_str}" ];then
                        echoColor red "\nThis option cannot be omitted, please re-enter!"
                        echoColor green "Please enter the authentication password:"
                        read auth_str
                else
                        break
                fi
        done
    echoColor green " \nConfiguration entry complete!\n"
    echoColor yellowBlack "Execute configuration..."
    download=$(($download + $download / 10))
    upload=$(($upload + $upload / 10))
    r_client=$( ($delay * 2 * $download / 1 000 * 1024 * 1024))
    r_conn=$(($r_client / 4))
        allowPort ${ut} ${port}
    if echo "${useAcme}" | grep -q "false";then
                if echo "${useLocalCert }" | grep -q "false";then
                        v6str=":" #Is ipv6?
                        result=$(echo ${ip} | grep ${v6str})
                        if [ "${result}" != "" ]; then
                                ip="[${ip}]" 
                        fi
                        u_host=${ip}
                        u_domain=${domain}
                        sec="1"
                        mail="admin@qq.com"
                        days=36500
                        echoColor purple "SIGN...\n "
                        openssl genrsa -out /etc/hihy/cert/${domain}.ca.key 2048
                        openssl req -new -x509 -days ${days} -key /etc/hihy/cert/${domain}.ca.key -subj "/C=CN/ST=GuangDong/L=ShenZhen/O=PonyMa/OU=Tecent/emailAddress=${mail}/CN=Tencent Root CA" -out /etc/hihy/cert/${domain} .ca.crt
                        openssl req -newkey rsa:2048 -nodes -keyout /etc/hihy/cert/${domain}.key -subj "/C=CN/ST=GuangDong/L=ShenZhen/O=PonyMa/OU= Tecent/emailAddress=${mail}/CN=Tencent Root CA" -out /etc/hihy/cert/${domain}.csr
                        openssl x509 -req -extfile <(printf "subjectAltName=DNS:${domain},DNS :${domain}") -days ${days} -in /etc/hihy/cert/${domain}.csr -CA /etc/hihy/cert/${domain}.ca.crt -CAkey /etc/hihy/cert/${domain}.ca.key -CAcreateserial -out /etc/hihy/cert/${domain}.crt
                        rm /etc/hihy/cert/${domain}.ca.key /etc/hihy/cert/${domain}.ca.srl /etc/hihy/cert/${domain}.csr
                        mv /etc/hihy/cert/${domain}.ca.crt /etc/hihy/result
                        echoColor purple "SUCCESS.\n"
                        cat <<EOF > /etc/hihy/result/hihyClient.json
{
"server": "${ip}:${port}",
"protocol": "${protocol}" ,
"up_mbps": ${upload},
"down_mbps": ${download},
"http": {
"listen": "127.0.0.1:10809",
"timeout" : 300,
"disable_udp": false
},
" socks5": {
"listen": "127.0.0.1:10808",
"timeout": 300,
"disable_udp": false
},
"alpn": "h3",
"acl": "acl/routes.acl",
" mmdb": "acl/Country.mmdb",
"auth_str": "${auth_str}",
"server_name": "${domain}",
"insecure": true,
"recv_window_conn": ${r_conn},
"recv_window ": ${r_client},
"disable_mtu_discovery": true,
"resolver": "https://doh.pub/dns-query",
"retry": 3,
"retry_interval": 3,
"quit_on_disconnect": false,
" handshake_timeout": 15,
"idle_timeout": 30
}
EOF
                else
                        u_host=${domain}
                        u_domain=${domain}
                        sec="0"
                        cat <<EOF > /etc/hihy/result/hihyClient.json
{
"server": "${domain}:${port}",
"protocol": "${protocol}",
"up_mbps ": ${upload},
"down_mbps": ${download},
"http": {
"listen": "127.0.0.1:10809",
"timeout" : 300,
"disable_udp": false
},
"socks5": {
"listen": "127.0.0.1:10808",
"timeout": 300,
"disable_udp": false
},
"alpn": "h3",
"acl": "acl/routes.acl",
"mmdb": "acl/Country.mmdb",
"auth_str": "${auth_str}",
"server_name": "${domain}",
"insecure": false,
"recv_window_conn": ${r_conn},
"recv_window": $ {r_client},
"disable_mtu_discovery": true,
"resolver": "https://doh.pub/dns-query",
"retry": 3,
"retry_interval": 3,
"quit_on_disconnect": false,
"handshake_timeout": 15,
"idle_timeout": 30
}
EOF
                fi                
                cat <<EOF > /etc/hihy/conf/hihyServer.json
{
"listen": ":${port}",
"protocol": "${protocol}",
" disable_udp": false,
"cert": "${cert}",
"key": "${key}",
"auth": {
        "mode": "password",
        "config": {
        "password": " ${auth_str}"
        }
},
"alpn": "h3",
"acl": "/etc/hihy/acl/hihyServer.acl",
"recv_window _conn": ${r_conn},
"recv_window_client": ${r_client},
"max_conn_client": 4096,
"disable_mtu_discovery": true,
"resolve_preference": "46",
"resolver": "https://8.8.8.8: 443/dns-query"
}
EOF

    else
                u_host=${domain}
                u_domain=${domain}
                sec="0"
                getPortBindMsg TCP 80
                getPortBindMsg TCP 443
                allowPort tcp 80
                allowPort tcp 443
                cat <<EOF> /etc/hihy/conf/ hihyServer.json
{
"listen": ":${port}",
"protocol": "${protocol}",
"acme": {
    "domains": [
    "${domain}"
    ],
    "email": " pekora@${domain}"
},
"disable_udp": false,
"auth": {
    "mode": "password",
    "config": {
    "password": "${auth_str}"
    }
},
"alpn": "h3",
"acl": "/etc/hihy/acl/hihyServer.acl",
"recv_window_conn": ${r_conn},
"recv_window_client": ${r_client},
"max_conn_client": 4096,
"disable_mtu_discovery": true ,
"resolve_preference": "46",
"resolver": "https://8.8.8.8:443/dns-query"
}
EOF

                cat <<EOF > /etc/hihy/result/hihyClient.json
{
"server": "${domain}:${port}",
"protocol": "${protocol}",
"up_mbps": ${upload},
"down_mbps": ${download},
"http": {
"listen": "127.0.0.1:10809",
"timeout" : 300,
"disable_udp": false
},
"socks5": {
"listen": "127.0.0.1:10808",
"timeout": 300,
"disable_udp": false
} ,
"alpn": "h3",
"acl": "acl/routes.acl",
"mmdb": "acl/Country.mmdb",
"auth_str": "${auth_str}",
"server_name": "$ {domain}",
"insecure": false,
"recv_window_conn": ${r_conn},
"recv_window": ${r_client},
"disable_mtu_discovery": true,
"resolver": "https://doh.pub/dns- query",
"retry": 3,
"retry_interval": 3,
"quit_on_disconnect": false,
"handshake_timeout": 15,
"idle_timeout": 30
}
EOF
    fi

        echo -e "\033[1;;35m\nWait,test config...\n\033[0m"
        echo "block all udp/443" > /etc/hihy/acl/hihyServer.acl
        /etc/hihy/bin/appS -c /etc/hihy/conf/hihyServer.json server > /tmp/hihy_debug.info 2>&1 &
        sleep 5
        msg=`cat /tmp/hihy_debug.info`
        case ${msg} in 
                *"Failed to get a certificate with ACME"*)
                        echoColor red "Domain name:${ u_host}, failed to apply for a certificate! Please check whether the panel firewall provided by the server is enabled (TCP: 80,443)\n or whether the domain name is correctly resolved to this ip (do not open CDN!)\n If the above two points cannot be satisfied, please reinstall and use Self-signed certificate."
                        rm /etc/hihy/conf/hihyServer.json
                        rm /etc/hihy/result/hihyC lient.json
                        rm /etc/systemd/system/hihy.service
                        exit
                        ;;
                *"bind: address already in use"*)
                        echoColor red "The port is occupied, please change the port!"
                        exit
                        ;;
                *"Server up and running" *) 
                        echoColor purple "Test success."
                        pIDa=`lsof -i :${port}|grep -v "PID" | awk '{print $2}'`
                        kill -9 ${pIDa} > /dev/null 2> &1
                        ;;
                *)         
                        pIDa=`lsof -i :${port}|grep -v "PID" | awk '{print $2}'`
                        kill -9 ${pIDa} > /dev/null 2>&1
                        echoColor red " Unknown error: Please run manually: `echoColor green "/etc/hihy/bin/appS -c /etc/hihy/conf/hihyServer.json server"`"
                        echoColor red "Check the error log and report to issue!"
                        exit
                        ;;
        esac
        rm /tmp/hihy_debug.info
        url="hysteria://${u_host}:${port}?protocol=${protocol}&auth=${auth_str}&peer=${u_domain}&insecure=${sec}&upmbps =${upload}&downmbps=${download}&alpn=h3#Hys-${u_host}"
        echo ${url} > /etc/hihy/result/url.txt
        if [ $sec = "1" ];then
                skip_cert_verify ="true"
        else
                skip_cert_verify="false"
        fi
        generateMetaYaml "Hys-${u_host}" ${u_host} ${port} ${auth_str} ${protocol} ${upload} ${download} ${u_domain} ${ skip_cert_verify} ${r_conn} ${r_client}
        echoColor green White "The installation is successful, please check the configuration details below"
        sleep 10
}

function downloadHysteriaCore(){
        version=`wget -qO- -t1 -T2 --no-check-certificate "https://api.github.com/repos /HyNetwork/hysteria/releases/latest" | grep "tag_name" | head -n 1 | awk -F ":" '{print $2}' | sed 's/\"//g;s/,//g; s/ //g'`
        echo -e "The Latest hysteria version:"`echoColor red "${version}"`"\nDownload..."
    get_arch=`arch`
    if [ $get_arch = "x86_64" ];then
        wget -q -O /etc/hihy/bin/appS --no-check-certificate https://github.com/HyNetwork/hysteria/releases/download/${version}/hysteria-linux-amd64
    elif [ $get_arch = "aarch64" ];then
        wget -q -O /etc/hihy/bin/appS --no-check-certificate https://github.com/HyNetwork/hysteria/releases/download/${version}/hysteria- linux-arm64
    elif [ $get_arch = "mips64" ];then
        wget -q -O /etc/hihy/bin/appS --no-check-certificate https://github.com/HyNetwork/hysteria/releases/download/ ${version}/hysteria-linux-mipsle
        elif [ $get_arch = "s390x" ];then
                wget -q -O /etc/hihy/bin/appS --no-check-certificate https://github. com/HyNetwork/hysteria/releases/download/${version}/hysteria-linux-s390x
        elif [ $get_arch = "i686" ];then
                wget -q -O /etc/hihy/bin/appS --no-check- certificate https://github.com/HyNetwork/hysteria/releases/download/${version}/hysteria-linux-386
    else
        echoColor yellowBlack "Error[OS Message]:${get_arch}\nPlease open a issue to https:/ /github.com/emptysuns/Hi_Hysteria/issues !"
        exit
    fi
        if [ -f "/etc/hihy/bin/appS" ]; then
                chmod 755 /etc/hihy/bin/appS
                echoColor purple "\nDownload completed."
        else
                echoColor red "Network Error: Can't connect to Github!"
        fi
}

function updateHysteriaCore(){
        if [ -f "/etc/hihy/bin/appS" ]; then
                localV=`/etc/hihy/bin/appS - v | cut -d " " -f
                3` remoteV=`wget -qO- -t1 -T2 --no-check-certificate "https://api.github.com/repos/HyNetwork/hysteria/releases/latest" | grep "tag_name" | head -n 1 | awk -F ":" '{print $2}' | sed 's/\"//g;s/,//g;s/ //g'`
                echo - e "Local core version:"`echoColor red "${localV}"`
                echo -e "Remote core version:"`echoColor red "${remoteV}"`
                if [ "${localV}" = "${remoteV}" ];then
                        echoColor green "Already the latest version.Ignore."
                else
                        status=`systemctl is-active hihy`
                        if [ "${status}" = "active" ] ;then #If it is in normal operation, the daemon will be stopped first, then automatically updated and then restarted, otherwise it is only responsible for updating
                                systemctl stop hihy
                                downloadHysteriaCore
                                systemctl start hihy
                        else
                                downloadHysteriaCore
                        fi
                        echoColor green "Hysteria Core update done."
                fi
        else
                echoColor red "hysteria core not found."
                exit
        fi
}

function changeServerConfig(){
        if [ ! -f "/etc/systemd/system/hihy.service" ]; then
                echoColor red "Please install hysteria first, then modify the configuration..."
                exit
        fi
        systemctl stop hihy
        delHihyFirewallPort
        updateHysteriaCore
        setHysteriaConfig
        systemctl start hihy
        printMsg
        echoColor yellowBlack "Reconfiguration completed."
        
}

function hihyUpdate(){
        localV=${hihyV}
        remoteV=`curl -fsSL https://git.io/hysteria.sh | sed - n 2p | cut -d '"' -f 2`
        if [ "${localV}" = "${remoteV}" ];then
                echoColor green "Already the latest version.Ignore."
        else
                wget -q -O /usr /bin/hihy --no-check-certificate https://raw.githubusercontent.com/emptysuns/Hi_Hysteria/main/server/install .sh
                chmod +x /usr/bin/hihy
                echoColor green "Done."
        fi

}

function hihyNotify(){
        localV=${hihyV}
        remoteV=`curl -fsSL https://git.io/hysteria.sh | sed - n 2p | cut -d '"' -f 2`
        if [ "${localV}" != "${remoteV}" ];then
                echoColor purple "[Update] hihy has an update, version:v${remoteV}, Recommended to update and check logs: https://github.com/emptysuns/Hi_Hysteria"
        fi

}

function hyCoreNotify(){
        if [ -f "/etc/hihy/bin/appS" ]; then
                  localV=`/etc/hihy/bin/appS -v | cut -d " " -f
                3` remoteV=`wget -qO- -t1 -T2 --no-check-certificate "https://api.github. com/repos/HyNetwork/hysteria/releases/latest" | grep "tag_name" | head -n 1 | awk -F ":" '{print $2}' | sed 's/\"//g;s/,/ /g;s/ //g'`
                if [ "${localV}" != "${remoteV}" ];then
                        echoColor purple "[Update] hysteria has an update, version:${remoteV}. detail: https: //github.com/HyNetwork/hysteria/blob/master/CHANGELOG.md"
                fi
        fi
}


function checkStatus(){
        status=`systemctl is-active hihy`
    if [ "${status}" = "active" ];then
                echoColor green "hysteria is working"
        else
                echoColor red "Dead!hysteria is not working!"
        fi
}

function install()
{        
        if [ -f "/etc/systemd/system/hihy.service" ]; then
                echoColor green "You have Successfully installed hysteria, if you need to modify the configuration, please use option 9/12"
                exit
        fi
        mkdir -p /etc/hihy/bin /etc/hihy/conf /etc/hihy/cert /etc/hihy/result
    echoColor purple "Ready to install .\n"
    version=`wget -qO- -t1 -T2 --no-check-certificate "https://api.github.com/repos/HyNetwork/hysteria/releases/latest" | grep "tag_name" | head -n 1 | awk -F ":" ' {print $2}' | sed 's/\"//g;s/,//g;s/ //g'`
    checkSystemForUpdate
        downloadHysteriaCore
        setHysteriaConfig
    cat <<EOF >/etc/systemd/system/hihy.service
[Unit ]
Description=hysteria:Hello World!
After=network.target

[Service]
Type=simple
PIDFile=/run/hihy.pid
ExecStart=/etc/hihy/bin/appS --log-level info -c /etc/hihy/ conf/hihyServer.json server
#Restart=on-failure
#RestartSec=10s

[Install]
WantedBy=multi-user.target
EOF
    sysctl -w net.core.rmem_max=8000000
    sysctl -p
    chmod 644 /etc/systemd/system/hihy .service
    systemctl daemon-reload
    systemctl enable hihy
    systemctl start hihy
        crontab -l > /tmp/crontab.tmp
        echo "15 4 * * 1,4 hihy cronTask" >> /tmp/crontab.tmp
        crontab /tmp/crontab.tmp
        rm /tmp/crontab.tmp
        printMsg
        echoColor yellowBlack "installation completed"
}


# output ufw port open status
function checkUFWAllowPort() {
        if ufw status | grep -q "$1"; then
                echoColor purple "UFW OPEN: ${1}"
        else
                echoColor red "UFW OPEN FAIL: ${1}"
                exit 0
        fi
}

# Output firewall-cmd port open status
function checkFirewalldAllowPort() {
        if firewall-cmd --list-ports --pe rmanent | grep -q "$1"; then
                echoColor purple "FIREWALLD OPEN: ${1}/${2}"
        else
                echoColor red "FIREWALLD OPEN FAIL: ${1}/${2}"
                exit 0
        fi
}

function allowPort () {
        # Add the corresponding open ports if the firewall is active
        # $1 tcp/udp
        # $2 port
        if systemctl status netfilter-persistent 2>/dev/null | grep -q "active (exited)"; then
                local updateFirewalldStatus=
                if !iptables -L | grep -q "allow ${1}/${2}(hihysteria)"; then
                        updateFirewalldStatus=true
                        iptables -I INPUT -p ${1} --dport ${2} -m comment -- comment "allow ${1}/${2}(hihysteria)" -j ACCEPT 2> /dev/null
                        echoColor purple "IPTABLES OPEN: ${1}/${2}"
                fi
                if echo "${updateFirewalldStatus}" | grep -q "true"; then
                        netfilter-persistent save 2>/dev/null
                fi
        elif [[ `ufw status 2>/dev/null | grep "Status: " | awk '{print $2}'` = "active " ]]; then
                if ! ufw status | grep -q ${2}; then
                        sudo ufw allow ${2} 2>/dev/null
                        checkUFWAllowPort ${2}
                fi
        elif systemctl status firewalld 2>/dev/null | grep -q "active (running)"; then
                local updateFirewalldStatus=
                if ! firewall-cmd --list-ports --perm anent | grep -qw "${2}/${1}"; then
                        updateFirewalldStatus=true
                        firewall-cmd --zone=public --add-port=${2}/${1} --permanent 2>/ dev/null
                        checkFirewalldAllowPort ${2}
                fi
                if echo "${updateFirewalldStatus}" | grep -q "true"; then
                        firewall-cmd --reload
                fi
        fi
}

function delHihyFirewallPort() {
        # Delete previous rule if firewall is up
        if systemctl status netfilter-persistent 2>/dev/null | grep -q "active (exited)"; then
                local updateFirewalldStatus=
                if iptables -L | grep -q "allow ${1}/${2}(hihysteria)" ; then
                        updateFirewalldStatus=true
                        iptables-save | sed -e '/hihysteria/d' | iptables-restore
                fi
                if echo "${updateFirewalldStatus}" | grep -q "true"; then
                        netfilter-persistent save 2> /dev/null
                fi
        elif [[ `ufw status 2>/dev/null | grep "Status: " | awk '{print $2}'` = "active" ]]; then
                port=`cat /etc/hihy/conf/hihyServer.json | grep "listen" | awk '{print $2}' | tr -cd "[0-9]"`
                if ufw status | grep -q ${port}; then
                        sudo ufw delete allow ${port} 2> /dev /null
                fi
        elif systemctl status firewalld 2>/dev/null | grep -q "active (running)"; then
                local updateFirewalldStatus=
                port=`cat /etc/hihy/conf/hihyServer.json | grep "listen" | awk '{print $2}' | tr -cd "[0-9]"`
                isFaketcp= `cat /etc/hihy/conf/hihyServer.json | grep "faketcp"`
                if [ -z "${isFaketcp}" ];then
                        ut="udp"
                else
                        ut="tcp"
                fi
                if firewall-cmd --list -ports --permanent | grep -qw "${port}/${ut}"; then
                        updateFirewalldStatus=true
                        firewall-cmd --zone=public --remove-port=${port}/${ut} 2> /dev/null
                fi
                if echo "${updateFirewalldStatus}" | grep -q "true"; then
                        firewall-cmd --reload 2> /dev/null
                fi
        fi
}

function checkRoot(){
        user=`whoami`
        if [ ! "${user}" = "root" ];then
                echoColor red "Please run as root user!"
                exit 0
        fi
}

function editProtocol(){
        # $1 change to $2, example(editProtocol 'udp' 'faketcp'): udp to faketcp
        sed -i "s/\"protocol\": \"${1}\"/\"protocol\": \"${2}\"/g" /etc/hihy/conf/hihyServer.json
        sed -i "s/\"protocol\": \"${1}\"/\"protocol\": \"${2}\"/g" /etc/hihy/result/hihyClient.json
        sed - i "s/protocol: ${1}/protocol: ${2}/g" /etc/hihy/result/meta Hys.yaml
        sed -i "s/protocol=${1}/protocol=${2}/g" /etc/hihy/result/url.txt
}

function changeMode(){
        if [ ! -f "/etc/ hihy/conf/hihyServer.json" ]; then
                echoColor red "The configuration file does not exist, exit..."
                exit
        fi
        protocol=`cat /etc/hihy/conf/hihyServer.json | grep protocol | awk '{print $2} ' | awk -F '"' '{ print $2}'`
        echoColor yellow "The current protocol is:"
        echoColor purple "${protocol}"
        port=`cat /etc/hihy/conf/hihyServer.json | grep "listen " | awk '{print $2}' | tr -cd "[0-9]"`
        if [ "${protocol}" = "udp" ];then
                echo -e "\033[32m\nPlease select the modified Protocol type:\n\n\033[0m\033[33m\033[01m1, faketcp\n2, wechat-video\033[0m\033[32m\n\nInput serial number:\033[0m"
            read pNum
                if [ -z "${pNum}" ] || [ "${pNum}" == "1" ];then
                        echoColor purple "Select to modify the protocol type to faketcp."
                        editProtocol "udp" "faketcp"
                        delHihyFirewallPort
                        allowPort "tcp" ${port}
                else
                        echoColor purple "Choose to modify the protocol type as wechat-video."
                        editProtocol "udp" "wechat-video"
                fi
        elif [ "${protocol}" = "faketcp" ];then
                delHihyFirewallPort
                allowPort "udp " ${port}
                echo -e "\033[32m\nPlease select the modified protocol type:\n\n\033[0m\033[33m\033[01m1, udp\n2, wechat-video\033[0m \033[32m\n\nInput serial number:\033[0m"
            read pNum
                if [ -z "${pNum}" ] || [ "${pNum}" == "1" ];then
                        echoColor purple "Select to modify the protocol type to udp."
                        editProtocol "faketcp" "udp"
                else
                        echoColor purple "Select the modification protocol type as wechat-video."
                        editProtocol "faketcp" "wechat-video"
                fi
        elif [ "${protocol}" = "wechat-video" ];then
                echo -e "\033[32m\nPlease Select the modified protocol type:\n\n\033[0m\033[33m\033[01m1, udp\n2, faketcp\033[0m\033[32m\n\nEnter the serial number:\033[0m"
            read pNum
                if [ -z "${pNum}" ] || [ "${pNum}" == "1" ];then
                        echoColor purple "Select to modify the protocol type to udp."
                        editProtocol wechat-video udp
                else
                        delHihyFirewallPort
                        allowPort " tcp" ${port}
                        echoColor purple "Select to modify the protocol type to faketcp."
                        editProtocol "wechat-video" "faketcp"
                fi
        else
                echoColor red "Unable to recognize the protocol type!"
                exit
        fi
        systemctl restart hihy
        echoColor green "Modification successful"
}


function generateMetaYaml(){
        cat <<EOF > /etc/hihy/result/metaHys.yaml
mixed-port: 7890
allow-lan: true
mode: rule
log-level: info
ipv6: true
dns:
  enable: true
  listen: 0.0.0.0 :53
  ipv6: true
  default-nameserver:
    - 114.114.114.114
    - 223.5.5.5
  enhanced-mode: redir-host
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns -query
  fallback:
    - 114.114.114.114
    - 223.5.5.5

proxies:
  - name: "$1"
    type: hysteria
    server: $2
    port: $3
    auth_str: $4
    alpn: h3
    protocol: $5
    up: $6
    down: $7
    sni: $8
    skip-cert -verify: $9
    recv_window_conn: ${10}
    recv_window: ${11}
    disable_mtu_discovery: true

proxy-groups:
  - name: "PROXY"
    type: select
    proxies:
     - $1

rule-providers:
  re ject:
    type: http
    behavior: domain
    url: "https://ghproxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt"
    path: ./ruleset/reject.yaml
    interval: 86400

  icloud:
    type: http
    behavior: domain
    url: "https://ghproxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/icloud.txt"
    path: ./ruleset/ icloud.yaml
    interval: 86400

  apple:
    type: http
    behavior: domain
    url: "https://ghproxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/apple.txt"
    path: . /ruleset/apple.yaml
    interval: 86400

  google:
    type: http
    behavior: domain
    url: "https://ghproxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/google.txt"
    path: ./ruleset/google.yaml
    interval: 86400

  proxy:
    type: http
    behavior: domain
    url: "https://ghproxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy .txt"
    path: ./ruleset/proxy.yaml
    interval: 86400

  direct:
    type: http
    behavior: domain
    url: "https://ghproxy.com/https://raw.githubuse rcontent.com/Loyalsoldier/clash-rules/release/direct.txt"
    path: ./ruleset/direct.yaml
    interval: 86400

  private:
    type: http
    behavior: domain
    url: "https://ghproxy.com/https:/ /raw.githubusercontent.com/Loyalsoldier/clash-rules/release/private.txt"
    path: ./ruleset/private.yaml
    interval: 86400

  gfw:
    type: http
    behavior: domain
    url: "https://ghproxy.com/ https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/gfw.txt"
    path: ./ruleset/gfw.yaml
    interval: 86400

  greatfire:
    type: http
    behavior: domain
    url: "https://ghproxy .com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/greatfire.txt"
    path: ./ruleset/greatfire.yaml
    interval: 86400

  tld-not-cn:
    type: http
    behavior: domain
    url : "https://ghproxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/tld-not-cn.txt"
    path: ./ruleset/tld-not-cn.yaml
    interval : 86400

  telegramcidr:
    type: http
    behavior: ipcidr
    url: "https://ghproxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/telegram cidr.txt"
    path: ./ruleset/telegramcidr.yaml
    interval: 86400

  cncidr:
    type: http
    behavior: ipcidr
    url: "https://ghproxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules /release/cncidr.txt"
    path: ./ruleset/cncidr.yaml
    interval: 86400

  lancidr:
    type: http
    behavior: ipcidr
    url: "https://ghproxy.com/https://raw.githubusercontent.com/Loyalsoldier/ clash-rules/release/lancidr.txt"
    path: ./ruleset/lancidr.yaml
    interval: 86400

  applications:
    type: http
    behavior: classical
    url: "https://ghproxy.com/https://raw.githubusercontent.com /Loyalsoldier/clash-rules/release/applications.txt"
    path: ./ruleset/applications.yaml
    interval: 86400

rules:
  - RULE-SET,applications,DIRECT
  - DOMAIN,clash.razord.top,DIRECT
  - DOMAIN,yacd. haishan.me,DIRECT
  - RULE-SET,private,DIRECT
  - RULE-SET,reject,REJECT
  - RULE-SET,icloud,DIRECT
  - RULE-SET,apple,DIRECT
  - RULE-SET,google,DIRECT
  - RULE-SET, proxy,PROXY
  -RULE-SET,direct,DIRECT
  -RULE-SET,lancidr,DIRECT
  -RULE-SET,cncidr,DIRECT
  -RULE-SET,telegramcidr,PROXY
  -GE OIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
EOF
}

function checkLogs(){
        echoColor purple "hysteria real-time log, level: info, press Ctrl+C to exit:"
        journalctl -fu hihy
}

function cronTask(){
        systemctl restart hihy #Prevent hysteria from taking up too much memory
        systemctl restart systemd-journald #Prevent the journal from taking up too much memory
}

function menu()
{
hihy
clear
cat << EOF
 ---------------- ---------------------------
|********** Hi Hysteria ********** |
|********** Author: emptysuns **********|
|********** Version: `echoColor red "${hihyV}"` * *********|
 ---------------------------------------- ---
Tips: `echoColor green "hihy"` command to run this script again.
`echoColor skyBlue "...................................... ................."`
`echoColor purple "############################ ####"`

`echoColor skyBlue "....................."`
`echoColor yellow "1) install hysteria"`
`echoColor magenta "2) uninstall "`
`echoColor skyBlue "................................"`
`echoColor yellow "3) start"`
`echoColor magenta "4) pause"`
`echoColor yellow "5) Reboot"`
`echoColor yellow "6) Running status"`
`echoColor skyBlue "............"`
`echoCo lor yellow "7) Update Core"`
`echoColor yellow "8) View current configuration"`
`echoColor skyBlue "9) Reconfigure"`
`echoColor yellow "10) Switch ipv4/ipv6 priority"`
`echoColor yellow "11) Update hihy"`
`echoColor red "12) Completely reset all configurations"`
`echoColor skyBlue "13) Modify the current protocol type"`
`echoColor yellow "14) View real-time log"`

`echoColor purple "###### #########################"`
`hihyNotify`
`hyCoreNotify`

`echoColor magenta "0)exit"`
`echoColor skyBlue ".... .........................................."`
EOF
read -p "Please select :" input
case $input in
        1)        
                install
        ;;
        2)
                uninstall
        ;;
        3)
                systemctl start hihy
                echoColor green "start successful"
        ;;
        4)
                systemctl stop hihy
                echoColor green "pause successful"
        ;;
    5)
        systemctl restart hihy
                echoColor green "Restart succeeded"

    ;;
    6)
        checkStatus
        ;;
        7)
                updateHysteriaCore
        ;;
        8)
                printMsg
    ;;
    9)
        changeServerConfig
    ;;
        10)
        changeIp64
    ;;
        11)
        hihyUpdate
    ;;
        12)
        reinstall
        ;;
        13)
        changeMode
        ;;
        14)
                checkLogs
    ; ;
        0)
                exit
        ;;
        *)
                echoColor red "Input Error !!!"
                exit 1
        ;;
    esac
}

checkRoot
if [ "$1" == "install" ]; then
        install
elif [ "$1" == "uninstall" ]; then
        uninstall
elif [ "$1" == "upda te" ]; then
        updateHysteriaCore
elif [ "$1" == "reinstall" ]; then
        reinstall
elif [ "$1" == "status" ]; then
        checkStatus
elif [ "$1" == "start" ]; then
        systemctl start hihy
elif [ "$1" == "stop" ]; then
        systemctl stop hihy
elif [ "$1" == "restart" ]; then
        systemctl restart hihy
elif [ "$1" == "logs" ]; then
        checkLogs
elif [ "$1 " == "config" ]; then
        printMsg
elif [ "$1" == "change" ]; then
        changeServerConfig
elif [ "$1" == "changeIp64" ]; then
        changeIp64
elif [ "$1" == "hihyUpdate" ]; then
        hihyUpdate
elif [ "$1" == "changeMode" ]; then
        changeMode
elif [ "$1" == "cronTask" ]; then
        cronTask
else
        menu
fi