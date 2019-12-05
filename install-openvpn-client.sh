#!/bin/bash

BASE_PATH=$(cd `dirname $0`; pwd)
CLIENT_OVPN_FILE=client-user.ovpn
CLIENT_OVPN_PASS=000000

function install_package()
{
    yum install -y openvpn expect
}

function shutdown()
{
    ps -ef | grep openvpn | grep config | grep -v grep | awk '{print $2}' | xargs kill -9
}

function startup()
{
    
    #nohup openvpn --daemon --config ${BASE_PATH}"/"${CLIENT_OVPN_FILE} >/dev/null 2>&1 &
/usr/bin/expect <<EOF
    set timeout 5
    spawn openvpn --config ${BASE_PATH}/${CLIENT_OVPN_FILE}
    expect "Enter Private Key Password"
    send ${CLIENT_OVPN_PASS}
    interact
    expect eof
EOF
}

function status()
{
    sleep 5
    echo ""
    result=`ps -ef | grep openvpn | grep config | grep -v grep`
    if [ -n "${result}" ];
    then
        vpn_ip=`ifconfig | grep "10.8." | awk '{print $2}'`
        echo -e "\033[32mOpenVpn Client Startup Success, vpn ip address is ${vpn_ip}.\033[0m"
    else
        echo -e "\033[31mOpenVpn Client Startup Failed.\033[0m"
    fi
}

main()
{
    install_package
    shutdown
    startup
    status
}

main
