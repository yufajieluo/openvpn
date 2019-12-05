#!/bin/bash

SERVER_NAME="install-openvpn"
SERVER_VERSION="v1.0.0"
SERVER_ADDR=
SERVER_PORT=
CLIENT_USER=

WORK_PATH="/root/openvpn-tmp"
CLIENT_PATH="/root/client/"
SELINUX_CONFIG_FILE="/etc/sysconfig/selinux"
OPENVPN_CONFIG_PATH="/etc/openvpn/"

COLOR_ERROR="31m"
COLOR_SUCCESS="32m"
COLOR_WARNING="33m"
COLOR_SYSTEM="34m"

########## common ##########

function help()
{
    echo "Usage:"
    echo "  ${SERVER_NAME} [OPTION]"
    echo ""
    echo "Available OPTION"
    echo "  --type         必选，server; client"
    echo ""
    echo "  --help         display this help and exit"
    echo "  --version      output version information and exit"
}

function version()
{
    echo "${SERVER_NAME} ${SERVER_VERSION}"
}

function print_color()
{
    echo -e "\033[${1}${2}\033[0m"
}

function init_path()
{
    mkdir -p ${WORK_PATH}
    cd ${WORK_PATH}
}

function check_selinux()
{
    result=`grep "^SELINUX=" ${SELINUX_CONFIG_FILE}`
    if [ ${result#*=} != "disabled" ];
    then
        sed -i s/"^SELINUX="${result#*=}/SELINUX=disabled/g ${SELINUX_CONFIG_FILE}
    fi
}

function install_package()
{
    yum -y install openssh-server lzo openssl openssl-devel openvpn NetworkManager-openvpn openvpn-auth-ldap zip unzip
}

function install_easyrsa()
{
    wget https://github.com/OpenVPN/easy-rsa/archive/master.zip
    unzip master.zip
}

function common()
{
    print_color ${COLOR_WARNING} "初始化工作目录开始..."
    init_path
    print_color ${COLOR_SUCCESS} "初始化工作目录完成."
    
    print_color ${COLOR_WARNING} "关闭SELinux开始..."
    check_selinux
    print_color ${COLOR_SUCCESS} "关闭SELinux完成."
    
    print_color ${COLOR_WARNING} "安装依赖包开始..."
    install_package
    print_color ${COLOR_SUCCESS} "安装依赖包完成."
    
    print_color ${COLOR_WARNING} "安装easy-rsa开始..."
    install_easyrsa
    print_color ${COLOR_SUCCESS} "安装easy-rsa完成."
}

function clear_work_path()
{
    if [ -d ${WORK_PATH} ];
    then
        rm -rf ${WORK_PATH}
    fi
}

function read_file()
{
    file=${1}
    content=
    line_begin=`grep -n "BEGIN" ${file} | awk -F ":" '{print $1}'`
    line_end=`grep -n "END" ${file} | awk -F ":" '{print $1}'`

    index=0
    while read line
    do
        let index++
        if [ ${index} -ge ${line_begin} ] && [ ${index} -le ${line_end} ];
        then
            if [ -n "${content}" ];
            then
                content+="\n"
            fi
            content+=${line}
        fi
    done < ${file}
}

########## server ##########

function generate_server_crt()
{
    # modify config
    cp -R ${WORK_PATH}"/easy-rsa-master" ${OPENVPN_CONFIG_PATH}"easy-rsa"
    cp ${OPENVPN_CONFIG_PATH}"easy-rsa/easyrsa3/vars.example" ${OPENVPN_CONFIG_PATH}"easy-rsa/easyrsa3/vars"
    sed -i s/"^#set_var EASYRSA_REQ_COUNTRY"/"set_var EASYRSA_REQ_COUNTRY"/g ${OPENVPN_CONFIG_PATH}"easy-rsa/easyrsa3/vars"
    sed -i s/"^#set_var EASYRSA_REQ_PROVINCE"/"set_var EASYRSA_REQ_PROVINCE"/g ${OPENVPN_CONFIG_PATH}"easy-rsa/easyrsa3/vars"
    sed -i s/"^#set_var EASYRSA_REQ_CITY"/"set_var EASYRSA_REQ_CITY"/g ${OPENVPN_CONFIG_PATH}"easy-rsa/easyrsa3/vars"
    sed -i s/"^#set_var EASYRSA_REQ_ORG"/"set_var EASYRSA_REQ_ORG"/g ${OPENVPN_CONFIG_PATH}"easy-rsa/easyrsa3/vars"
    sed -i s/"^#set_var EASYRSA_REQ_EMAIL"/"set_var EASYRSA_REQ_EMAIL"/g ${OPENVPN_CONFIG_PATH}"easy-rsa/easyrsa3/vars"
    sed -i s/"^#set_var EASYRSA_REQ_OU"/"set_var EASYRSA_REQ_OU"/g ${OPENVPN_CONFIG_PATH}"easy-rsa/easyrsa3/vars"
    
    cd ${OPENVPN_CONFIG_PATH}"easy-rsa/easyrsa3"
    
    # init
    print_color ${COLOR_WARNING} "init-pki ..."
    ./easyrsa init-pki
    print_color ${COLOR_SUCCESS} "init-pki 完成."
    
    # generate root crt
    print_color ${COLOR_WARNING} "build-ca ..."
    ./easyrsa build-ca
    print_color ${COLOR_SUCCESS} "build-ca 完成."
    
    # generate server crt
    print_color ${COLOR_WARNING} "gen-req server nopass ..."
    ./easyrsa gen-req server nopass
    print_color ${COLOR_SUCCESS} "gen-req server nopass 完成."
    
    # sign server crt
    print_color ${COLOR_WARNING} "sign server ..."
    ./easyrsa sign server server
    print_color ${COLOR_SUCCESS} "sign server 完成."
    
    # generate dh
    print_color ${COLOR_WARNING} "gen-dh ..."
    ./easyrsa gen-dh
    print_color ${COLOR_SUCCESS} "gen-dh 完成."

    # move crt
    print_color ${COLOR_WARNING} "move server ..."
    cp -f ${OPENVPN_CONFIG_PATH}"easy-rsa/easyrsa3/pki/ca.crt" ${OPENVPN_CONFIG_PATH}
    cp -f ${OPENVPN_CONFIG_PATH}"easy-rsa/easyrsa3/pki/dh.pem" ${OPENVPN_CONFIG_PATH}
    cp -f ${OPENVPN_CONFIG_PATH}"easy-rsa/easyrsa3/pki/private/server.key" ${OPENVPN_CONFIG_PATH}
    cp -f ${OPENVPN_CONFIG_PATH}"easy-rsa/easyrsa3/pki/issued/server.crt" ${OPENVPN_CONFIG_PATH}
    print_color ${COLOR_SUCCESS} "move server 完成."
    
    # clear req file
    print_color ${COLOR_WARNING} "clear req file ..."
    rm -rf ${CLIENT_PATH}"easy-rsa/easyrsa3/pki/reqs/server.req"
    print_color ${COLOR_SUCCESS} "clear req file 完成."
}

function generate_server_conf()
{
    openvpn_server_conf_file=${OPENVPN_CONFIG_PATH}"server.conf"
    touch ${openvpn_server_conf_file}
    echo "port ${SERVER_PORT}" >> ${openvpn_server_conf_file}
    echo "proto tcp" >> ${openvpn_server_conf_file}
    echo "dev tun" >> ${openvpn_server_conf_file}
    echo "ca ${OPENVPN_CONFIG_PATH}ca.crt" >> ${openvpn_server_conf_file}
    echo "dh ${OPENVPN_CONFIG_PATH}dh.pem" >> ${openvpn_server_conf_file}
    echo "key ${OPENVPN_CONFIG_PATH}server.key" >> ${openvpn_server_conf_file}
    echo "cert ${OPENVPN_CONFIG_PATH}server.crt" >> ${openvpn_server_conf_file}
    echo "server 10.8.0.0 255.255.255.0" >> ${openvpn_server_conf_file}
    echo "ifconfig-pool-persist ipp.txt" >> ${openvpn_server_conf_file}
    echo "push \"route 172.18.0.0 255.255.0.0\"" >> ${openvpn_server_conf_file}
    echo "push \"dhcp-option DNS 114.114.114.114\"" >> ${openvpn_server_conf_file}
    echo "client-to-client" >> ${openvpn_server_conf_file}
    echo "duplicate-cn" >> ${openvpn_server_conf_file}
    echo "comp-lzo" >> ${openvpn_server_conf_file}
    echo "max-clients 100" >> ${openvpn_server_conf_file}
    echo "keepalive 10 120" >> ${openvpn_server_conf_file}
    echo "persist-key" >> ${openvpn_server_conf_file}
    echo "persist-tun" >> ${openvpn_server_conf_file}
    echo "status /var/log/openvpn-status.log" >> ${openvpn_server_conf_file}
    echo "log-append /var/log/openvpn.log" >> ${openvpn_server_conf_file}
    echo "verb 3" >> ${openvpn_server_conf_file}
}

function set_iptables()
{
    #iptables_conf_file=/etc/sysctl.conf
    #result=`grep "^net.ipv4.ip_forward" ${iptables_conf_file}`
    #if [ -z "${result}" ];
    #then
    #    echo "net.ipv4.ip_forward = 1" >> ${iptables_conf_file}
    #else
    #    sed -i s/"^net.ipv4.ip_forward"/"#net.ipv4.ip_forward"/g ${iptables_conf_file}
    #    echo "net.ipv4.ip_forward = 1" >> ${iptables_conf_file}
    #fi
    #sysctl -p
    #
    #systemctl stop firewalld
    #yum install -y iptables iptables-services
    #iptables -A INPUT -p tcp -m tcp --dport ${SERVER_PORT} -j ACCEPT
    #iptables -t nat -A POSTROUTING -s 10.8.0.0/24  -j MASQUERADE
    #systemctl start iptables
    
    
    systemctl stop firewalld
    systemctl stop iptables
}

function startup()
{
    openvpn --daemon --config ${OPENVPN_CONFIG_PATH}"server.conf"
}

function server_handler()
{
    common
    
    print_color ${COLOR_WARNING} "生成服务端证书开始..."
    generate_server_crt
    print_color ${COLOR_SUCCESS} "生成服务端证书完成."
    
    print_color ${COLOR_WARNING} "生成服务端配置文件开始..."
    generate_server_conf
    print_color ${COLOR_SUCCESS} "生成服务端配置文件完成."
    
    print_color ${COLOR_WARNING} "配置防火墙开始 ..."
    set_iptables
    print_color ${COLOR_SUCCESS} "配置防火墙完成."
    
    print_color ${COLOR_WARNING} "启动服务开始 ..."
    startup
    print_color ${COLOR_SUCCESS} "启动服务完成."
    
    print_color ${COLOR_WARNING} "清理临时文件开始 ..."
    clear_work_path
    print_color ${COLOR_SUCCESS} "清理临时文件完成."
}

function server_entrance()
{
    clear
    print_color ${COLOR_SYSTEM} ""
    print_color ${COLOR_SYSTEM} ".......... openvpn client by WSHUAI .........."
    print_color ${COLOR_SYSTEM} ""
    
    while true
    do
        read -p "$(print_color ${COLOR_SYSTEM} 'please input server port [1194]: ')" SERVER_PORT
        if [ -z ${SERVER_PORT} ];
        then
            SERVER_PORT=1194
        fi
        
        output=`netstat -anp |grep "${SERVER_PORT} "`
        if [ -n "${output}" ];
        then
            print_color ${COLOR_WARNING} "端口${SERVER_PORT}已被占用，请重新选择."
            continue
        else
            break
        fi
    done
    
    #echo ${SERVER_PORT}
    server_handler
}

########## client ##########

function generate_ovpn_conf()
{
    ovpn_conf_file=${CLIENT_PATH}"${CLIENT_USER}.ovpn"
    touch ${ovpn_conf_file}
    echo "client" >> ${ovpn_conf_file}
    echo "nobind" >> ${ovpn_conf_file}
    echo "dev tun" >> ${ovpn_conf_file}
    echo "proto tcp" >> ${ovpn_conf_file}
    echo "remote ${SERVER_ADDR} ${SERVER_PORT}" >> ${ovpn_conf_file}
    echo "resolv-retry infinite" >> ${ovpn_conf_file}
    echo "persist-key" >> ${ovpn_conf_file}
    echo "persist-tun" >> ${ovpn_conf_file}
    echo "remote-cert-tls server" >> ${ovpn_conf_file}    
    echo "" >> ${ovpn_conf_file}
    
    content=
    
    echo "<ca>" >> ${ovpn_conf_file}
    read_file ${CLIENT_PATH}"ca.crt"
    echo -e ${content} >> ${ovpn_conf_file}
    echo "</ca>" >> ${ovpn_conf_file}
    
    echo "<cert>" >> ${ovpn_conf_file}
    read_file ${CLIENT_PATH}${CLIENT_USER}.crt
    echo -e ${content} >> ${ovpn_conf_file}
    echo "</cert>" >> ${ovpn_conf_file}
    
    echo "<key>" >> ${ovpn_conf_file}
    read_file ${CLIENT_PATH}${CLIENT_USER}.key
    echo -e ${content} >> ${ovpn_conf_file}
    echo "</key>" >> ${ovpn_conf_file}
    
    echo "" >> ${ovpn_conf_file}
    echo "comp-lzo" >> ${ovpn_conf_file}
    echo "verb 3" >> ${ovpn_conf_file}
}

function generate_client_crt()
{
    mkdir ${CLIENT_PATH}
    cp -R ${WORK_PATH}"/easy-rsa-master" ${OPENVPN_CONFIG_PATH}"easy-rsa"
    cp -R ${WORK_PATH}"/easy-rsa-master" ${CLIENT_PATH}"easy-rsa"
    cd ${CLIENT_PATH}"easy-rsa/easyrsa3"
    
    # init
    print_color ${COLOR_WARNING} "init-pki ..."
    ./easyrsa init-pki
    print_color ${COLOR_SUCCESS} "init-pki 完成."
    
    # generate client crt
    print_color ${COLOR_WARNING} "gen-req client ..."
    ./easyrsa gen-req ${CLIENT_USER}
    print_color ${COLOR_SUCCESS} "gen-req client 完成."
    
    # import crt
    print_color ${COLOR_WARNING} "import-req client ..."
    cd ${OPENVPN_CONFIG_PATH}"easy-rsa/easyrsa3"
    ./easyrsa import-req ${CLIENT_PATH}"easy-rsa/easyrsa3/pki/reqs/${CLIENT_USER}.req" ${CLIENT_USER}
    print_color ${COLOR_SUCCESS} "import-req 完成."
    
    # sign crt
    print_color ${COLOR_WARNING} "sign client ..."
    ./easyrsa sign client ${CLIENT_USER}
    print_color ${COLOR_SUCCESS} "sign client 完成."
    
    # move crt
    print_color ${COLOR_WARNING} "move client ..."
    mv -f ${CLIENT_PATH}"easy-rsa/easyrsa3/pki/private/${CLIENT_USER}.key" ${CLIENT_PATH}
    mv -f ${OPENVPN_CONFIG_PATH}"easy-rsa/easyrsa3/pki/issued/${CLIENT_USER}.crt" ${CLIENT_PATH}
    cp -f ${OPENVPN_CONFIG_PATH}"easy-rsa/easyrsa3/pki/ca.crt" ${CLIENT_PATH}
    print_color ${COLOR_SUCCESS} "move client 完成."
    
    # generate ovpn file
    print_color ${COLOR_WARNING} "generate ovpn file ..."
    generate_ovpn_conf
    print_color ${COLOR_SUCCESS} "generate ovpn file 完成."
    
    # clear req file
    print_color ${COLOR_WARNING} "clear req file ..."
    rm -rf ${OPENVPN_CONFIG_PATH}"easy-rsa/easyrsa3/pki/reqs/${CLIENT_USER}.req"
    rm -rf ${CLIENT_PATH}${CLIENT_USER}.key
    rm -rf ${CLIENT_PATH}${CLIENT_USER}.crt
    rm -rf ${CLIENT_PATH}"ca.crt"
    print_color ${COLOR_SUCCESS} "clear req file 完成."
}

function client_handler()
{
    common
    
    print_color ${COLOR_WARNING} "生成客户端证书开始..."
    generate_client_crt
    print_color ${COLOR_SUCCESS} "生成客户端证书完成."

    print_color ${COLOR_WARNING} "清理临时文件开始 ..."
    clear_work_path
    print_color ${COLOR_SUCCESS} "清理临时文件完成."
}

function client_entrance()
{
    clear
    print_color ${COLOR_SYSTEM} ""
    print_color ${COLOR_SYSTEM} ".......... openvpn client by WSHUAI .........."
    print_color ${COLOR_SYSTEM} ""
    read -p "$(print_color ${COLOR_SYSTEM} 'please input client user name [client-user]: ')" CLIENT_USER
    if [ -z ${CLIENT_USER} ];
    then
        CLIENT_USER="client-user"
    fi
    
    while true
    do
        read -p "$(print_color ${COLOR_SYSTEM} 'please input server public addr: ')" SERVER_ADDR
        if [ -z ${SERVER_ADDR} ];
        then
            print_color ${COLOR_ERROR} "server public addr can not be empty."
        else
            break
        fi
    done
    
    read -p "$(print_color ${COLOR_SYSTEM} 'please input server port [1194]: ')" SERVER_PORT
    if [ -z ${SERVER_PORT} ];
    then
        SERVER_PORT=1194
    fi
    
    #echo ${CLIENT_USER}
    #echo ${SERVER_ADDR}
    client_handler
}


########## main ##########

ARGS=`getopt -o t:,b: --long help,version,type: -- "$@"`
if [ $# == 0 ];
then
    help
    echo ""
    echo "Terminating..." >&2
    exit 1
fi

if [ $? != 0 ];
then
    echo "Terminating..." >&2
    exit 1
fi

eval set -- "$ARGS"

type=

while true
do
    case "$1" in
        --help)
            help
            break
            ;;
        --version)
            version
            break
            ;;
        --type)
            type=$2
            shift 2
            ;;
        --)
            shift
            break
            ;;
    esac
done

case ${type} in
    server)
        server_entrance
        break
        ;;
    client)
        client_entrance
        break
        ;;
    *)
        #print_color ${COLOR_ERROR} "type must by server or client."
        break
        ;;
esac