#!/bin/bash

# 一键启用BBR脚本
# 适用于Ubuntu/Debian等Linux系统
# 需要以root权限运行

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
PLAIN='\033[0m'

# 检查是否以root权限运行
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}错误：此脚本必须以root权限运行！${PLAIN}" 
   exit 1
fi

# 检查是否支持fq队列调度算法
check_fq_support() {
    if ! tc qdisc show | grep -q fq; then
        echo -e "${YELLOW}正在检查fq队列调度算法支持...${PLAIN}"
        
        # 检查tc命令是否存在
        if ! command -v tc &> /dev/null; then
            echo -e "${YELLOW}安装交通控制工具...${PLAIN}"
            if [[ -f /etc/debian_version ]]; then
                apt update
                apt install -y iproute2
            elif [[ -f /etc/redhat-release ]]; then
                yum install -y iproute
            else
                echo -e "${RED}未知的系统类型，无法安装必要的工具${PLAIN}"
                return 1
            fi
        fi
        
        # 尝试加载fq模块
        modprobe sch_fq
        if [[ $? -ne 0 ]]; then
            echo -e "${YELLOW}尝试安装内核模块...${PLAIN}"
            if [[ -f /etc/debian_version ]]; then
                apt update
                apt install -y linux-modules-extra-$(uname -r)
                modprobe sch_fq
            elif [[ -f /etc/redhat-release ]]; then
                yum install -y kernel-modules-extra
                modprobe sch_fq
            fi
        fi
        
        # 再次检查fq支持
        if tc qdisc add dev lo root fq 2>/dev/null; then
            tc qdisc del dev lo root fq 2>/dev/null
            echo -e "${GREEN}fq队列调度算法支持已确认${PLAIN}"
            return 0
        else
            echo -e "${RED}当前系统不支持fq队列调度算法，BBR可能无法正常工作${PLAIN}"
            return 1
        fi
    else
        echo -e "${GREEN}系统已支持fq队列调度算法${PLAIN}"
        return 0
    fi
}

# 检查Linux内核版本
check_kernel_version() {
    local kernel_version=$(uname -r | cut -d- -f1)
    local major=$(echo "$kernel_version" | cut -d. -f1)
    local minor=$(echo "$kernel_version" | cut -d. -f2)
    
    if [[ $major -lt 4 || ($major -eq 4 && $minor -lt 9) ]]; then
        echo -e "${YELLOW}当前内核版本为 $kernel_version${PLAIN}"
        echo -e "${RED}BBR要求内核版本至少为4.9，需要先升级内核${PLAIN}"
        ask_update_kernel
    else
        echo -e "${GREEN}内核版本为 $kernel_version，满足BBR要求${PLAIN}"
        check_fq_support && enable_bbr
    fi
}

# 询问是否升级内核
ask_update_kernel() {
    echo -e "${YELLOW}是否要升级内核以支持BBR？[y/n]${PLAIN}"
    read -r answer
    case $answer in
        [Yy]*)
            update_kernel
            ;;
        *)
            echo -e "${YELLOW}已取消操作${PLAIN}"
            exit 0
            ;;
    esac
}

# 升级内核（适用于Ubuntu/Debian）
update_kernel() {
    echo -e "${GREEN}准备升级内核...${PLAIN}"
    
    if [[ -f /etc/debian_version ]]; then
        # Debian/Ubuntu系统
        apt update
        apt install -y linux-image-generic linux-headers-generic
        echo -e "${GREEN}内核已升级，需要重启系统${PLAIN}"
        echo -e "${YELLOW}是否立即重启？[y/n]${PLAIN}"
        read -r reboot_answer
        if [[ $reboot_answer =~ ^[Yy]$ ]]; then
            reboot
        else
            echo -e "${YELLOW}请稍后手动重启系统，然后再次运行此脚本${PLAIN}"
            exit 0
        fi
    elif [[ -f /etc/redhat-release ]]; then
        # CentOS/RHEL系统
        yum -y install elrepo-release
        yum --enablerepo=elrepo-kernel -y install kernel-ml kernel-ml-headers
        # 修改GRUB默认启动项
        sed -i 's/GRUB_DEFAULT=.*/GRUB_DEFAULT=0/' /etc/default/grub
        if [[ -f /usr/sbin/grub2-mkconfig ]]; then
            grub2-mkconfig -o /boot/grub2/grub.cfg
        elif [[ -f /usr/sbin/grub-mkconfig ]]; then
            grub-mkconfig -o /boot/grub/grub.cfg
        fi
        echo -e "${GREEN}内核已升级，需要重启系统${PLAIN}"
        echo -e "${YELLOW}是否立即重启？[y/n]${PLAIN}"
        read -r reboot_answer
        if [[ $reboot_answer =~ ^[Yy]$ ]]; then
            reboot
        else
            echo -e "${YELLOW}请稍后手动重启系统，然后再次运行此脚本${PLAIN}"
            exit 0
        fi
    else
        echo -e "${RED}不支持的系统类型，请手动升级内核${PLAIN}"
        exit 1
    fi
}

# 尝试多种队列调度算法
try_alternate_qdisc() {
    local qdiscs=("fq" "fq_codel" "cake" "pfifo_fast")
    
    for qdisc in "${qdiscs[@]}"; do
        echo -e "${YELLOW}尝试使用 $qdisc 队列调度算法...${PLAIN}"
        
        # 尝试加载相应模块
        modprobe sch_$qdisc 2>/dev/null
        
        # 测试是否可用
        if tc qdisc add dev lo root $qdisc 2>/dev/null; then
            tc qdisc del dev lo root $qdisc 2>/dev/null
            echo -e "${GREEN}$qdisc 队列调度算法可用，将使用它与BBR配合${PLAIN}"
            echo "net.core.default_qdisc=$qdisc" > /etc/sysctl.d/99-bbr.conf
            echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/99-bbr.conf
            return 0
        fi
    done
    
    echo -e "${RED}未找到可用的队列调度算法，将使用系统默认值${PLAIN}"
    echo "net.ipv4.tcp_congestion_control=bbr" > /etc/sysctl.d/99-bbr.conf
    return 1
}

# 启用BBR
enable_bbr() {
    echo -e "${GREEN}正在启用BBR...${PLAIN}"
    
    # 检查BBR是否已启用
    if sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
        echo -e "${GREEN}BBR已经启用！${PLAIN}"
        echo -e "${GREEN}当前拥塞控制算法：$(sysctl -n net.ipv4.tcp_congestion_control)${PLAIN}"
        echo -e "${GREEN}当前队列调度算法：$(sysctl -n net.core.default_qdisc)${PLAIN}"
        return
    fi
    
    # 检查是否支持fq队列调度算法
    if tc qdisc add dev lo root fq 2>/dev/null; then
        tc qdisc del dev lo root fq 2>/dev/null
        # 配置sysctl参数
        cat > /etc/sysctl.d/99-bbr.conf << EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    else
        echo -e "${YELLOW}fq队列调度算法不可用，尝试替代方案...${PLAIN}"
        try_alternate_qdisc
    fi

    # 应用参数
    sysctl --system
    
    # 验证BBR是否开启
    if sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
        echo -e "${GREEN}BBR启用成功！${PLAIN}"
        echo -e "${GREEN}当前拥塞控制算法：$(sysctl -n net.ipv4.tcp_congestion_control)${PLAIN}"
        echo -e "${GREEN}当前队列调度算法：$(sysctl -n net.core.default_qdisc)${PLAIN}"
    else
        echo -e "${RED}BBR启用失败，请检查系统环境${PLAIN}"
    fi
}

# 主函数
main() {
    echo -e "${GREEN}===== 一键启用BBR脚本 =====${PLAIN}"
    check_kernel_version
}

# 执行主函数
main