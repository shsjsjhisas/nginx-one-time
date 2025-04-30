#!/bin/bash

# --- Function Definitions ---
function print_info { echo "[INFO] $1"; }
function print_warning { echo "[WARN] $1"; }
function print_error { echo "[ERROR] $1" >&2; }

# Function to check if a command exists
function command_exists { command -v "$1" &> /dev/null; }

# Function to check if a package is installed
function package_installed { dpkg -s "$1" &> /dev/null; }

# --- Get User Input ---
print_info "请输入证书配置所需的信息:"

# Get Domain Name
while true; do 
    read -p "请输入您的域名 (例如: example.com): " DOMAIN
    if [[ -z "$DOMAIN" ]]; then 
        print_error "域名不能为空，请重新输入。"
    elif [[ "$DOMAIN" =~ [[:space:]] ]]; then 
        print_error "域名不应包含空格，请重新输入。"
    else 
        break
    fi
done

# Get Email Address
while true; do 
    read -p "请输入您的邮箱地址 (用于 Let's Encrypt 账户和通知): " EMAIL
    if [[ -z "$EMAIL" ]]; then 
        print_error "邮箱地址不能为空，请重新输入。"
    elif [[ ! "$EMAIL" == *@* ]]; then 
        print_error "邮箱地址格式似乎无效 (缺少 '@')，请重新输入。"
    else 
        break
    fi
done

# --- Configuration Confirmation ---
echo
print_info "--- 请确认以下信息 ---"
print_info "域名:          $DOMAIN"
print_info "Email 地址:    $EMAIL"
print_info "证书目录:      /root/cert/$DOMAIN/"
print_info "-------------------------"
read -p "信息是否正确？按 Enter 键继续，按 Ctrl+C 取消..." confirm_enter_key
echo

# --- Function to Install Prerequisites ---
function install_prerequisites {
    print_info "检查并安装必要的软件包..."
    local packages_to_install=()

    # Essential for Let's Encrypt certificates
    if ! command_exists certbot; then packages_to_install+=("certbot"); fi
    
    # Check if nginx is installed, and if so, add the nginx plugin
    if command_exists nginx; then
        if ! package_installed python3-certbot-nginx; then 
            packages_to_install+=("python3-certbot-nginx"); 
        fi
    fi

    if [ ${#packages_to_install[@]} -gt 0 ]; then
        print_info "需要安装以下软件包: ${packages_to_install[*]}"
        sudo apt-get update || { print_error "更新软件包列表失败。"; exit 1; }
        sudo apt-get install -y "${packages_to_install[@]}" || { print_error "安装软件包失败。"; exit 1; }
        print_info "软件包安装完成。"
    else
        print_info "所有必要的软件包似乎都已安装。"
    fi
}

# --- Function to Stop Nginx Service ---
function stop_nginx {
    if command_exists systemctl && systemctl is-active --quiet nginx; then
        print_info "正在停止 Nginx 服务以进行证书获取..."
        sudo systemctl stop nginx || { print_warning "停止 Nginx 失败，可能它没有在运行？"; }
    else
        print_info "Nginx 未运行或无法通过 systemctl 管理，跳过停止步骤。"
    fi
}

# --- Function to Start Nginx Service ---
function start_nginx {
    if command_exists systemctl && command_exists nginx; then
        print_info "正在启动 Nginx 服务..."
        sudo systemctl start nginx || { 
            print_warning "启动 Nginx 失败。请检查 'sudo systemctl status nginx' 和 'sudo journalctl -xeu nginx.service'"
        }
    else
        print_info "Nginx 未安装或无法通过 systemctl 管理，跳过启动步骤。"
    fi
}

# --- Function to Obtain Certificate using Standalone mode ---
function obtain_certificate_standalone {
    local domain_args=("-d" "$DOMAIN")
    local cert_path="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"

    # Check if certificate already exists
    if [ -f "$cert_path" ]; then
        print_info "证书似乎已存在于 $cert_path。尝试续签..."
        sudo certbot renew --cert-name "$DOMAIN" \
            --pre-hook "command_exists nginx && systemctl stop nginx" \
            --post-hook "command_exists nginx && systemctl start nginx" || {
            print_error "证书续签失败。"
            exit 1
        }
        print_info "证书续签（如果需要）完成。"
        return 0 # Indicate success/completion
    fi

    print_info "为域名 ${domain_args[*]} 获取新的 Let's Encrypt 证书 (Standalone 模式)..."
    sudo certbot certonly --standalone --agree-tos --no-eff-email -n \
        "${domain_args[@]}" \
        -m "$EMAIL" \
        --pre-hook "command_exists nginx && systemctl stop nginx" \
        --post-hook "command_exists nginx && systemctl start nginx" \
        || { print_error "Certbot 获取证书失败 (certonly --standalone)。"; return 1; }

    print_info "证书获取成功。"
    return 0 # Indicate success
}

# --- Function to Create Certificate Directory and Copy Files ---
function configure_certificate_directory {
    print_info "配置证书到指定目录: /root/cert/$DOMAIN/"
    
    # Create target directory
    sudo mkdir -p "/root/cert/$DOMAIN/" || {
        print_error "创建目标目录失败。"
        exit 1
    }
    
    # Certificate source paths
    local source_cert="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    local source_key="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    local source_chain="/etc/letsencrypt/live/$DOMAIN/chain.pem"
    local source_cert_only="/etc/letsencrypt/live/$DOMAIN/cert.pem"
    
    # Target paths
    local target_cert="/root/cert/$DOMAIN/fullchain.pem"
    local target_key="/root/cert/$DOMAIN/privkey.pem"
    local target_chain="/root/cert/$DOMAIN/chain.pem"
    local target_cert_only="/root/cert/$DOMAIN/cert.pem"
    
    # Copy files
    sudo cp "$source_cert" "$target_cert" || {
        print_error "复制 fullchain.pem 失败。"
        exit 1
    }
    
    sudo cp "$source_key" "$target_key" || {
        print_error "复制 privkey.pem 失败。"
        exit 1
    }
    
    sudo cp "$source_chain" "$target_chain" || {
        print_error "复制 chain.pem 失败。"
        exit 1
    }
    
    sudo cp "$source_cert_only" "$target_cert_only" || {
        print_error "复制 cert.pem 失败。"
        exit 1
    }
    
    # Set proper permissions
    sudo chmod 600 "/root/cert/$DOMAIN/"*.pem || {
        print_error "设置文件权限失败。"
        exit 1
    }
    
    print_info "证书文件已成功复制到 /root/cert/$DOMAIN/ 目录。"
}

# --- Function to Create Renewal Hook for Copying Certificates ---
function create_renewal_hook {
    print_info "创建证书续签后自动复制的钩子脚本..."
    
    local hook_dir="/etc/letsencrypt/renewal-hooks/deploy"
    local hook_script="$hook_dir/copy-to-custom-dir.sh"
    
    # Create hook directory if not exists
    sudo mkdir -p "$hook_dir" || {
        print_error "创建钩子脚本目录失败。"
        exit 1
    }
    
    # Create the hook script
    sudo tee "$hook_script" > /dev/null << EOF
#!/bin/bash

# This script copies renewed certificates to the custom directory
# It runs automatically after successful certificate renewal

# Check if the renewed certificate is for our domain
if [ "\$RENEWED_LINEAGE" == "/etc/letsencrypt/live/$DOMAIN" ]; then
    # Create directory if not exists
    mkdir -p "/root/cert/$DOMAIN/"
    
    # Copy certificate files
    cp "\$RENEWED_LINEAGE/fullchain.pem" "/root/cert/$DOMAIN/fullchain.pem"
    cp "\$RENEWED_LINEAGE/privkey.pem" "/root/cert/$DOMAIN/privkey.pem"
    cp "\$RENEWED_LINEAGE/chain.pem" "/root/cert/$DOMAIN/chain.pem"
    cp "\$RENEWED_LINEAGE/cert.pem" "/root/cert/$DOMAIN/cert.pem"
    
    # Set proper permissions
    chmod 600 "/root/cert/$DOMAIN/"*.pem
    
    echo "[$(date)] Renewed certificates copied to /root/cert/$DOMAIN/" >> /var/log/letsencrypt/renewal-copy.log
fi
EOF
    
    # Make the hook script executable
    sudo chmod +x "$hook_script" || {
        print_error "设置钩子脚本执行权限失败。"
        exit 1
    }
    
    print_info "续签钩子脚本已创建: $hook_script"
}

# --- Function to Verify Auto Renewal ---
function verify_auto_renewal {
    print_info "验证自动续签设置..."
    local timer_active=false
    local cron_exists=false

    # Check systemd timer
    if systemctl list-unit-files | grep -q 'certbot.timer'; then
        if sudo systemctl is-active --quiet certbot.timer; then 
            print_info "certbot.timer 正在运行。"; 
            timer_active=true; 
        else 
            print_warning "Certbot systemd 定时器存在但未运行。尝试启动..."; 
            sudo systemctl start certbot.timer && sudo systemctl enable certbot.timer && timer_active=true || print_error "启动 Certbot timer 失败。"; 
        fi
    fi
    
    # Check cron job
    if [ -f /etc/cron.d/certbot ]; then 
        print_info "certbot cron 任务存在。"; 
        cron_exists=true; 
    fi
    
    if ! $timer_active && ! $cron_exists; then 
        print_warning "警告：未找到有效的 Certbot 自动续签任务。"; 
    fi

    print_info "已配置自动续签，将在证书到期前自动续签。"
}

# --- Main Execution Flow ---
print_info "=== 开始 SSL 证书安装和配置 ==="

# 1. 安装必备软件包
install_prerequisites

# 2. 停止 Nginx (如果存在)
stop_nginx

# 3. 获取证书 (Standalone 模式) 
if ! obtain_certificate_standalone; then
    print_warning "证书获取失败。尝试重新启动 Nginx (如果之前在运行)..."
    start_nginx
    exit 1
fi

# 4. 配置证书目录
configure_certificate_directory

# 5. 创建续签钩子
create_renewal_hook

# 6. 重启 Nginx (如果存在)
start_nginx

# 7. 验证自动续签设置
verify_auto_renewal

# --- 完成 ---
print_info "==========================================================="
print_info "            证书配置已完成！"
print_info "-----------------------------------------------------------"
print_info "域名:          $DOMAIN"
print_info "证书目录:      /root/cert/$DOMAIN/"
print_info "原始证书路径:  /etc/letsencrypt/live/$DOMAIN/"
print_info "-----------------------------------------------------------"
print_info "证书文件包括:"
print_info "- /root/cert/$DOMAIN/fullchain.pem (完整证书链)"
print_info "- /root/cert/$DOMAIN/privkey.pem (私钥)"
print_info "- /root/cert/$DOMAIN/chain.pem (证书链)"
print_info "- /root/cert/$DOMAIN/cert.pem (仅证书)"
print_info "-----------------------------------------------------------"
print_info "证书将自动续签，并在续签后自动复制到配置目录"
print_info "==========================================================="

exit 0
