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
print_info "请输入流媒体转发设置所需的信息:"

# Get Domain Name
while true; do 
    read -p "请输入您的域名 (例如: stream.example.com): " DOMAIN
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

# Get Backend URL
while true; do 
    read -p "请输入后端流媒体URL (例如: https://d1vnr7amzbx49s.cloudfront.net/): " BACKEND_URL
    if [[ -z "$BACKEND_URL" ]]; then 
        print_error "后端URL不能为空，请重新输入。"
    elif [[ ! "$BACKEND_URL" =~ ^https?:// ]]; then 
        print_error "后端URL应以http://或https://开头，请重新输入。"
    else 
        # 移除末尾的斜杠（如果有）
        BACKEND_URL=${BACKEND_URL%/}
        break
    fi
done

# Extract backend host from URL
BACKEND_HOST=$(echo "$BACKEND_URL" | sed -E 's|^https?://([^/]+).*|\1|')

# Get Stream Path
read -p "请输入流媒体访问路径 (默认: /live/): " STREAM_PATH
STREAM_PATH=${STREAM_PATH:-/live/}
# 确保路径以/开头和结尾
[[ "$STREAM_PATH" != /* ]] && STREAM_PATH="/$STREAM_PATH"
[[ "$STREAM_PATH" != */ ]] && STREAM_PATH="$STREAM_PATH/"

# Get Authentication Username
read -p "请输入访问流媒体的用户名 (默认: streamuser): " AUTH_USER
AUTH_USER=${AUTH_USER:-streamuser}

# Get Authentication Password
while true; do
    read -s -p "请输入访问流媒体的密码: " AUTH_PASS
    echo
    if [[ -z "$AUTH_PASS" ]]; then
        print_error "密码不能为空，请重新输入。"
    else
        read -s -p "请再次输入密码确认: " AUTH_PASS_CONFIRM
        echo
        if [[ "$AUTH_PASS" != "$AUTH_PASS_CONFIRM" ]]; then
            print_error "两次输入的密码不匹配，请重新输入。"
        else
            break
        fi
    fi
done

# --- Configuration Confirmation ---
echo
print_info "--- 请确认以下信息 ---"
print_info "域名:          $DOMAIN"
print_info "Email 地址:    $EMAIL"
print_info "后端URL:       $BACKEND_URL"
print_info "流媒体路径:    $STREAM_PATH"
print_info "认证用户名:    $AUTH_USER"
print_info "认证密码:      [已设置]"
print_info "-------------------------"
read -p "信息是否正确？按 Enter 键继续，按 Ctrl+C 取消..." confirm_enter_key
echo

# --- Function to Install Prerequisites ---
function install_prerequisites {
    print_info "检查并安装必要的软件包..."
    local packages_to_install=()

    # Essential for web serving & proxy
    if ! command_exists nginx; then packages_to_install+=("nginx"); fi

    # Essential for Let's Encrypt certificates
    if ! command_exists certbot; then packages_to_install+=("certbot"); fi
    if ! package_installed python3-certbot-nginx; then packages_to_install+=("python3-certbot-nginx"); fi

    # Essential for password authentication
    if ! command_exists htpasswd; then packages_to_install+=("apache2-utils"); fi

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
    if command_exists systemctl; then
        print_info "正在启动 Nginx 服务..."
        sudo systemctl start nginx || { 
            print_error "启动 Nginx 失败。请检查 'sudo systemctl status nginx' 和 'sudo journalctl -xeu nginx.service'"
            exit 1
        }
    else
        print_warning "无法使用 systemctl 启动 Nginx。"
    fi
}

# --- Function to Create Password File ---
function create_password_file {
    print_info "创建认证密码文件..."
    # 创建密码文件目录（如果不存在）
    sudo mkdir -p /etc/nginx/auth/
    # 使用htpasswd创建密码文件
    echo "$AUTH_PASS" | sudo htpasswd -c -i /etc/nginx/auth/.htpasswd "$AUTH_USER" || {
        print_error "创建密码文件失败。"
        exit 1
    }
    print_info "密码文件已创建: /etc/nginx/auth/.htpasswd"
}

# --- Function to Configure Nginx Log Format ---
function configure_nginx_log_format {
    print_info "配置 Nginx 日志格式..."
    local nginx_conf="/etc/nginx/nginx.conf"
    local backup_file="/etc/nginx/nginx.conf.bak"
    
    # 创建配置文件备份
    sudo cp "$nginx_conf" "$backup_file"
    
    # 检查配置文件中是否已存在自定义日志格式
    if sudo grep -q "log_format auth_log" "$nginx_conf"; then
        print_info "自定义日志格式已存在，跳过配置。"
        return 0
    fi
    
    # 添加自定义日志格式到http块
    sudo awk '
    /http {/ {
        print;
        print "    # Custom log format for authentication logs";
        print "    log_format auth_log \047$remote_addr - $remote_user [$time_local] \"$request\" "
        print "                      $status $body_bytes_sent \"$http_referer\" "
        print "                      \"$http_user_agent\"\047;";
        next;
    }
    {print}
    ' "$nginx_conf" | sudo tee "$nginx_conf.tmp" > /dev/null
    
    sudo mv "$nginx_conf.tmp" "$nginx_conf"
    print_info "Nginx 日志格式已配置。"
}

# --- Function to Obtain Certificate using Standalone mode ---
function obtain_certificate_standalone {
    local domain_args=("-d" "$DOMAIN")
    local cert_path="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"

    # Check if certificate already exists
    if [ -f "$cert_path" ]; then
        print_info "证书似乎已存在于 $cert_path。尝试续签..."
        sudo certbot renew --cert-name "$DOMAIN" \
            --pre-hook "systemctl stop nginx" \
            --post-hook "systemctl start nginx" || {
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
        --deploy-hook "systemctl restart nginx" \
        --pre-hook "systemctl stop nginx" \
        --post-hook "systemctl start nginx" \
        || { print_error "Certbot 获取证书失败 (certonly --standalone)。"; return 1; }

    print_info "证书获取成功。"
    return 0 # Indicate success
}

# --- Function to Generate Nginx Stream Proxy Config ---
function generate_stream_proxy_config {
    print_info "生成 Nginx 流媒体代理配置..."
    
    # 定义证书路径
    local ssl_cert="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    local ssl_key="/etc/letsencrypt/live/$DOMAIN/privkey.pem"

    # 检查证书文件是否实际存在
    if [ ! -f "$ssl_cert" ] || [ ! -f "$ssl_key" ]; then
        print_error "证书文件未在预期路径找到: $ssl_cert 或 $ssl_key"
        print_error "无法生成 Nginx 配置。"
        exit 1
    fi

    # 创建Nginx站点配置
    local nginx_conf="/etc/nginx/sites-available/stream_proxy_$DOMAIN"
    
    sudo tee "$nginx_conf" > /dev/null << EOF
# --- HTTPS Server Block for $DOMAIN ---
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    # --- Domain ---
    server_name $DOMAIN;

    # --- SSL/TLS Certificate Configuration ---
    ssl_certificate     $ssl_cert;
    ssl_certificate_key $ssl_key;

    # --- SSL/TLS Security Settings ---
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;

    # --- Stream Proxy Location with Password and Logging ---
    location $STREAM_PATH {
        # --- Password Protection ---
        auth_basic "Password Protected Stream";
        auth_basic_user_file /etc/nginx/auth/.htpasswd;

        # --- Reverse Proxy Settings ---
        proxy_pass $BACKEND_URL/;
        proxy_set_header Host $BACKEND_HOST;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_cache off;
        proxy_redirect off;

        # --- Access Log ---
        access_log /var/log/nginx/stream_auth.log auth_log;
    }

    # Other paths return 403 Forbidden
    location / {
        return 403 "Forbidden";
    }
}

# --- HTTP to HTTPS Redirect ---
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}
EOF

    # 启用站点配置
    if [ ! -L "/etc/nginx/sites-enabled/stream_proxy_$DOMAIN" ]; then
        sudo ln -s "$nginx_conf" "/etc/nginx/sites-enabled/stream_proxy_$DOMAIN"
    fi

    print_info "Nginx 流媒体代理配置已生成并启用。"
}

# --- Function to Test Config and Start/Reload Nginx ---
function test_and_start_nginx {
    print_info "检查并重载 Nginx 配置..."
    if sudo nginx -t; then
        if systemctl is-active --quiet nginx; then
            sudo systemctl reload nginx
        else
            sudo systemctl start nginx
        fi
        print_info "Nginx 配置已成功应用。"
    else
        print_error "Nginx 配置测试失败！请检查配置文件。"
        exit 1
    fi
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

# --- Function to Configure Firewall ---
function configure_firewall {
    # Check if ufw is installed and enabled
    if command_exists ufw && sudo ufw status | grep -q "Status: active"; then
        print_info "配置防火墙规则..."
        sudo ufw allow 'Nginx Full' || print_warning "添加防火墙规则失败。"
        sudo ufw reload || print_warning "重新加载防火墙规则失败。"
        print_info "防火墙规则已更新。"
    else
        print_info "UFW防火墙未启用或未安装，跳过防火墙配置。"
    fi
}

# --- Main Execution Flow ---
print_info "=== 开始 SSL 证书安装和流媒体转发配置 ==="

# 1. 安装必备软件包
install_prerequisites

# 2. 创建密码文件
create_password_file

# 3. 配置Nginx日志格式
configure_nginx_log_format

# 4. 停止 Nginx (为 certonly --standalone 做准备)
stop_nginx

# 5. 获取证书 (Standalone 模式) 
if ! obtain_certificate_standalone; then
    print_warning "证书获取失败。尝试重新启动 Nginx (如果之前在运行)..."
    start_nginx
    exit 1
fi

# 6. 生成流媒体代理配置
generate_stream_proxy_config

# 7. 测试并重载Nginx配置
test_and_start_nginx

# 8. 验证自动续签设置
verify_auto_renewal

# 9. 配置防火墙
configure_firewall

# --- 完成 ---
print_info "==========================================================="
print_info "            流媒体转发配置已完成！"
print_info "-----------------------------------------------------------"
print_info "访问地址:      https://$DOMAIN$STREAM_PATH"
print_info "用户名:        $AUTH_USER"
print_info "密码:          [已设置]"
print_info "后端服务:      $BACKEND_URL"
print_info "-----------------------------------------------------------"
print_info "证书路径:      /etc/letsencrypt/live/$DOMAIN/"
print_info "密码文件:      /etc/nginx/auth/.htpasswd"
print_info "日志文件:      /var/log/nginx/stream_auth.log"
print_info "-----------------------------------------------------------"
print_info "如需修改密码，请运行:"
print_info "sudo htpasswd -c /etc/nginx/auth/.htpasswd $AUTH_USER"
print_info "如需添加新用户，请运行:"
print_info "sudo htpasswd /etc/nginx/auth/.htpasswd 新用户名"
print_info "==========================================================="

exit 0
