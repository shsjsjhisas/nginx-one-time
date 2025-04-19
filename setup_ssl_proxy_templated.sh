#!/bin/bash

# --- Function Definitions ---
function print_info { echo "[INFO] $1"; }
function print_warning { echo "[WARN] $1"; }
function print_error { echo "[ERROR] $1" >&2; } # Error doesn't exit automatically

# Function to check if a command exists
function command_exists { command -v "$1" &> /dev/null; }

# Function to check if a package is installed
function package_installed { dpkg -s "$1" &> /dev/null; }

# --- Get User Input (Same as before) ---
print_info "请输入运行脚本所需的信息:"
# Get Domain Name
while true; do read -p "请输入您的域名 (例如: mydomain.com): " DOMAIN; if [[ -z "$DOMAIN" ]]; then print_error "域名不能为空，请重新输入。"; elif [[ "$DOMAIN" =~ [[:space:]] ]]; then print_error "域名不应包含空格，请重新输入。"; else break; fi; done
# Get Email Address
while true; do read -p "请输入您的邮箱地址 (用于 Let's Encrypt 账户和通知): " EMAIL; if [[ -z "$EMAIL" ]]; then print_error "邮箱地址不能为空，请重新输入。"; elif [[ ! "$EMAIL" == *@* ]]; then print_error "邮箱地址格式似乎无效 (缺少 '@')，请重新输入。"; else break; fi; done
# Get Internal Port
while true; do read -p "请输入内部应用程序正在监听的端口号 (1-65535): " INTERNAL_PORT; if [[ -z "$INTERNAL_PORT" ]]; then print_error "端口号不能为空，请重新输入。"; elif ! [[ "$INTERNAL_PORT" =~ ^[0-9]+$ ]]; then print_error "端口号必须是纯数字，请重新输入。"; elif (( INTERNAL_PORT <= 0 || INTERNAL_PORT > 65535 )); then print_error "端口号必须在 1 到 65535 之间，请重新输入。"; else break; fi; done

# --- Configuration Confirmation (Same as before) ---
echo; print_info "--- 请确认以下信息 ---"; print_info "域名:         $DOMAIN"; print_info "Email 地址:   $EMAIL"; print_info "内部端口:     $INTERNAL_PORT"; print_info "-------------------------"; read -p "信息是否正确？按 Enter 键继续，按 Ctrl+C 取消..." confirm_enter_key; echo

# --- Security Warning about Certificate Path ---
print_warning "-----------------------------------------------------------------------"
print_warning "重要提示：关于证书路径"
print_warning "您请求将证书放在 /root/cert/。然而，由于权限限制，Nginx (运行为 www-data)"
print_warning "通常无法访问 /root 目录。这会导致 Nginx 无法加载证书而启动失败。"
print_warning "为确保安全性和功能性，脚本将使用 Certbot 的标准安全路径："
print_warning "/etc/letsencrypt/live/$DOMAIN/"
print_warning "最终的 Nginx 配置将指向此标准路径。"
print_warning "-----------------------------------------------------------------------"
read -p "按 Enter 键接受并继续，或按 Ctrl+C 取消..." confirm_path_ack

# --- Function to Install Prerequisites ---
function install_prerequisites {
    print_info "检查并安装必要的软件包..."
    local packages_to_install=()

    # Essential for web serving & proxy
    if ! command_exists nginx; then packages_to_install+=("nginx"); fi

    # Essential for Let's Encrypt certificates
    if ! command_exists certbot; then packages_to_install+=("certbot"); fi
    # Although certbot package might bring it, explicitly check/add plugin
    if ! package_installed python3-certbot-nginx; then packages_to_install+=("python3-certbot-nginx"); fi

    # Essential for script logic (text processing) - gawk provides awk
    if ! command_exists awk; then packages_to_install+=("gawk"); fi

    # Core utilities - normally present, but check anyway
    if ! command_exists grep; then print_warning "Core utility 'grep' not found, this is unusual."; fi
    if ! command_exists tee; then print_warning "Core utility 'tee' not found, this is unusual."; fi
    if ! command_exists dpkg; then print_warning "Core utility 'dpkg' not found, cannot check package status accurately."; fi
    if ! command_exists systemctl; then print_warning "System control 'systemctl' not found, system may not be systemd-based."; fi

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
        sudo systemctl start nginx || { print_error "启动 Nginx 失败。请检查 'sudo systemctl status nginx' 和 'sudo journalctl -xeu nginx.service'"; exit 1; }
     else
         print_warning "无法使用 systemctl 启动 Nginx。"
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
            --pre-hook "systemctl stop nginx" \
            --post-hook "systemctl start nginx" || {
            print_error "证书续签失败。"; exit 1;
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

# --- Function to Generate Final Nginx Config from Template ---
function generate_nginx_config {
    print_info "生成 Nginx 配置文件..."
    
    # 定义证书路径（使用标准的 Let's Encrypt 路径）
    local ssl_cert="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    local ssl_key="/etc/letsencrypt/live/$DOMAIN/privkey.pem"

    # 检查证书文件是否实际存在
    if [ ! -f "$ssl_cert" ] || [ ! -f "$ssl_key" ]; then
        print_error "证书文件未在预期路径找到: $ssl_cert 或 $ssl_key"
        print_error "无法生成 Nginx 配置。"
        exit 1
    fi

    # 创建Nginx配置
    sudo tee /etc/nginx/sites-available/"$DOMAIN" > /dev/null << EOF
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name $DOMAIN;

    ssl_certificate     $ssl_cert;
    ssl_certificate_key $ssl_key;

    location / {
        proxy_pass http://127.0.0.1:$INTERNAL_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
        client_max_body_size 100M;
        proxy_read_timeout 10m;
    }
}

server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}
EOF

    # 启用站点
    if [ ! -L /etc/nginx/sites-enabled/"$DOMAIN" ]; then
        sudo ln -s /etc/nginx/sites-available/"$DOMAIN" /etc/nginx/sites-enabled/
    fi
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

    # 注意：不再运行dry-run，以避免可能的问题
    print_info "已配置自动续签，将在证书到期前自动续签。"
}

# --- Main Execution Flow ---
print_info "=== 开始 SSL 证书安装和 Nginx 反向代理配置 ==="

# 1. 安装必备软件包
install_prerequisites

# 2. 停止 Nginx (为 certonly --standalone 做准备)
stop_nginx

# 3. 获取证书 (Standalone 模式) 并配置续签 Hooks
if ! obtain_certificate_standalone; then
    # Attempt to start Nginx again if cert acquisition failed, before exiting
    print_warning "证书获取失败。尝试重新启动 Nginx (如果之前在运行)..."
    start_nginx # Try to leave Nginx in a running state if possible
    exit 1
fi

# 4. 根据模板生成最终的 Nginx 配置文件
generate_nginx_config

# 5. 测试 Nginx 配置并启动/重载 Nginx
test_and_start_nginx

# 6. 验证自动续签设置
verify_auto_renewal

# --- 完成 ---
print_info "==============================================="
print_info "完成! 访问 https://$DOMAIN"
print_info "证书路径: /etc/letsencrypt/live/$DOMAIN/"
print_info "==============================================="

exit 0