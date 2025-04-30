#!/bin/bash

# --- Function Definitions ---
function print_info { echo "[INFO] $1"; }
function print_warning { echo "[WARN] $1"; }
function print_error { echo "[ERROR] $1" >&2; }

# Function to check if a command exists
function command_exists { command -v "$1" &> /dev/null; }

# Function to check if a package is installed (Debian/Ubuntu specific)
function package_installed { dpkg -s "$1" &> /dev/null; }

# --- Configuration Variables (Pre-filled based on your info) ---
DEFAULT_DOMAIN="news.hitony666.top"
DEFAULT_BACKEND_URL="https://d1vnr7amzbx49s.cloudfront.net/" # Ensure trailing slash if needed by proxy logic
DEFAULT_STREAM_PATH="/live/" # Access will be https://domain/live/index_1.m3u8
DEFAULT_CERT_BASE_DIR="/root/cert" # Base directory where certs are currently stored

# --- Get User Input (Allow overrides, but use defaults) ---
print_info "请输入流媒体转发设置所需的信息 (按 Enter 使用默认值):"

read -p "请输入您的域名 (默认: $DEFAULT_DOMAIN): " DOMAIN
DOMAIN=${DOMAIN:-$DEFAULT_DOMAIN}

# Validate Domain
if [[ -z "$DOMAIN" ]]; then
    print_error "域名不能为空。"
    exit 1
elif [[ "$DOMAIN" =~ [[:space:]] ]]; then
    print_error "域名不应包含空格。"
    exit 1
fi

# Certificate Paths (Derived from Domain and Base Dir)
CURRENT_FULLCHAIN_PATH="${DEFAULT_CERT_BASE_DIR}/${DOMAIN}/fullchain.pem"
CURRENT_PRIVKEY_PATH="${DEFAULT_CERT_BASE_DIR}/${DOMAIN}/privkey.pem"

print_info "将使用的当前证书路径:"
print_info "  全链证书: $CURRENT_FULLCHAIN_PATH"
print_info "  私钥文件: $CURRENT_PRIVKEY_PATH"
read -p "证书路径是否正确? 按 Enter 确认, 或 Ctrl+C 取消..." confirm_cert_paths

# Check if certificate files exist at the source location
if [ ! -f "$CURRENT_FULLCHAIN_PATH" ]; then
    print_error "错误: 证书文件未找到: $CURRENT_FULLCHAIN_PATH"
    exit 1
fi
if [ ! -f "$CURRENT_PRIVKEY_PATH" ]; then
    print_error "错误: 私钥文件未找到: $CURRENT_PRIVKEY_PATH"
    exit 1
fi


read -p "请输入后端流媒体基础URL (默认: $DEFAULT_BACKEND_URL): " BACKEND_URL
BACKEND_URL=${BACKEND_URL:-$DEFAULT_BACKEND_URL}
# Validate Backend URL
if [[ -z "$BACKEND_URL" ]]; then
    print_error "后端URL不能为空。"
    exit 1
elif [[ ! "$BACKEND_URL" =~ ^https?:// ]]; then
    print_error "后端URL应以http://或https://开头。"
    exit 1
fi
# Ensure trailing slash for proxy_pass logic if needed (depends on how backend structures URLs)
[[ "$BACKEND_URL" != */ ]] && BACKEND_URL="$BACKEND_URL/"


# Extract backend host from URL for Host header
BACKEND_HOST=$(echo "$BACKEND_URL" | sed -E 's|^https?://([^/]+).*|\1|')

read -p "请输入流媒体访问路径 (默认: $DEFAULT_STREAM_PATH): " STREAM_PATH
STREAM_PATH=${STREAM_PATH:-$DEFAULT_STREAM_PATH}
# Ensure path starts and ends with /
[[ "$STREAM_PATH" != /* ]] && STREAM_PATH="/$STREAM_PATH"
[[ "$STREAM_PATH" != */ ]] && STREAM_PATH="$STREAM_PATH/"

# Get Authentication Username
read -p "请输入访问流媒体的用户名 (例如: streamuser): " AUTH_USER
# Validate Username (basic)
if [[ -z "$AUTH_USER" ]]; then
    print_error "用户名不能为空。"
    exit 1
elif [[ "$AUTH_USER" =~ [[:space:]] ]]; then
    print_error "用户名不应包含空格。"
    exit 1
fi

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
print_info "域名:              $DOMAIN"
print_info "当前证书全链路径:  $CURRENT_FULLCHAIN_PATH"
print_info "当前证书私钥路径:  $CURRENT_PRIVKEY_PATH"
print_info "后端URL:           $BACKEND_URL"
print_info "后端Host头:        $BACKEND_HOST"
print_info "流媒体访问路径:    $STREAM_PATH"
print_info "认证用户名:        $AUTH_USER"
print_info "认证密码:          [已设置]"
print_info "-------------------------"
print_warning "脚本将把证书文件移动到 /etc/nginx/ssl/$DOMAIN/ 以确保 Nginx 可以访问。"
read -p "信息是否正确？按 Enter 键继续，按 Ctrl+C 取消..." confirm_enter_key
echo

# --- Define Target Certificate Paths ---
TARGET_SSL_DIR="/etc/nginx/ssl/${DOMAIN}"
TARGET_FULLCHAIN_PATH="${TARGET_SSL_DIR}/fullchain.pem"
TARGET_PRIVKEY_PATH="${TARGET_SSL_DIR}/privkey.pem"
PASSWORD_FILE="/etc/nginx/.htpasswd" # Using standard location from manual steps
LOG_FILE="/var/log/nginx/m3u8_auth.log" # Custom log file
SITE_CONFIG_NAME="m3u8_proxy_${DOMAIN}" # Nginx site config filename

# --- Function to Install Prerequisites ---
function install_prerequisites {
    print_info "检查并安装必要的软件包 (nginx, apache2-utils)..."
    local packages_to_install=()

    if ! command_exists nginx; then packages_to_install+=("nginx"); fi
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

# --- Function to Move and Secure Certificates ---
function move_and_secure_certificates {
    print_info "正在移动并设置证书文件权限..."
    print_info "目标目录: $TARGET_SSL_DIR"

    # Create target directory
    sudo mkdir -p "$TARGET_SSL_DIR" || { print_error "创建目标证书目录失败: $TARGET_SSL_DIR"; exit 1; }

    # Move files
    print_info "移动 $CURRENT_FULLCHAIN_PATH -> $TARGET_FULLCHAIN_PATH"
    sudo mv "$CURRENT_FULLCHAIN_PATH" "$TARGET_FULLCHAIN_PATH" || { print_error "移动 fullchain.pem 失败。"; exit 1; }
    print_info "移动 $CURRENT_PRIVKEY_PATH -> $TARGET_PRIVKEY_PATH"
    sudo mv "$CURRENT_PRIVKEY_PATH" "$TARGET_PRIVKEY_PATH" || { print_error "移动 privkey.pem 失败。"; exit 1; }

    # Set ownership and permissions
    sudo chown -R root:root "$TARGET_SSL_DIR" || { print_error "设置证书目录所有权失败。"; exit 1; }
    sudo chmod 644 "$TARGET_FULLCHAIN_PATH" || { print_error "设置 fullchain.pem 权限失败。"; exit 1; }
    sudo chmod 600 "$TARGET_PRIVKEY_PATH" || { print_error "设置 privkey.pem 权限失败。"; exit 1; }

    print_info "证书已成功移动并设置权限。"
}

# --- Function to Create Password File ---
function create_password_file {
    print_info "创建认证密码文件: $PASSWORD_FILE"
    # Use htpasswd to create/update the password file
    # The -c flag creates the file or overwrites it if it exists
    # The -b flag reads the password from the command line (less secure history-wise, but okay for script)
    # The -i flag reads password from stdin (more secure)
    echo "$AUTH_PASS" | sudo htpasswd -c -i "$PASSWORD_FILE" "$AUTH_USER" || {
        print_error "创建密码文件失败。"
        exit 1
    }
    # Secure the password file
    sudo chown root:www-data "$PASSWORD_FILE" # Allow nginx group to read
    sudo chmod 640 "$PASSWORD_FILE"
    print_info "密码文件已创建并设置权限。"
}

# --- Function to Configure Nginx Log Format ---
function configure_nginx_log_format {
    print_info "配置 Nginx 自定义日志格式 'auth_log'..."
    local nginx_conf="/etc/nginx/nginx.conf"
    local log_format_name="auth_log"
    local log_format_string="'\$remote_addr - \$remote_user [\$time_local] \"\$request\" \$status \$body_bytes_sent \"\$http_referer\" \"\$http_user_agent\"'"

    # Check if the format already exists in nginx.conf
    if sudo grep -q "log_format ${log_format_name}" "$nginx_conf"; then
        print_info "日志格式 '${log_format_name}' 已存在于 $nginx_conf，跳过配置。"
        return 0
    fi

    # Create backup
    sudo cp "$nginx_conf" "${nginx_conf}.bak_$(date +%F_%T)"
    print_info "已创建备份: ${nginx_conf}.bak_..."

    # Add log format inside the http block
    # Use sed to insert the line after the first line containing 'http {'
    sudo sed -i "/http {/a \    log_format ${log_format_name} ${log_format_string}; # Added by script" "$nginx_conf" || {
         print_error "向 $nginx_conf 添加日志格式失败。"
         print_warning "请手动将以下行添加到 $nginx_conf 的 http {} 块内:"
         print_warning "log_format ${log_format_name} ${log_format_string};"
         # Continue, maybe nginx -t will catch it later
         return 1
     }

    print_info "自定义日志格式 '${log_format_name}' 已添加到 $nginx_conf。"
    return 0
}


# --- Function to Generate Nginx Site Configuration ---
function generate_nginx_site_config {
    print_info "生成 Nginx 站点配置文件..."
    local site_conf_path="/etc/nginx/sites-available/${SITE_CONFIG_NAME}"

    # Create Nginx site configuration using the moved certificate paths
    sudo tee "$site_conf_path" > /dev/null << EOF
# --- HTTPS Server Block for $DOMAIN ---
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    server_name $DOMAIN;

    # --- SSL/TLS Certificate Configuration (Moved Paths) ---
    ssl_certificate     $TARGET_FULLCHAIN_PATH;
    ssl_certificate_key $TARGET_PRIVKEY_PATH;

    # --- SSL/TLS Security Settings (Recommended) ---
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;
    # Add other security headers if desired (e.g., Strict-Transport-Security)
    # add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    # --- M3U8 Proxy Location ---
    # Access via https://$DOMAIN$STREAM_PATH...
    location $STREAM_PATH {
        # --- Password Protection ---
        auth_basic "Password Protected Stream";
        auth_basic_user_file $PASSWORD_FILE;

        # --- Reverse Proxy Settings ---
        proxy_pass $BACKEND_URL; # Backend URL (ensure trailing / is correct for your need)

        # --- Proxy Headers (Crucial for CloudFront/backends) ---
        proxy_set_header Host $BACKEND_HOST; # Set Host to backend hostname
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # --- Settings for Streaming ---
        proxy_http_version 1.1;
        proxy_set_header Connection ""; # Disable keep-alive to backend for simple proxying
        proxy_buffering off; # Important for live streams
        proxy_cache off; # Disable caching for this proxy
        proxy_redirect off; # Don't follow backend redirects automatically

        # --- Access Log (Using custom format) ---
        access_log $LOG_FILE auth_log;
        error_log /var/log/nginx/m3u8_error.log; # Separate error log for this location if needed
    }

    # --- Optional: Deny access to other paths ---
    location / {
        return 403 "Forbidden";
    }
}

# --- HTTP (80) to HTTPS Redirect (Recommended) ---
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;

    # Redirect all HTTP traffic to HTTPS
    return 301 https://\$host\$request_uri;
}
EOF

    if [ $? -ne 0 ]; then
        print_error "写入 Nginx 站点配置文件失败: $site_conf_path"
        exit 1
    fi

    print_info "Nginx 站点配置文件已生成: $site_conf_path"

    # Enable the site by creating a symlink
    local enabled_site_link="/etc/nginx/sites-enabled/${SITE_CONFIG_NAME}"
    if [ -L "$enabled_site_link" ]; then
        print_info "站点符号链接已存在，跳过创建。"
    elif [ -e "$enabled_site_link" ]; then
         print_warning "在 $enabled_site_link 处存在一个文件而不是符号链接。请手动检查。"
    else
        sudo ln -s "$site_conf_path" "$enabled_site_link" || {
            print_error "创建 Nginx 站点符号链接失败。"
            exit 1
        }
        print_info "Nginx 站点配置已启用。"
    fi

    # Optional: Remove default site if it exists and conflicts
    if [ -L "/etc/nginx/sites-enabled/default" ]; then
         print_info "检测到默认站点配置，将尝试移除以避免冲突..."
         sudo rm /etc/nginx/sites-enabled/default || print_warning "移除默认站点链接失败。"
    fi
}

# --- Function to Test Config and Reload Nginx ---
function test_and_reload_nginx {
    print_info "检查 Nginx 配置语法..."
    if sudo nginx -t; then
        print_info "Nginx 配置测试成功。正在重新加载 Nginx..."
        sudo systemctl reload nginx || {
            print_error "重新加载 Nginx 失败。尝试重启..."
            sudo systemctl restart nginx || {
                 print_error "重启 Nginx 也失败了。请检查 Nginx 状态和日志:"
                 print_error "sudo systemctl status nginx"
                 print_error "sudo journalctl -xeu nginx.service"
                 print_error "sudo tail -n 50 /var/log/nginx/error.log"
                 exit 1
            }
        }
        print_info "Nginx 已成功重新加载/启动。"
    else
        print_error "Nginx 配置测试失败！请检查错误信息并修复配置文件。"
        print_error "检查: $nginx_conf 和 /etc/nginx/sites-available/${SITE_CONFIG_NAME}"
        exit 1
    fi
}

# --- Function to Configure Firewall ---
function configure_firewall {
    if ! command_exists ufw; then
        print_info "未找到 UFW 防火墙，跳过配置。"
        return
    fi

    if sudo ufw status | grep -q "Status: active"; then
        print_info "配置 UFW 防火墙规则..."
        # Allow HTTP (for redirect) and HTTPS
        sudo ufw allow 'Nginx Full' || print_warning "添加 'Nginx Full' 防火墙规则失败。"
        # Explicitly allow ports just in case 'Nginx Full' isn't defined well
        sudo ufw allow 80/tcp || print_warning "允许端口 80 失败。"
        sudo ufw allow 443/tcp || print_warning "允许端口 443 失败。"
        # Reload UFW (only if it was already active)
        # sudo ufw reload || print_warning "重新加载 UFW 规则失败。" # Reload might disrupt connections, consider if needed
        print_info "防火墙规则已更新 (确保 80/tcp 和 443/tcp 已允许)。"
        print_info "当前 UFW 状态:"
        sudo ufw status | sed 's/^/[UFW] /' # Indent output for clarity
    else
        print_info "UFW 防火墙未激活，跳过规则配置。"
        print_warning "如果稍后启用 UFW，请确保允许端口 80 和 443。"
    fi
}

# --- Main Execution Flow ---
print_info "=== 开始 Nginx M3U8 代理配置 ==="

# 1. 安装必备软件包
install_prerequisites

# 2. 移动并保护证书文件 (关键步骤)
move_and_secure_certificates

# 3. 创建密码文件
create_password_file

# 4. 配置 Nginx 全局日志格式
configure_nginx_log_format

# 5. 生成并启用 Nginx 站点配置
generate_nginx_site_config

# 6. 测试并重载 Nginx 配置
test_and_reload_nginx

# 7. 配置防火墙
configure_firewall

# --- 完成 ---
echo
print_info "==========================================================="
print_info "          Nginx M3U8 代理配置已完成！"
print_info "-----------------------------------------------------------"
print_info "访问地址:      https://$DOMAIN${STREAM_PATH}index_1.m3u8" # Assuming index_1.m3u8 is the file
print_info "用户名:        $AUTH_USER"
print_info "密码:          [已设置]"
print_info "后端服务:      $BACKEND_URL"
print_info "-----------------------------------------------------------"
print_info "证书路径:      $TARGET_SSL_DIR"
print_info "密码文件:      $PASSWORD_FILE"
print_info "访问日志:      $LOG_FILE"
print_info "-----------------------------------------------------------"
print_info "如需修改密码，请运行:"
print_info "echo '新密码' | sudo htpasswd -i $PASSWORD_FILE $AUTH_USER"
print_info "如需添加新用户，请运行 (注意不要加 -c):"
print_info "sudo htpasswd $PASSWORD_FILE 新用户名"
print_info "==========================================================="
print_info "请使用支持 HLS 和 Basic Auth 的播放器 (如 VLC) 测试访问。"
print_info "如果遇到问题，请检查 Nginx 日志： /var/log/nginx/error.log, /var/log/nginx/m3u8_error.log, 和 $LOG_FILE"
echo

exit 0