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

# --- MODIFIED: Get Backend URL (Focus on Base URL) ---
while true; do
    print_info "后端URL应指向流媒体所在的 *基础目录*，而不是具体的 .m3u8 文件。"
    print_info "例如: 如果原始流是 https://cdn.example.com/live/stream.m3u8，"
    print_info "那么后端基础URL通常是 https://cdn.example.com/live/"
    read -p "请输入后端流媒体的基础URL (例如: https://example.net/live/): " BACKEND_URL_INPUT

    if [[ -z "$BACKEND_URL_INPUT" ]]; then
        print_error "后端URL不能为空，请重新输入。"
    elif [[ ! "$BACKEND_URL_INPUT" =~ ^https?:// ]]; then
        print_error "后端URL应以http://或https://开头，请重新输入。"
    elif [[ "$BACKEND_URL_INPUT" =~ \.(m3u8|mpd|ts|m4s|mp4)$ ]]; then
        print_warning "您输入的URL似乎包含了一个文件名 ($BACKEND_URL_INPUT)。"
        print_warning "通常应输入该文件所在的 *目录* URL。例如 'https://origin.com/stream/'。"
        read -p "是否要自动修正为基础目录？ (Y/n): " confirm_fix_url
        if [[ "$confirm_fix_url" =~ ^[Nn]$ ]]; then
            BACKEND_URL="$BACKEND_URL_INPUT" # User insists, proceed with caution
            print_warning "将按您的要求使用完整URL，这可能导致代理行为不符合预期。"
            # Remove trailing slash if user insisted on full URL (less likely to be correct for proxy_pass /)
             BACKEND_URL=${BACKEND_URL%/}
            break
        else
            # Attempt to fix by getting directory name
            # Need dirname command
            if ! command_exists dirname; then
                 print_error "'dirname' 命令未找到。请安装 'coreutils' (sudo apt install coreutils) 或手动输入基础URL。"
                 continue # Ask again
            fi
            BACKEND_URL=$(dirname "$BACKEND_URL_INPUT")
            # Ensure it ends with / after dirname might remove it
            [[ "$BACKEND_URL" != */ ]] && BACKEND_URL="$BACKEND_URL/"
            # Handle edge case where dirname results in '.' or just the scheme
            if [[ "$BACKEND_URL" == "./" ]] || [[ "$BACKEND_URL" == "http:/" ]] || [[ "$BACKEND_URL" == "https:/"]]; then
                BACKEND_URL=$(echo "$BACKEND_URL_INPUT" | sed -E 's|^(https?://[^/]+)/.*|\1/|')
            fi
            print_info "已将后端URL修正为基础路径: $BACKEND_URL"
            break
        fi
    else
        # User provided a likely base URL, ensure it ends with /
        BACKEND_URL="$BACKEND_URL_INPUT"
        [[ "$BACKEND_URL" != */ ]] && BACKEND_URL="$BACKEND_URL/"
        break
    fi
done
# --- END MODIFIED Backend URL Input ---

# Extract backend host from URL (No change needed here)
BACKEND_HOST=$(echo "$BACKEND_URL" | sed -E 's|^https?://([^/]+).*|\1|')

# Get Stream Path
read -p "请输入您希望在本机访问流媒体的路径 (默认: /live/): " STREAM_PATH
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
print_info "域名:               $DOMAIN"
print_info "Email 地址:         $EMAIL"
print_info "后端基础URL:        $BACKEND_URL" # Clarified label
print_info "本机访问路径:       $STREAM_PATH" # Clarified label
print_info "认证用户名:         $AUTH_USER"
print_info "认证密码:           [已设置]"
print_info "---"
print_info "通过组合 本机访问路径 和 原始流文件名/路径 来访问您的流。"
print_info "例如: 如果原始流是 ${BACKEND_URL}subdir/playlist.m3u8"
print_info "您的访问地址将是: https://$DOMAIN${STREAM_PATH}subdir/playlist.m3u8"
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
    # Nginx plugin is generally recommended for easier integration & renewals
    if ! package_installed python3-certbot-nginx; then packages_to_install+=("python3-certbot-nginx"); fi

    # Essential for password authentication
    if ! command_exists htpasswd; then packages_to_install+=("apache2-utils"); fi

    # Potentially needed for dirname in URL parsing
    if ! command_exists dirname; then packages_to_install+=("coreutils"); fi


    if [ ${#packages_to_install[@]} -gt 0 ]; then
        print_info "需要安装以下软件包: ${packages_to_install[*]}"
        sudo apt-get update || { print_error "更新软件包列表失败。"; exit 1; }
        sudo apt-get install -y "${packages_to_install[@]}" || { print_error "安装软件包失败。"; exit 1; }
        print_info "软件包安装完成。"
    else
        print_info "所有必要的软件包似乎都已安装。"
    fi
}

# --- Function to Stop Nginx Service (Used by Certbot hooks) ---
function stop_nginx_hook {
    # This function might be called by certbot hooks
    if command_exists systemctl && systemctl is-active --quiet nginx; then
        print_info "(Certbot Hook) 正在停止 Nginx 服务..."
        sudo systemctl stop nginx || { print_warning "(Certbot Hook) 停止 Nginx 失败。"; }
    fi
}

# --- Function to Start/Reload Nginx Service (Used by Certbot hooks) ---
function start_or_reload_nginx_hook {
    # This function might be called by certbot hooks
     if command_exists systemctl; then
        if systemctl is-active --quiet nginx; then
            print_info "(Certbot Hook) 正在重载 Nginx 服务..."
            sudo systemctl reload nginx || {
                print_warning "(Certbot Hook) 重载 Nginx 失败，尝试重启..."
                sudo systemctl restart nginx || print_error "(Certbot Hook) 重启 Nginx 也失败了。";
            }
        else
            print_info "(Certbot Hook) 正在启动 Nginx 服务..."
            sudo systemctl start nginx || print_error "(Certbot Hook) 启动 Nginx 失败。";
        fi
    fi
}


# --- Function to Create Password File ---
function create_password_file {
    print_info "创建认证密码文件..."
    local pass_dir="/etc/nginx/auth"
    local pass_file="$pass_dir/.htpasswd"
    # 创建密码文件目录（如果不存在）
    sudo mkdir -p "$pass_dir" || { print_error "创建目录 $pass_dir 失败。"; exit 1; }
    # 使用htpasswd创建密码文件 (-c creates, -i reads password from stdin)
    echo "$AUTH_PASS" | sudo htpasswd -c -i "$pass_file" "$AUTH_USER" || {
        print_error "创建密码文件 $pass_file 失败。"
        exit 1
    }
    # Set permissions: readable by root and the nginx group (usually www-data)
    sudo chown root:www-data "$pass_file" || print_warning "设置密码文件所有者失败。"
    sudo chmod 640 "$pass_file" || print_warning "设置密码文件权限失败。"
    print_info "密码文件已创建: $pass_file"
}

# --- Function to Configure Nginx Log Format ---
function configure_nginx_log_format {
    print_info "配置 Nginx 日志格式..."
    local nginx_conf="/etc/nginx/nginx.conf"
    local backup_file="$nginx_conf.bak.$(date +%s)"
    local http_block_marker="http {" # More reliable marker
    local log_format_name="auth_log"
    local log_format_string="    log_format $log_format_name '\$remote_addr - \$remote_user [\$time_local] \"\$request\" '\n'                      \$status \$body_bytes_sent \"\$http_referer\" '\n'                      \"\$http_user_agent\"';"


    # Check if the specific log format already exists
    if sudo grep -Pzo "(?s)http\s*\{[^}]*log_format\s+$log_format_name\s+" "$nginx_conf" > /dev/null; then
        print_info "自定义日志格式 '$log_format_name' 已存在于 http 块中，跳过配置。"
        return 0
    fi

     # Check if http block exists
     if ! sudo grep -q "$http_block_marker" "$nginx_conf"; then
        print_error "无法在 $nginx_conf 中找到 'http {' 块。无法自动添加日志格式。"
        return 1 # Indicate failure
    fi

    # Create backup
    sudo cp "$nginx_conf" "$backup_file" || { print_error "创建备份 $backup_file 失败。"; return 1; }
    print_info "已创建备份 $backup_file"

    # Add log format inside the http block using awk
    if ! sudo awk -v marker="$http_block_marker" -v format="$log_format_string" '
    BEGIN { added=0 }
    $0 ~ marker && !added {
        print;
        print ""; # Add a blank line for separation
        print "    # Custom log format for authentication logs (added by script)";
        print format;
        print ""; # Add a blank line for separation
        added=1;
        next;
    }
    {print}
    ' "$nginx_conf" > "$nginx_conf.tmp"; then
        print_error "使用 awk 添加日志格式时出错。"
        sudo rm -f "$nginx_conf.tmp" # Clean up temp file
        return 1
    fi

    # Check if awk actually added the format (basic check)
    if ! grep -q "log_format $log_format_name" "$nginx_conf.tmp"; then
         print_error "Awk 脚本未能添加日志格式。可能是 http 块格式问题。正在恢复备份。"
         sudo mv "$backup_file" "$nginx_conf"
         sudo rm -f "$nginx_conf.tmp"
         return 1
    fi

    # Test the temporary file before replacing the original
    if ! sudo nginx -t -c "$nginx_conf.tmp" > /dev/null; then
        print_error "添加日志格式后 Nginx 配置测试失败！正在恢复备份。"
        sudo mv "$backup_file" "$nginx_conf"
        sudo rm -f "$nginx_conf.tmp"
        return 1
    fi

    # Replace original with temporary file
    sudo mv "$nginx_conf.tmp" "$nginx_conf"
    print_info "Nginx 日志格式已配置。"
    return 0
}

# --- Function to Obtain Certificate using Nginx Plugin ---
# Switching to Nginx plugin as it's generally easier for renewals
function obtain_certificate_nginx {
    local domain_args=("-d" "$DOMAIN")
    local cert_path="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"

    # Check if certificate already exists
    if [ -f "$cert_path" ]; then
        print_info "证书似乎已存在于 $cert_path。尝试使用 Nginx 插件进行续签..."
        # Renew using nginx plugin, reload nginx on success
        sudo certbot renew --cert-name "$DOMAIN" --nginx --post-hook "systemctl reload nginx" || {
            print_error "证书续签失败。请检查 Certbot 日志 (/var/log/letsencrypt/letsencrypt.log) 和 Nginx 状态。"
            # Don't exit, maybe the existing cert is still valid
            return 1
        }
        print_info "证书续签（如果需要）完成。"
        return 0 # Indicate success/completion
    fi

    print_info "为域名 ${domain_args[*]} 获取新的 Let's Encrypt 证书 (Nginx 插件模式)..."
    # Ensure Nginx is running before using the plugin
    if ! systemctl is-active --quiet nginx; then
        print_info "Nginx 未运行，尝试启动以进行证书获取..."
        sudo systemctl start nginx || {
            print_error "启动 Nginx 失败。无法使用 Nginx 插件获取证书。"
            return 1
        }
    fi

    # Obtain cert using nginx plugin, automatically modifies config and reloads
    sudo certbot --nginx --agree-tos --no-eff-email -n \
        "${domain_args[@]}" \
        -m "$EMAIL" \
        || { print_error "Certbot 使用 Nginx 插件获取证书失败。"; return 1; }

    # Certbot --nginx usually handles reload, but double check
    if ! systemctl is-active --quiet nginx; then
         print_warning "Certbot 完成后 Nginx 似乎没有运行。尝试启动..."
         sudo systemctl start nginx || print_error "启动 Nginx 失败。"
    fi

    print_info "证书获取成功，Nginx 配置已由 Certbot 更新以处理 SSL。"
    return 0 # Indicate success
}

# --- Function to Generate Nginx Stream Proxy Config ---
function generate_stream_proxy_config {
    print_info "生成 Nginx 流媒体代理配置..."

    local ssl_cert="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    local ssl_key="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    local pass_file="/etc/nginx/auth/.htpasswd" # Consistent path

    # 检查证书文件是否实际存在
    if [ ! -f "$ssl_cert" ] || [ ! -f "$ssl_key" ]; then
        print_error "证书文件未在预期路径找到: $ssl_cert 或 $ssl_key"
        print_error "请确保证书已成功获取。无法生成 Nginx 配置。"
        return 1
    fi

    # 检查密码文件是否存在
    if [ ! -f "$pass_file" ]; then
        print_error "密码文件未在预期路径找到: $pass_file"
        print_error "无法生成 Nginx 配置。"
        return 1
    fi

    # 定义Nginx站点配置路径
    local nginx_conf_dir="/etc/nginx/sites-available"
    local nginx_conf="$nginx_conf_dir/stream_proxy_$DOMAIN.conf" # Add .conf extension
    local nginx_enabled_dir="/etc/nginx/sites-enabled"
    local nginx_symlink="$nginx_enabled_dir/stream_proxy_$DOMAIN.conf"

    sudo mkdir -p "$nginx_conf_dir" "$nginx_enabled_dir"


    # --- MODIFIED: Nginx Configuration Template ---
    # Uses BACKEND_URL (ends with /), STREAM_PATH (ends with /)
    # Uses $BACKEND_HOST for Host header
    # Uses standard Let's Encrypt includes
    # Uses correct password file path
    # Removed unnecessary explicit SSL settings covered by Let's Encrypt includes
    # Kept Connection: "" as it works for HLS
    sudo tee "$nginx_conf" > /dev/null << EOF
# --- HTTPS Server Block for $DOMAIN (Managed by Script) ---
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;

    # --- SSL ---
    # Certbot will manage these lines if using --nginx plugin,
    # but we set them here initially or if standalone was used.
    ssl_certificate $ssl_cert;
    ssl_certificate_key $ssl_key;
    include /etc/letsencrypt/options-ssl-nginx.conf; # Recommended SSL parameters
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;   # Recommended DH parameters

    # --- Security Headers ---
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    # add_header Referrer-Policy "strict-origin-when-cross-origin" always; # Uncomment if needed

    # --- Stream Proxy Location ---
    location $STREAM_PATH {
        # --- Password Protection ---
        auth_basic "Password Protected Stream";
        auth_basic_user_file $pass_file; # Use variable

        # --- Reverse Proxy Settings ---
        proxy_pass $BACKEND_URL; # $BACKEND_URL guaranteed to end with /
        proxy_set_header Host $BACKEND_HOST; # Set host to backend's expected host
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_http_version 1.1;
        proxy_set_header Connection ""; # Suitable for HLS
        proxy_buffering off;           # Crucial for streaming
        proxy_cache off;               # Disable cache for live streams
        proxy_redirect off;
        proxy_request_buffering off;   # Send client request body immediately
        proxy_read_timeout 24h;        # Long timeout for streaming
        proxy_send_timeout 24h;        # Long timeout for streaming

        # --- Logging ---
        access_log /var/log/nginx/stream_access.log auth_log; # Use custom format
        error_log /var/log/nginx/stream_error.log warn;      # Log proxy errors
    }

    # --- Root and Other Paths ---
    location / {
        return 403 "Forbidden";
        access_log off;
        log_not_found off;
    }

    # Required for Certbot HTTP-01 challenges (even if redirecting)
    # Ensure the root path is accessible by Nginx (www-data)
    location /.well-known/acme-challenge/ {
        root /var/www/html; # Default Certbot webroot, adjust if needed
        allow all;
    }
}

# --- HTTP to HTTPS Redirect ---
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;

    # Required for Certbot HTTP-01 challenges during initial setup or renewal
    location /.well-known/acme-challenge/ {
        root /var/www/html; # Default Certbot webroot, adjust if needed
        allow all;
    }

    # Redirect all other HTTP traffic to HTTPS
    location / {
      return 301 https://\$host\$request_uri;
    }
}
EOF
    # --- END MODIFIED Nginx Template ---


    # 启用站点配置
    if [ ! -L "$nginx_symlink" ]; then
        # Remove default config if it exists and this is the only site
        if [ -L "/etc/nginx/sites-enabled/default" ]; then
             print_warning "发现默认的 Nginx 站点配置，正在移除..."
             sudo rm -f "/etc/nginx/sites-enabled/default"
        fi
        sudo ln -s "$nginx_conf" "$nginx_symlink" || { print_error "创建符号链接 $nginx_symlink 失败。"; return 1; }
         print_info "Nginx 站点配置已启用: $nginx_symlink"
    else
        print_info "符号链接 $nginx_symlink 已存在。"
    fi

    print_info "Nginx 流媒体代理配置已生成。"
    return 0
}

# --- Function to Test Config and Reload Nginx ---
function test_and_reload_nginx {
    print_info "检查并应用 Nginx 配置..."
    if sudo nginx -t; then
        print_info "Nginx 配置测试通过。正在重载..."
        sudo systemctl reload nginx || {
             print_error "重载 Nginx 失败。尝试重启..."
             sudo systemctl restart nginx || {
                 print_error "重启 Nginx 也失败了。请检查 'sudo systemctl status nginx' 和 'sudo journalctl -xeu nginx.service'"
                 return 1 # Use return code
             }
        }
        print_info "Nginx 配置已成功应用。"
    else
        print_error "Nginx 配置测试失败！请检查生成的配置文件。"
        print_error "失败的配置文件可能是: $nginx_conf 或 /etc/nginx/nginx.conf"
        return 1 # Use return code
    fi
    return 0
}

# --- Function to Verify Auto Renewal ---
function verify_auto_renewal {
    print_info "验证 Certbot 自动续签设置..."
    local timer_active=false
    local cron_exists=false

    # Check systemd timer (preferred method)
    if systemctl list-unit-files --type=timer | grep -q 'certbot.timer'; then
        if sudo systemctl is-active --quiet certbot.timer; then
            print_info "Certbot systemd 定时器 (certbot.timer) 正在运行。"
            timer_active=true
        else
            print_warning "Certbot systemd 定时器存在但未运行。尝试启用并启动..."
            sudo systemctl enable certbot.timer && sudo systemctl start certbot.timer && timer_active=true || print_error "启动或启用 Certbot timer 失败。"
        fi
    fi

    # Check cron job (legacy check)
    if [ -f /etc/cron.d/certbot ] || crontab -l 2>/dev/null | grep -q 'certbot'; then
        print_info "检测到 Certbot cron 任务。"
        cron_exists=true
        if $timer_active; then
            print_warning "同时检测到 systemd 定时器和 cron 任务，建议仅使用 systemd 定时器。"
        fi
    fi

    if ! $timer_active && ! $cron_exists; then
        print_warning "警告：未找到有效的 Certbot 自动续签任务 (systemd timer 或 cron)。"
        print_warning "您可能需要手动设置续签或运行 'sudo certbot renew --dry-run' 进行测试。"
    else
        print_info "Certbot 自动续签似乎已配置。"
        print_info "运行 'sudo certbot renew --dry-run' 可以测试续签过程。"
    fi
}

# --- Function to Configure Firewall ---
function configure_firewall {
    # Check if ufw is installed and enabled
    if command_exists ufw && sudo ufw status | grep -q "Status: active"; then
        print_info "配置 UFW 防火墙规则..."
        local changed=false
        # Check for specific ports OR the Nginx Full profile
        if ! sudo ufw status verbose | grep -qw "80/tcp" && ! sudo ufw status verbose | grep -q "Nginx HTTP"; then
            print_info "允许端口 80/tcp (HTTP)..."
            sudo ufw allow 80/tcp || print_warning "添加防火墙规则 80/tcp 失败。"
            changed=true
        fi
         if ! sudo ufw status verbose | grep -qw "443/tcp" && ! sudo ufw status verbose | grep -q "Nginx HTTPS"; then
            print_info "允许端口 443/tcp (HTTPS)..."
            sudo ufw allow 443/tcp || print_warning "添加防火墙规则 443/tcp 失败。"
             changed=true
        fi
        # Alternatively, simpler: sudo ufw allow 'Nginx Full'

        if $changed; then
             sudo ufw reload || print_warning "重新加载防火墙规则失败。"
             print_info "防火墙规则已更新。"
        else
             print_info "端口 80 和 443 似乎已在 UFW 中允许。"
        fi
    else
        print_info "UFW防火墙未启用或未安装，跳过防火墙配置。"
        print_warning "请确保防火墙允许 TCP 端口 80 和 443 的入站连接。"
    fi
}

# --- Main Execution Flow ---
print_info "=== 开始 SSL 证书安装和流媒体转发配置 ==="

# Check root/sudo privileges
if [ "$(id -u)" -ne 0 ]; then
  print_error "此脚本需要 root 或 sudo 权限才能运行。"
  exit 1
fi

# 0. Create webroot for Certbot if it doesn't exist
sudo mkdir -p /var/www/html/.well-known/acme-challenge
sudo chown -R www-data:www-data /var/www/html

# 1. 安装必备软件包
install_prerequisites || exit 1

# 2. 创建密码文件
create_password_file || exit 1

# 3. 配置Nginx日志格式 (Best effort)
configure_nginx_log_format || print_warning "配置 Nginx 日志格式时遇到问题，已跳过。"

# 4. 获取或续签证书 (Using Nginx plugin now)
if ! obtain_certificate_nginx; then
    print_error "未能获取或续签 Let's Encrypt 证书。"
    # Attempt to ensure Nginx is running if it exists
    if command_exists nginx && ! systemctl is-active --quiet nginx; then sudo systemctl start nginx; fi
    exit 1
fi

# 5. 生成流媒体代理 Nginx 配置
if ! generate_stream_proxy_config; then
     print_error "生成 Nginx 配置文件失败。"
     exit 1
fi

# 6. 测试并重载Nginx配置
if ! test_and_reload_nginx; then
     print_error "应用 Nginx 配置失败。"
     exit 1
fi

# 7. 验证自动续签设置
verify_auto_renewal

# 8. 配置防火墙
configure_firewall

# --- 完成 ---
# --- MODIFIED FINAL OUTPUT ---
echo
print_info "==========================================================="
print_info "            流媒体转发配置已完成！"
print_info "-----------------------------------------------------------"
print_info "您的代理域名:       https://$DOMAIN"
print_info "本机访问路径:       $STREAM_PATH"
print_info "后端基础URL:        $BACKEND_URL"
print_info ""
print_info "--- 如何访问您的流 ---"
print_info "要访问流，请将 原始流URL中 基础URL(${BACKEND_URL}) 之后的部分"
print_info "附加到您的 代理URL(https://$DOMAIN) 和 本机访问路径(${STREAM_PATH}) 之后。"
print_info "例如:"
print_info "  如果原始流是: ${BACKEND_URL}subdir/playlist.m3u8"
print_info "  您的访问地址是: https://$DOMAIN${STREAM_PATH}subdir/playlist.m3u8"
print_info ""
print_info "  如果原始流是: ${BACKEND_URL}master.m3u8"
print_info "  您的访问地址是: https://$DOMAIN${STREAM_PATH}master.m3u8"
print_info "-----------------------------------------------------------"
print_info "认证用户名:         $AUTH_USER"
print_info "认证密码:           [您设置的密码]"
print_info "-----------------------------------------------------------"
print_info "证书路径:           /etc/letsencrypt/live/$DOMAIN/"
print_info "Nginx配置:          /etc/nginx/sites-enabled/stream_proxy_$DOMAIN.conf"
print_info "密码文件:           /etc/nginx/auth/.htpasswd"
print_info "访问日志:           /var/log/nginx/stream_access.log"
print_info "错误日志:           /var/log/nginx/stream_error.log"
print_info "-----------------------------------------------------------"
print_info "如需修改密码 ($AUTH_USER)，请运行:"
print_info "echo '新密码' | sudo htpasswd -i /etc/nginx/auth/.htpasswd $AUTH_USER"
print_info "如需添加新用户，请运行 (不带 -c 选项):"
print_info "echo '新密码' | sudo htpasswd -i /etc/nginx/auth/.htpasswd 新用户名"
print_info "==========================================================="
# --- END MODIFIED FINAL OUTPUT ---

exit 0
