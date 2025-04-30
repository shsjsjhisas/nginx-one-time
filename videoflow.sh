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

# Get Backend URL (Modified Prompt and Logic)
while true; do
    # --- MODIFIED PROMPT ---
    print_info "后端URL应指向流媒体所在的 *基础目录*，而不是具体的 .m3u8 文件。"
    print_info "例如，如果原始流是 https://cdn.example.com/live/stream.m3u8，"
    print_info "那么后端基础URL通常是 https://cdn.example.com/live/"
    read -p "请输入后端流媒体的基础URL (例如: https://example.net/live/): " BACKEND_URL
    # --- END MODIFIED PROMPT ---

    if [[ -z "$BACKEND_URL" ]]; then
        print_error "后端URL不能为空，请重新输入。"
    elif [[ ! "$BACKEND_URL" =~ ^https?:// ]]; then
        print_error "后端URL应以http://或https://开头，请重新输入。"
    # --- ADDED WARNING ---
    elif [[ "$BACKEND_URL" =~ \.(m3u8|mpd|ts|m4s|mp4)$ ]]; then
        print_warning "您输入的后端URL似乎包含了一个具体的文件名 ($BACKEND_URL)。"
        print_warning "通常，您应该输入该文件所在的目录URL。例如，对于 'https://origin.com/stream/playlist.m3u8'，应输入 'https://origin.com/stream/'。"
        read -p "是否确认使用此URL？ (y/N): " confirm_file_url
        if [[ ! "$confirm_file_url" =~ ^[Yy]$ ]]; then
            continue # Ask again
        fi
        # If user confirmed, proceed but remove the filename for proxy_pass base
        BACKEND_URL=$(dirname "$BACKEND_URL")
        # Ensure it ends with / after dirname might remove it
         [[ "$BACKEND_URL" != */ ]] && BACKEND_URL="$BACKEND_URL/"
         # Also handle the case where dirname results in '.' if URL was just http://host/file.m3u8
         if [[ "$BACKEND_URL" == "./" ]]; then
             BACKEND_URL=$(echo "$BACKEND_URL_ORIGINAL" | sed -E 's|^(https?://[^/]+)/.*|\1/|')
             print_info "已将后端URL修正为基础路径: $BACKEND_URL"
         fi
        print_info "将使用计算出的基础路径: $BACKEND_URL"
        # Store original input for potential recovery if dirname fails badly
        BACKEND_URL_ORIGINAL="$BACKEND_URL"

    # --- END ADDED WARNING ---
    else
        # --- MODIFIED LOGIC: Ensure trailing slash for proxy_pass ---
        # Ensure backend URL ends with a slash for correct proxy_pass path mapping
        [[ "$BACKEND_URL" != */ ]] && BACKEND_URL="$BACKEND_URL/"
        # --- END MODIFIED LOGIC ---
        break
    fi
done

# Extract backend host from URL (No change needed here)
BACKEND_HOST=$(echo "$BACKEND_URL" | sed -E 's|^https?://([^/]+).*|\1|')

# Get Stream Path (No change needed here)
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
print_info "例如: 如果原始流是 .../path/to/stream.m3u8"
print_info "您的访问地址将是: https://$DOMAIN${STREAM_PATH}path/to/stream.m3u8"
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

    # Essential for dirname command used in input validation
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

# --- Function to Stop Nginx Service ---
function stop_nginx {
    if command_exists systemctl && systemctl is-active --quiet nginx; then
        print_info "正在停止 Nginx 服务以进行证书获取..."
        # Use certbot hooks instead for standalone
        # sudo systemctl stop nginx || { print_warning "停止 Nginx 失败，可能它没有在运行？"; }
    else
        print_info "Nginx 未运行或无法通过 systemctl 管理，跳过停止步骤。"
    fi
}

# --- Function to Start Nginx Service ---
function start_nginx {
    if command_exists systemctl; then
        if ! systemctl is-active --quiet nginx; then
            print_info "正在启动 Nginx 服务..."
            sudo systemctl start nginx || {
                print_error "启动 Nginx 失败。请检查 'sudo systemctl status nginx' 和 'sudo journalctl -xeu nginx.service'"
                exit 1
            }
        else
             print_info "Nginx 已经在运行。"
        fi
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
    sudo chmod 640 /etc/nginx/auth/.htpasswd # Restrict permissions slightly
    # Ensure nginx user can read it (adjust group if nginx runs as different group)
    sudo chown root:www-data /etc/nginx/auth/.htpasswd
    print_info "密码文件已创建: /etc/nginx/auth/.htpasswd"
}

# --- Function to Configure Nginx Log Format ---
function configure_nginx_log_format {
    print_info "配置 Nginx 日志格式..."
    local nginx_conf="/etc/nginx/nginx.conf"
    local http_block_marker="http {" # More reliable marker
    local log_format_name="auth_log"
    local log_format_string="    log_format $log_format_name '\$remote_addr - \$remote_user [\$time_local] \"\$request\" '\n'                      \$status \$body_bytes_sent \"\$http_referer\" '\n'                      \"\$http_user_agent\"';"

    # Check if the specific log format already exists
    if sudo grep -q "log_format $log_format_name" "$nginx_conf"; then
        print_info "自定义日志格式 '$log_format_name' 已存在，跳过配置。"
        return 0
    fi

    # Check if http block exists
     if ! sudo grep -q "$http_block_marker" "$nginx_conf"; then
        print_error "无法在 $nginx_conf 中找到 'http {' 块。无法自动添加日志格式。"
        return 1
    fi

    # Create backup
    sudo cp "$nginx_conf" "$nginx_conf.bak.$(date +%s)" || { print_error "创建备份 $nginx_conf.bak 失败。"; return 1; }
    print_info "已创建备份 $nginx_conf.bak.*"

    # Add log format inside the http block using awk
    sudo awk -v marker="$http_block_marker" -v format="$log_format_string" '
    $0 ~ marker {
        print;
        print "    # Custom log format for authentication logs (added by script)";
        print format;
        next;
    }
    {print}
    ' "$nginx_conf" > "$nginx_conf.tmp" && sudo mv "$nginx_conf.tmp" "$nginx_conf"

    if [ $? -eq 0 ]; then
        print_info "Nginx 日志格式已配置。"
        # Test config syntax immediately after changing main nginx.conf
        if ! sudo nginx -t; then
             print_error "修改 nginx.conf 后 Nginx 配置测试失败！正在恢复备份。"
             sudo mv "$nginx_conf.bak.$(ls -t "$nginx_conf.bak."* | head -n 1)" "$nginx_conf" # Attempt restore
             return 1
        fi
    else
        print_error "使用 awk 添加日志格式失败。请手动检查 $nginx_conf。"
        return 1
    fi
    return 0
}


# --- Function to Obtain Certificate using Standalone mode ---
function obtain_certificate_standalone {
    local domain_args=("-d" "$DOMAIN")
    local cert_path="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    local pre_hook="sudo systemctl stop nginx"
    local post_hook="sudo systemctl start nginx"

    # Check if certificate already exists
    if [ -f "$cert_path" ]; then
        print_info "证书似乎已存在于 $cert_path。尝试续签..."
        # Use --force-renewal for testing if needed, but not recommended for production
        sudo certbot renew --cert-name "$DOMAIN" \
            --pre-hook "$pre_hook" \
            --post-hook "$post_hook" || {
            print_error "证书续签失败。"
            # Don't exit immediately, maybe config generation can still work if cert is valid
            return 1
        }
        print_info "证书续签（如果需要）完成。"
        return 0 # Indicate success/completion
    fi

    print_info "为域名 ${domain_args[*]} 获取新的 Let's Encrypt 证书 (Standalone 模式)..."
    # Temporarily stop nginx if running for standalone challenge
    stop_nginx # Call the function to stop it

    sudo certbot certonly --standalone --agree-tos --no-eff-email -n \
        "${domain_args[@]}" \
        -m "$EMAIL" \
        --preferred-challenges http \
        --http-01-port 80 \
        || {
            print_error "Certbot 获取证书失败 (certonly --standalone)。请检查端口80是否被占用以及防火墙设置。";
            start_nginx # Try to restart nginx if it was stopped
            return 1;
          }

    print_info "证书获取成功。"
    start_nginx # Restart nginx after successful acquisition
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
        print_error "请确保证书已成功获取。无法生成 Nginx 配置。"
        return 1 # Use return code instead of exit
    fi

    # 创建Nginx站点配置
    local nginx_conf_dir="/etc/nginx/sites-available"
    local nginx_conf="$nginx_conf_dir/stream_proxy_$DOMAIN"
    local nginx_enabled_dir="/etc/nginx/sites-enabled"
    local nginx_symlink="$nginx_enabled_dir/stream_proxy_$DOMAIN"

    sudo mkdir -p "$nginx_conf_dir" "$nginx_enabled_dir"

    # --- Nginx Configuration ---
    # Note: proxy_pass uses BACKEND_URL which now guaranteed ends with /
    # Note: location uses STREAM_PATH which now guaranteed ends with /
    # This setup maps https://yourdomain.com/STREAM_PATH/foo -> BACKEND_URL/foo
    sudo tee "$nginx_conf" > /dev/null << EOF
# --- HTTPS Server Block for $DOMAIN ---
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;

    # --- Favicon / Robots ---
    location = /favicon.ico { access_log off; log_not_found off; }
    location = /robots.txt  { access_log off; log_not_found off; return 200 "User-agent: *\nDisallow: /\n"; }

    # --- SSL/TLS Certificate Configuration ---
    ssl_certificate     $ssl_cert;
    ssl_certificate_key $ssl_key;
    include /etc/letsencrypt/options-ssl-nginx.conf; # Recommended: Use Let's Encrypt's SSL options
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;   # Recommended: Use Let's Encrypt's DH params

    # --- Security Headers ---
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    # add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'self'; object-src 'none';" always; # CSP might break players, enable cautiously

    # --- Stream Proxy Location with Password and Logging ---
    location $STREAM_PATH {
        # --- Password Protection ---
        auth_basic "Password Protected Stream";
        auth_basic_user_file /etc/nginx/auth/.htpasswd;

        # --- Reverse Proxy Settings ---
        proxy_pass $BACKEND_URL; # $BACKEND_URL now ends with /
        proxy_set_header Host \$http_host; # Pass the original Host header requested by the client
        # Alternatively, force the backend host if required by the backend:
        # proxy_set_header Host $BACKEND_HOST;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade; # For potential WebSocket needs
        proxy_set_header Connection \$connection_upgrade; # For potential WebSocket needs
        proxy_buffering off; # Crucial for streaming
        proxy_cache off;     # Disable cache for live streams
        proxy_redirect off;
        proxy_request_buffering off; # Send request body immediately
        proxy_read_timeout 1d; # Increase timeout for long-lived connections
        proxy_send_timeout 1d; # Increase timeout for long-lived connections
        # proxy_intercept_errors on; # Optionally handle backend errors within Nginx

        # --- Access Log ---
        access_log /var/log/nginx/stream_auth.log auth_log;
        error_log /var/log/nginx/stream_error.log warn; # Log proxy errors
    }

    # --- Optional: Root location returns 403 ---
    location / {
        return 403 "Forbidden";
        access_log off;
    }

    # --- Optional: Error Pages ---
    # error_page 403 /403.html;
    # location = /403.html {
    #     internal;
    #     root /var/www/html; # Or your custom error page location
    # }
}

# --- HTTP to HTTPS Redirect ---
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;

    # For Let's Encrypt renewal verification
    location /.well-known/acme-challenge/ {
        root /var/www/html; # Or a dedicated directory Certbot uses
        allow all;
    }

    location / {
      return 301 https://\$host\$request_uri;
    }
}

# Variable for Connection header based on Upgrade header
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ''      close;
}
EOF

    # Include the map in the main http block if not already present
    local nginx_conf_main="/etc/nginx/nginx.conf"
    if ! sudo grep -q "map \$http_upgrade \$connection_upgrade" "$nginx_conf_main"; then
         print_info "Adding 'map \$http_upgrade \$connection_upgrade' to $nginx_conf_main..."
         # Very basic insertion - might need manual adjustment if http block is complex
         sudo sed -i '/http {/a \
    # Variable for Connection header based on Upgrade header (added by script)\
    map $http_upgrade $connection_upgrade {\
        default upgrade;\
        ""      close;\
    }\
' "$nginx_conf_main" || print_warning "自动添加 map 失败，可能需要手动添加到 $nginx_conf_main 的 http 块中。"

        # Test config syntax immediately after changing main nginx.conf
        if ! sudo nginx -t; then
             print_error "添加 map 后 Nginx 配置测试失败！请检查 $nginx_conf_main。"
             # Note: Not attempting automatic revert of this change easily.
             return 1
        fi
    fi


    # 启用站点配置
    if [ ! -L "$nginx_symlink" ]; then
        sudo ln -s "$nginx_conf" "$nginx_symlink" || { print_error "创建符号链接 $nginx_symlink 失败。"; return 1; }
    else
        print_info "符号链接 $nginx_symlink 已存在。"
    fi

    print_info "Nginx 流媒体代理配置已生成并启用。"
    return 0
}


# --- Function to Test Config and Start/Reload Nginx ---
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
        print_error "失败的配置文件可能是: /etc/nginx/sites-available/stream_proxy_$DOMAIN 或 /etc/nginx/nginx.conf"
        return 1 # Use return code
    fi
    return 0
}

# --- Function to Verify Auto Renewal ---
function verify_auto_renewal {
    print_info "验证 Certbot 自动续签设置..."
    local timer_active=false
    local cron_exists=false

    # Check systemd timer
    if systemctl list-unit-files --type=timer | grep -q 'certbot.timer'; then
        if sudo systemctl is-active --quiet certbot.timer; then
            print_info "Certbot systemd 定时器 (certbot.timer) 正在运行。"
            timer_active=true
        else
            print_warning "Certbot systemd 定时器存在但未运行。尝试启用并启动..."
            sudo systemctl enable certbot.timer && sudo systemctl start certbot.timer && timer_active=true || print_error "启动或启用 Certbot timer 失败。"
        fi
    fi

    # Check cron job (less common now but check anyway)
    if [ -f /etc/cron.d/certbot ] || crontab -l 2>/dev/null | grep -q 'certbot'; then
        print_info "检测到 Certbot cron 任务。"
        cron_exists=true
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
        if ! sudo ufw status verbose | grep -qw "80/tcp"; then
            print_info "允许端口 80/tcp (HTTP)..."
            sudo ufw allow 80/tcp || print_warning "添加防火墙规则 80/tcp 失败。"
            changed=true
        fi
         if ! sudo ufw status verbose | grep -qw "443/tcp"; then
            print_info "允许端口 443/tcp (HTTPS)..."
            sudo ufw allow 443/tcp || print_warning "添加防火墙规则 443/tcp 失败。"
             changed=true
        fi
        # Alternative: sudo ufw allow 'Nginx Full'

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

# 0. Create necessary webroot for potential certbot challenges if needed
# This ensures the directory exists even if using standalone initially
# The HTTP->HTTPS redirect block also uses this.
sudo mkdir -p /var/www/html/.well-known/acme-challenge
sudo chown -R www-data:www-data /var/www/html

# 1. 安装必备软件包
install_prerequisites || exit 1 # Exit if prerequisites fail

# 2. 创建密码文件
create_password_file || exit 1 # Exit if password file creation fails

# 3. 配置Nginx日志格式 (Best effort, don't exit if it fails)
configure_nginx_log_format || print_warning "配置 Nginx 日志格式时遇到问题，已跳过。"

# 4. 获取或续签证书 (Standalone 模式)
# stop_nginx and start_nginx are handled within obtain_certificate_standalone now
if ! obtain_certificate_standalone; then
    print_error "未能获取或续签 Let's Encrypt 证书。"
    # Attempt to ensure Nginx is running if it exists
    if command_exists nginx; then start_nginx; fi
    exit 1
fi

# 5. 生成流媒体代理配置
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
print_info "要访问流，请将 原始流URL中基础路径之后的部分 附加到您的代理URL后。"
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
print_info "Nginx配置:          /etc/nginx/sites-enabled/stream_proxy_$DOMAIN"
print_info "密码文件:           /etc/nginx/auth/.htpasswd"
print_info "访问日志:           /var/log/nginx/stream_auth.log"
print_info "错误日志:           /var/log/nginx/stream_error.log"
print_info "-----------------------------------------------------------"
print_info "如需修改密码，请运行:"
print_info "echo '新密码' | sudo htpasswd -i /etc/nginx/auth/.htpasswd $AUTH_USER"
print_info "如需添加新用户，请运行 (不带 -c 选项):"
print_info "echo '新密码' | sudo htpasswd -i /etc/nginx/auth/.htpasswd 新用户名"
print_info "==========================================================="
# --- END MODIFIED FINAL OUTPUT ---

exit 0