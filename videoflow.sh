#!/bin/bash

# --- Function Definitions ---
function print_info { echo -e "\033[0;32m[INFO]\033[0m $1"; }
function print_warning { echo -e "\033[0;33m[WARN]\033[0m $1"; }
function print_error { echo -e "\033[0;31m[ERROR]\033[0m $1" >&2; }

# --- 检查证书状态和位置 ---
function check_cert_status {
    print_info "检查Let's Encrypt证书状态..."
    
    # 获取域名
    read -p "请输入您的域名 (例如: ocean.hitony666.top): " DOMAIN
    if [[ -z "$DOMAIN" ]]; then 
        print_error "域名不能为空，无法继续。"
        exit 1
    fi
    
    # 查看证书是否存在于预期位置
    EXPECTED_CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    EXPECTED_KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    
    if [[ -f "$EXPECTED_CERT" && -f "$EXPECTED_KEY" ]]; then
        print_info "证书文件已在预期路径找到:"
        print_info "- 证书: $EXPECTED_CERT"
        print_info "- 私钥: $EXPECTED_KEY"
        return 0
    fi
    
    print_warning "预期路径未找到证书，正在搜索系统中的证书..."
    
    # 在系统中搜索证书
    FOUND_CERTS=$(sudo find /etc/letsencrypt/ -name "fullchain.pem" 2>/dev/null)
    if [[ -z "$FOUND_CERTS" ]]; then
        print_error "在系统中未找到任何Let's Encrypt证书。"
        print_info "您可能需要手动指定证书路径或重新获取证书。"
        manual_cert_setup
        return 1
    fi
    
    print_info "找到以下证书文件:"
    echo "$FOUND_CERTS" | cat -n
    
    read -p "请选择要使用的证书编号 (若要手动指定路径，请输入'0'): " CERT_NUM
    
    if [[ "$CERT_NUM" == "0" ]]; then
        manual_cert_setup
        return 0
    fi
    
    SELECTED_CERT=$(echo "$FOUND_CERTS" | sed -n "${CERT_NUM}p")
    if [[ -z "$SELECTED_CERT" ]]; then
        print_error "选择无效，将转为手动设置。"
        manual_cert_setup
        return 0
    fi
    
    # 找到对应的私钥
    CERT_DIR=$(dirname "$SELECTED_CERT")
    SELECTED_KEY="$CERT_DIR/privkey.pem"
    
    if [[ ! -f "$SELECTED_KEY" ]]; then
        print_error "未找到对应的私钥文件: $SELECTED_KEY"
        print_info "将转为手动设置。"
        manual_cert_setup
        return 0
    fi
    
    print_info "已选择使用以下证书文件:"
    print_info "- 证书: $SELECTED_CERT"
    print_info "- 私钥: $SELECTED_KEY"
    
    # 创建临时配置文件
    create_nginx_config "$DOMAIN" "$SELECTED_CERT" "$SELECTED_KEY"
    return 0
}

# --- 手动设置证书路径 ---
function manual_cert_setup {
    print_info "手动设置证书路径..."
    
    read -p "请输入证书文件(fullchain.pem)的完整路径: " MANUAL_CERT
    if [[ ! -f "$MANUAL_CERT" ]]; then
        print_error "证书文件不存在: $MANUAL_CERT"
        print_info "请确认路径并重试。"
        exit 1
    fi
    
    read -p "请输入私钥文件(privkey.pem)的完整路径: " MANUAL_KEY
    if [[ ! -f "$MANUAL_KEY" ]]; then
        print_error "私钥文件不存在: $MANUAL_KEY"
        print_info "请确认路径并重试。"
        exit 1
    fi
    
    print_info "将使用以下证书文件:"
    print_info "- 证书: $MANUAL_CERT"
    print_info "- 私钥: $MANUAL_KEY"
    
    # 创建临时配置文件
    create_nginx_config "$DOMAIN" "$MANUAL_CERT" "$MANUAL_KEY"
}

# --- 创建Nginx配置文件 ---
function create_nginx_config {
    local domain=$1
    local cert_path=$2
    local key_path=$3
    
    print_info "正在创建Nginx配置文件..."
    
    # 获取流媒体URL
    read -p "请输入完整的m3u8流地址 (例如: https://d1vnr7assmzbx49s.clouasdddfront.net/index_1.m3u8): " FULL_URL
    if [[ -z "$FULL_URL" ]]; then 
        print_error "m3u8流地址不能为空，无法继续。"
        exit 1
    fi
    
    # 解析URL组件
    BACKEND_HOST=$(echo "$FULL_URL" | sed -E 's|^https?://([^/]+).*|\1|')
    PROTOCOL=$(echo "$FULL_URL" | sed -E 's|^(https?://).*|\1|')
    BACKEND_URL="${PROTOCOL}${BACKEND_HOST}"
    M3U8_FILE=$(echo "$FULL_URL" | sed -E 's|^.*/([^/]+)$|\1|')
    
    # 设置流路径
    read -p "请设置本地访问路径 (默认: /live/): " STREAM_PATH
    STREAM_PATH=${STREAM_PATH:-/live/}
    [[ "$STREAM_PATH" != /* ]] && STREAM_PATH="/$STREAM_PATH"
    [[ "$STREAM_PATH" != */ ]] && STREAM_PATH="$STREAM_PATH/"
    
    # 设置认证信息
    read -p "请设置访问用户名 (默认: streamuser): " AUTH_USER
    AUTH_USER=${AUTH_USER:-streamuser}
    read -s -p "请设置访问密码: " AUTH_PASS
    echo
    
    # 创建密码文件
    sudo mkdir -p /etc/nginx/auth/
    echo "$AUTH_PASS" | sudo htpasswd -c -i /etc/nginx/auth/.htpasswd "$AUTH_USER" || {
        print_error "创建密码文件失败。"
        exit 1
    }
    
    # 创建访问信息页面
    sudo mkdir -p "/var/www/html/access_info_$domain"
    
    local access_file="/var/www/html/access_info_$domain/index.html"
    sudo tee "$access_file" > /dev/null << EOF
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>流媒体访问信息 - $domain</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background-color: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #1a73e8;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        .info-box {
            background-color: #f1f8ff;
            border-left: 4px solid #1a73e8;
            padding: 15px;
            margin-bottom: 20px;
        }
        code {
            background-color: #f0f0f0;
            padding: 2px 5px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        .note {
            margin-top: 30px;
            font-size: 14px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>流媒体访问信息</h1>
        
        <div class="info-box">
            <p><strong>您的流媒体已成功配置！</strong> 以下是访问信息：</p>
            <p><strong>流媒体地址:</strong> <code>https://$domain$STREAM_PATH</code></p>
            <p><strong>用户名:</strong> <code>$AUTH_USER</code></p>
            <p><strong>密码:</strong> <code>[已设置的密码]</code></p>
        </div>
        
        <h2>使用说明</h2>
        <p>您可以使用任何支持HTTP认证的m3u8播放器来访问此流媒体。</p>
        <p>播放时需要输入设置的用户名和密码。</p>
        
        <h2>VLC播放器示例</h2>
        <ol>
            <li>打开VLC播放器</li>
            <li>点击"媒体" > "打开网络串流"</li>
            <li>输入URL: <code>https://$AUTH_USER:[已设置的密码]@$domain$STREAM_PATH</code></li>
            <li>点击"播放"</li>
        </ol>
        
        <div class="note">
            <p>注意：此页面仅供参考，建议保存这些信息到其他安全的地方，并在完成设置后移除此页面。</p>
        </div>
    </div>
</body>
</html>
EOF
    
    sudo chown -R www-data:www-data "/var/www/html/access_info_$domain"
    sudo chmod -R 755 "/var/www/html/access_info_$domain"
    
    # 确保有WebSocket支持
    local nginx_conf="/etc/nginx/nginx.conf"
    if ! sudo grep -q "map \$http_upgrade \$connection_upgrade" "$nginx_conf"; then
        sudo cp "$nginx_conf" "$nginx_conf.bak"
        sudo awk '
        /http {/ {
            print;
            print "    # Variable for Connection header based on Upgrade header";
            print "    map $http_upgrade $connection_upgrade {";
            print "        default upgrade;";
            print "        \"\"      close;";
            print "    }";
            next;
        }
        {print}
        ' "$nginx_conf" | sudo tee "$nginx_conf.tmp" > /dev/null
        sudo mv "$nginx_conf.tmp" "$nginx_conf"
    fi
    
    # 创建服务器配置
    local server_conf="/etc/nginx/sites-available/stream_proxy_$domain"
    
    sudo tee "$server_conf" > /dev/null << EOF
# --- HTTPS Server Block for $domain ---
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;

    # --- Domain ---
    server_name $domain;

    # --- SSL/TLS Certificate Configuration ---
    ssl_certificate     $cert_path;
    ssl_certificate_key $key_path;

    # --- SSL/TLS Security Settings ---
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;

    # --- 访问信息页面位置 ---
    location /info/ {
        alias /var/www/html/access_info_$domain/;
        index index.html;
        try_files \$uri \$uri/ =404;
    }

    # --- Stream Proxy Location with Password and Logging ---
    location $STREAM_PATH {
        # --- Password Protection ---
        auth_basic "Password Protected Stream";
        auth_basic_user_file /etc/nginx/auth/.htpasswd;

        # --- Reverse Proxy Settings ---
        proxy_pass $BACKEND_URL;
        proxy_set_header Host $BACKEND_HOST;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_buffering off;
        proxy_cache off;
        proxy_redirect off;

        # --- Access Log ---
        access_log /var/log/nginx/stream_auth.log auth_log;
    }

    # 添加M3U8文件专用路径
    location $STREAM_PATH$M3U8_FILE {
        # --- Password Protection ---
        auth_basic "Password Protected Stream";
        auth_basic_user_file /etc/nginx/auth/.htpasswd;

        # --- Reverse Proxy Settings ---
        proxy_pass $FULL_URL;
        proxy_set_header Host $BACKEND_HOST;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_buffering off;
        proxy_cache off;
        proxy_redirect off;

        # --- Access Log ---
        access_log /var/log/nginx/stream_auth.log auth_log;
    }

    # Other paths return to info page
    location / {
        return 301 /info/;
    }
}

# --- HTTP to HTTPS Redirect ---
server {
    listen 80;
    listen [::]:80;
    server_name $domain;
    return 301 https://\$host\$request_uri;
}
EOF

    # 启用配置
    if [ ! -L "/etc/nginx/sites-enabled/stream_proxy_$domain" ]; then
        sudo ln -s "$server_conf" "/etc/nginx/sites-enabled/stream_proxy_$domain"
    fi
    
    # 验证并重载配置
    print_info "验证Nginx配置..."
    if sudo nginx -t; then
        sudo systemctl reload nginx
        print_info "Nginx配置已成功应用！"
        print_info "-----------------------------------------------------------"
        print_info "您可以通过以下地址访问："
        print_info "流媒体地址：https://$domain$STREAM_PATH"
        print_info "流媒体文件：https://$domain$STREAM_PATH$M3U8_FILE"
        print_info "访问信息页：https://$domain/info/"
        print_info "-----------------------------------------------------------"
        print_info "用户名：$AUTH_USER"
        print_info "密码：[已设置]"
        print_info "-----------------------------------------------------------"
    else
        print_error "Nginx配置验证失败！请检查配置文件。"
        exit 1
    fi
}

# --- 主执行流程 ---
print_info "=== 证书路径修复工具 ==="
check_cert_status
print_info "=== 设置完成 ==="

exit 0
