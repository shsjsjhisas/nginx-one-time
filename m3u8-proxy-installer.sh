#!/bin/bash

# m3u8-proxy-installer.sh
# 一键式m3u8代理中转服务安装脚本

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # 恢复默认颜色

# 配置文件路径
CONFIG_DIR="/etc/m3u8-proxy"
NGINX_CONF_DIR=""
NGINX_SITE_AVAILABLE=""
NGINX_SITE_ENABLED=""
AUTH_FILE="/etc/nginx/.htpasswd"
SOURCE_FILE="$CONFIG_DIR/source.conf"
SCRIPT_LOG="$CONFIG_DIR/install.log"

# 日志函数
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$SCRIPT_LOG"
    echo -e "$1"
}

# 确认root权限
check_root() {
    if [ "$(id -u)" != "0" ]; then
        log "${RED}错误: 此脚本需要root权限，请使用sudo或root用户运行${NC}"
        exit 1
    fi
}

# 检测操作系统
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        OS="rhel"
    elif [ -f /etc/debian_version ]; then
        OS="debian"
    else
        OS="unknown"
    fi
    
    log "${BLUE}检测到操作系统: $OS $VER${NC}"
    
    # 设置nginx配置路径
    if [[ "$OS" == "centos" || "$OS" == "rhel" || "$OS" == "fedora" ]]; then
        NGINX_CONF_DIR="/etc/nginx/conf.d"
        NGINX_SITE_AVAILABLE="$NGINX_CONF_DIR/m3u8-proxy.conf"
        NGINX_SITE_ENABLED="$NGINX_CONF_DIR/m3u8-proxy.conf"
        PACKAGE_MANAGER="yum"
    else
        NGINX_CONF_DIR="/etc/nginx"
        NGINX_SITE_AVAILABLE="$NGINX_CONF_DIR/sites-available/m3u8-proxy"
        NGINX_SITE_ENABLED="$NGINX_CONF_DIR/sites-enabled/m3u8-proxy"
        PACKAGE_MANAGER="apt"
    fi
}

# 创建必要的目录
create_dirs() {
    mkdir -p "$CONFIG_DIR"
    mkdir -p /var/www/html/m3u8-proxy
    
    # 确保日志文件存在
    touch "$SCRIPT_LOG"
    chmod 640 "$SCRIPT_LOG"
}

# 安装软件依赖
install_dependencies() {
    log "${BLUE}正在安装必要的软件...${NC}"
    
    # 更新包管理器
    if [ "$PACKAGE_MANAGER" = "apt" ]; then
        apt update -y >> "$SCRIPT_LOG" 2>&1
        apt install -y nginx certbot curl wget python3-certbot-nginx apache2-utils >> "$SCRIPT_LOG" 2>&1
    else
        yum install -y epel-release >> "$SCRIPT_LOG" 2>&1
        yum install -y nginx certbot python3-certbot-nginx httpd-tools curl wget >> "$SCRIPT_LOG" 2>&1
    fi
    
    if [ $? -ne 0 ]; then
        log "${RED}安装软件失败，请查看日志: $SCRIPT_LOG${NC}"
        exit 1
    fi
    
    # 检查NGINX是否支持sub_filter
    if ! nginx -V 2>&1 | grep -q with-http_sub_module; then
        log "${YELLOW}警告: 当前NGINX不支持sub_filter功能，m3u8文件内的URL将无法被正确替换${NC}"
        log "${YELLOW}建议您重新编译NGINX并启用http_sub_module模块${NC}"
    fi
    
    log "${GREEN}软件安装完成!${NC}"
}

# 启动并启用NGINX服务
enable_nginx() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable nginx >> "$SCRIPT_LOG" 2>&1
        systemctl start nginx >> "$SCRIPT_LOG" 2>&1
    elif command -v service >/dev/null 2>&1; then
        service nginx enable >> "$SCRIPT_LOG" 2>&1
        service nginx start >> "$SCRIPT_LOG" 2>&1
    else
        log "${YELLOW}警告: 无法启用NGINX服务，请手动启动${NC}"
    fi
}

# 设置中转源
set_proxy_source() {
    local current_source=""
    
    if [ -f "$SOURCE_FILE" ]; then
        current_source=$(cat "$SOURCE_FILE")
        log "${YELLOW}当前中转源: ${current_source}${NC}"
    fi
    
    echo "请输入要中转的m3u8源地址 (例如: https://example.com/live/):"
    read -p "> " source_url
    
    # 验证URL格式
    if [[ ! $source_url =~ ^https?:// ]]; then
        log "${RED}错误: 源地址必须以http://或https://开头${NC}"
        return 1
    fi
    
    # 确保URL以/结尾
    [[ $source_url != */ ]] && source_url="${source_url}/"
    
    # 尝试测试源可访问性
    if ! curl -s --head "$source_url" >/dev/null; then
        log "${YELLOW}警告: 无法连接到源地址。请确认源地址可访问。是否继续? [y/N]${NC}"
        read -p "> " continue_anyway
        if [[ ! $continue_anyway =~ ^[Yy]$ ]]; then
            return 1
        fi
    fi
    
    # 保存源地址到配置文件
    echo "$source_url" > "$SOURCE_FILE"
    chmod 600 "$SOURCE_FILE"  # 设置安全权限
    log "${GREEN}源地址已设置为: $source_url${NC}"
    
    # 询问是否更新NGINX配置
    if [ -f "$NGINX_SITE_AVAILABLE" ]; then
        echo "是否应用新的源地址到NGINX配置? [Y/n]"
        read -p "> " refresh
        if [[ $refresh != "n" && $refresh != "N" ]]; then
            generate_nginx_config
            reload_nginx
        fi
    fi
    
    return 0
}

# 配置访问密码
setup_authentication() {
    echo "是否为流媒体设置访问密码? [Y/n]"
    read -p "> " enable_auth
    
    if [[ $enable_auth != "n" && $enable_auth != "N" ]]; then
        echo "请设置用户名:"
        read -p "> " username
        
        # 验证用户名
        if [[ -z "$username" || "$username" =~ [^a-zA-Z0-9_] ]]; then
            log "${RED}错误: 用户名只能包含字母、数字和下划线${NC}"
            return 1
        fi
        
        # 创建密码文件
        while true; do
            if htpasswd -c "$AUTH_FILE" "$username" 2>/dev/null; then
                break
            else
                log "${RED}密码创建失败，请重试${NC}"
                echo "是否重试? [Y/n]"
                read -p "> " retry
                if [[ $retry == "n" || $retry == "N" ]]; then
                    return 1
                fi
            fi
        done
        
        chmod 600 "$AUTH_FILE"  # 设置安全权限
        echo "true" > "$CONFIG_DIR/auth_enabled"
        log "${GREEN}认证已启用! 用户名: $username${NC}"
    else
        echo "false" > "$CONFIG_DIR/auth_enabled"
        if [ -f "$AUTH_FILE" ]; then
            echo "删除现有密码保护? [Y/n]"
            read -p "> " remove_auth
            if [[ $remove_auth != "n" && $remove_auth != "N" ]]; then
                rm -f "$AUTH_FILE"
                log "${GREEN}密码保护已移除${NC}"
            else
                echo "true" > "$CONFIG_DIR/auth_enabled"
            fi
        fi
    fi
    
    return 0
}

# 配置域名和SSL
setup_domain() {
    local current_domain=""
    
    if [ -f "$CONFIG_DIR/domain.conf" ]; then
        current_domain=$(cat "$CONFIG_DIR/domain.conf")
        log "${YELLOW}当前设置的域名: ${current_domain}${NC}"
    fi
    
    echo "请输入您的域名 (例如: stream.example.com):"
    echo "注意: 请确保该域名已正确解析到此服务器IP"
    read -p "> " domain
    
    # 验证域名格式
    if [[ ! $domain =~ ^[a-zA-Z0-9][a-zA-Z0-9\.-]+\.[a-zA-Z]{2,}$ ]]; then
        log "${RED}错误: 无效的域名格式${NC}"
        return 1
    fi
    
    # 检查域名解析
    echo "正在验证域名解析..."
    local server_ip=$(curl -s ifconfig.me)
    local domain_ip=$(dig +short "$domain" 2>/dev/null || host -t A "$domain" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    
    if [ -z "$domain_ip" ]; then
        log "${YELLOW}警告: 无法解析域名。请确保域名已正确设置DNS解析${NC}"
    elif [ "$server_ip" != "$domain_ip" ]; then
        log "${YELLOW}警告: 域名 $domain 当前解析到 $domain_ip, 而不是本服务器IP $server_ip${NC}"
        echo "是否继续? [y/N]"
        read -p "> " continue_anyway
        if [[ ! $continue_anyway =~ ^[Yy]$ ]]; then
            return 1
        fi
    else
        log "${GREEN}域名解析验证成功!${NC}"
    fi
    
    # 保存域名到配置文件
    echo "$domain" > "$CONFIG_DIR/domain.conf"
    chmod 600 "$CONFIG_DIR/domain.conf"
    
    # 询问是否配置SSL
    echo "是否为此域名配置SSL证书? [Y/n]"
    read -p "> " setup_ssl
    
    if [[ $setup_ssl != "n" && $setup_ssl != "N" ]]; then
        # 先生成基本配置以便certbot使用
        generate_nginx_config "pre-ssl"
        reload_nginx
        
        log "${BLUE}正在申请SSL证书...${NC}"
        if certbot --nginx -d "$domain" --non-interactive --agree-tos --register-unsafely-without-email --redirect >> "$SCRIPT_LOG" 2>&1; then
            echo "true" > "$CONFIG_DIR/ssl_enabled"
            chmod 600 "$CONFIG_DIR/ssl_enabled"
            
            # 设置自动续期
            echo "0 0,12 * * * root python3 -c 'import random; import time; time.sleep(random.random() * 3600)' && certbot renew -q" > /etc/cron.d/certbot-renew
            chmod 644 /etc/cron.d/certbot-renew
            
            log "${GREEN}SSL证书已配置成功并已设置自动续期!${NC}"
            # 重新生成完整配置
            generate_nginx_config
        else
            log "${RED}SSL证书申请失败。请查看日志: $SCRIPT_LOG${NC}"
            log "${YELLOW}将使用HTTP配置继续。${NC}"
            echo "false" > "$CONFIG_DIR/ssl_enabled"
            chmod 600 "$CONFIG_DIR/ssl_enabled"
        fi
    else
        echo "false" > "$CONFIG_DIR/ssl_enabled"
        chmod 600 "$CONFIG_DIR/ssl_enabled"
    fi
    
    return 0
}

# 生成NGINX配置
generate_nginx_config() {
    local mode="$1"  # 传入"pre-ssl"表示仅用于申请SSL的预配置
    
    if [ ! -f "$SOURCE_FILE" ] && [ "$mode" != "pre-ssl" ]; then
        log "${RED}错误: 未设置源地址，请先设置源地址${NC}"
        return 1
    fi
    
    local source_url=""
    [ -f "$SOURCE_FILE" ] && source_url=$(cat "$SOURCE_FILE")
    
    local auth_enabled="false"
    [ -f "$CONFIG_DIR/auth_enabled" ] && auth_enabled=$(cat "$CONFIG_DIR/auth_enabled")
    
    local domain="localhost"
    [ -f "$CONFIG_DIR/domain.conf" ] && domain=$(cat "$CONFIG_DIR/domain.conf")
    
    local ssl_enabled="false"
    [ -f "$CONFIG_DIR/ssl_enabled" ] && ssl_enabled=$(cat "$CONFIG_DIR/ssl_enabled")
    
    # 创建基本配置
    cat > "$NGINX_SITE_AVAILABLE" << EOF
server {
    listen 80;
    server_name $domain;

    access_log /var/log/nginx/m3u8-proxy-access.log;
    error_log /var/log/nginx/m3u8-proxy-error.log;

    # 提供静态登录页面
    location / {
        root /var/www/html/m3u8-proxy;
        index index.html;
    }
EOF

    # 如果不是预配置且存在源地址，添加代理配置
    if [ "$mode" != "pre-ssl" ] && [ -n "$source_url" ]; then
        cat >> "$NGINX_SITE_AVAILABLE" << EOF

    # m3u8和ts文件代理
    location /proxy/ {
EOF

        # 添加验证配置
        if [ "$auth_enabled" = "true" ]; then
            cat >> "$NGINX_SITE_AVAILABLE" << EOF
        auth_basic "Protected Stream";
        auth_basic_user_file $AUTH_FILE;
EOF
        fi

        # 添加代理设置和m3u8内容替换
        cat >> "$NGINX_SITE_AVAILABLE" << EOF
        proxy_pass $source_url;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        
        # 支持跨域
        add_header Access-Control-Allow-Origin *;
        add_header Access-Control-Allow-Methods 'GET, OPTIONS';
        add_header Access-Control-Allow-Headers 'DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type';
        
        # 尝试替换m3u8中的源站地址
        proxy_set_header Accept-Encoding "";
        sub_filter_types *;
        sub_filter "$source_url" "/proxy/";
        sub_filter_once off;
        
        # 关闭缓存，确保实时性
        proxy_cache off;
        expires -1;
    }
EOF
    fi

    # 关闭服务器块
    cat >> "$NGINX_SITE_AVAILABLE" << EOF
}
EOF

    # 如果是Debian/Ubuntu系统，需要创建软链接
    if [ "$NGINX_SITE_AVAILABLE" != "$NGINX_SITE_ENABLED" ] && [ ! -f "$NGINX_SITE_ENABLED" ]; then
        ln -sf "$NGINX_SITE_AVAILABLE" "$NGINX_SITE_ENABLED"
    fi
    
    # 创建欢迎页面
    create_welcome_page
    
    log "${GREEN}NGINX配置文件已生成: $NGINX_SITE_AVAILABLE${NC}"
    return 0
}

# 创建欢迎页面
create_welcome_page() {
    local domain="localhost"
    [ -f "$CONFIG_DIR/domain.conf" ] && domain=$(cat "$CONFIG_DIR/domain.conf")
    
    local ssl_enabled="false"
    [ -f "$CONFIG_DIR/ssl_enabled" ] && ssl_enabled=$(cat "$CONFIG_DIR/ssl_enabled")
    
    local protocol="http"
    [ "$ssl_enabled" = "true" ] && protocol="https"
    
    cat > /var/www/html/m3u8-proxy/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>M3U8 代理服务</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
            background-color: #f8f9fa;
        }
        .container {
            max-width: 800px;
            margin: 40px auto;
            padding: 30px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #eee;
        }
        .info {
            background: #f1f8ff;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            border-left: 4px solid #4285f4;
        }
        .success {
            color: #28a745;
            font-weight: bold;
        }
        code {
            background-color: #f5f5f5;
            padding: 3px 5px;
            border-radius: 3px;
            font-family: monospace;
            font-size: 0.9em;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            font-size: 0.8em;
            color: #999;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>M3U8 代理服务</h1>
        <div class="info">
            <p class="success">✓ 服务运行中</p>
            <p>您的流媒体地址: <code>${protocol}://${domain}/proxy/playlist.m3u8</code></p>
            <p>将此地址用于您的媒体播放器或网页播放器即可观看流媒体内容</p>
        </div>
        
        <h3>使用说明:</h3>
        <ol>
            <li>在您的播放器中打开上述地址</li>
            <li>如果设置了密码保护，请输入您的用户名和密码</li>
            <li>流媒体内容将通过此服务器中转，隐藏原始源地址</li>
        </ol>
        
        <div class="footer">
            <p>M3U8 Proxy Service - 配置与管理: <code>bash <(curl -Ls https://your-script-url.com)</code></p>
        </div>
    </div>
</body>
</html>
EOF

    # 设置适当的权限
    chmod 644 /var/www/html/m3u8-proxy/index.html
}

# 重新加载NGINX配置
reload_nginx() {
    log "${BLUE}检查NGINX配置...${NC}"
    if nginx -t >> "$SCRIPT_LOG" 2>&1; then
        log "${GREEN}NGINX配置检查通过，重新加载服务...${NC}"
        if command -v systemctl >/dev/null 2>&1; then
            systemctl reload nginx >> "$SCRIPT_LOG" 2>&1
        else
            service nginx reload >> "$SCRIPT_LOG" 2>&1
        fi
        
        if [ $? -eq 0 ]; then
            log "${GREEN}NGINX已成功重新加载!${NC}"
        else
            log "${RED}NGINX重新加载失败! 请检查日志: $SCRIPT_LOG${NC}"
            return 1
        fi
    else
        log "${RED}NGINX配置有误! 请检查日志: $SCRIPT_LOG${NC}"
        return 1
    fi
    
    return 0
}

# 显示当前配置信息
show_config() {
    log "${BLUE}=== M3U8代理配置信息 ===${NC}"
    
    if [ -f "$SOURCE_FILE" ]; then
        log "${YELLOW}中转源: ${NC}$(cat $SOURCE_FILE)"
    else
        log "${YELLOW}中转源: ${NC}未设置"
    fi
    
    local auth_status="禁用"
    if [ -f "$CONFIG_DIR/auth_enabled" ] && [ "$(cat $CONFIG_DIR/auth_enabled)" = "true" ]; then
        auth_status="启用"
        if [ -f "$AUTH_FILE" ]; then
            local username=$(cut -d: -f1 "$AUTH_FILE")
            log "${YELLOW}认证用户: ${NC}$username"
        fi
    fi
    log "${YELLOW}密码保护: ${NC}$auth_status"
    
    if [ -f "$CONFIG_DIR/domain.conf" ]; then
        log "${YELLOW}域名: ${NC}$(cat $CONFIG_DIR/domain.conf)"
    else
        log "${YELLOW}域名: ${NC}未设置"
    fi
    
    local ssl_status="禁用"
    if [ -f "$CONFIG_DIR/ssl_enabled" ] && [ "$(cat $CONFIG_DIR/ssl_enabled)" = "true" ]; then
        ssl_status="启用"
    fi
    log "${YELLOW}SSL: ${NC}$ssl_status"
    
    # 检查NGINX状态
    local nginx_status="未知"
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet nginx; then
            nginx_status="运行中"
        else
            nginx_status="已停止"
        fi
    elif command -v service >/dev/null 2>&1; then
        if service nginx status >/dev/null 2>&1; then
            nginx_status="运行中"
        else
            nginx_status="已停止"
        fi
    fi
    log "${YELLOW}NGINX状态: ${NC}$nginx_status"
    
    # 显示访问URL
    if [ -f "$CONFIG_DIR/domain.conf" ]; then
        local domain=$(cat "$CONFIG_DIR/domain.conf")
        local protocol="http"
        
        if [ -f "$CONFIG_DIR/ssl_enabled" ] && [ "$(cat $CONFIG_DIR/ssl_enabled)" = "true" ]; then
            protocol="https"
        fi
        
        log "${GREEN}代理访问地址: ${NC}$protocol://$domain/proxy/playlist.m3u8"
    fi
    
    # 显示服务器信息
    local server_ip=$(curl -s ifconfig.me 2>/dev/null || wget -qO- ifconfig.me 2>/dev/null)
    [ -n "$server_ip" ] && log "${YELLOW}服务器IP: ${NC}$server_ip"
}

# 备份配置
backup_config() {
    local backup_dir="$CONFIG_DIR/backup"
    local timestamp=$(date +%Y%m%d%H%M%S)
    local backup_file="$backup_dir/backup_$timestamp.tar.gz"
    
    mkdir -p "$backup_dir"
    
    log "${BLUE}正在备份当前配置...${NC}"
    tar -czf "$backup_file" "$CONFIG_DIR"/*.conf "$NGINX_SITE_AVAILABLE" 2>/dev/null
    
    if [ $? -eq 0 ] && [ -f "$backup_file" ]; then
        chmod 600 "$backup_file"
        log "${GREEN}配置已备份到: $backup_file${NC}"
        return 0
    else
        log "${RED}备份失败!${NC}"
        return 1
    fi
}

# 卸载服务
uninstall_service() {
    echo -e "${RED}警告: 这将删除M3U8代理服务及其所有配置。${NC}"
    echo "确定要卸载吗? [y/N]"
    read -p "> " confirm
    
    if [[ $confirm =~ ^[Yy]$ ]]; then
        log "${YELLOW}开始卸载M3U8代理服务...${NC}"
        
        # 询问是否备份配置
        echo "是否备份当前配置? [Y/n]"
        read -p "> " backup
        if [[ $backup != "n" && $backup != "N" ]]; then
            backup_config
        fi
        
        # 移除NGINX配置
        rm -f "$NGINX_SITE_ENABLED" "$NGINX_SITE_AVAILABLE"
        
        # 移除所有配置文件
        echo "是否删除所有配置文件? [y/N]"
        read -p "> " del_config
        if [[ $del_config =~ ^[Yy]$ ]]; then
            rm -rf "$CONFIG_DIR"
        fi
        
        # 移除网站文件
        echo "是否删除网站文件? [y/N]"
        read -p "> " del_web
        if [[ $del_web =~ ^[Yy]$ ]]; then
            rm -rf /var/www/html/m3u8-proxy
        fi
        
        # 重新加载NGINX
        reload_nginx
        
        log "${GREEN}M3U8代理服务已卸载!${NC}"
    else
        log "${YELLOW}已取消卸载${NC}"
    fi
}

# 测试流可用性
test_stream() {
    if [ ! -f "$SOURCE_FILE" ]; then
        log "${RED}错误: 未设置源地址，无法测试${NC}"
        return 1
    fi
    
    local source_url=$(cat "$SOURCE_FILE")
    log "${BLUE}正在测试源流可用性: $source_url${NC}"
    
    # 尝试获取m3u8文件
    local temp_file="/tmp/test_m3u8.m3u8"
    local result=$(curl -s -o "$temp_file" -w "%{http_code}" "$source_url")
    
    if [ "$result" = "200" ]; then
        if grep -q "#EXTM3U" "$temp_file"; then
            log "${GREEN}源流测试成功! 收到了有效的m3u8响应${NC}"
            
            # 检查内容信息
            local duration=$(grep -o "EXTINF:[0-9.]*" "$temp_file" | head -1 | cut -d: -f2)
            [ -n "$duration" ] && log "${YELLOW}片段时长: ${NC}$duration 秒"
            
            local segments=$(grep -c "\.ts" "$temp_file")
            [ -n "$segments" ] && log "${YELLOW}片段数量: ${NC}$segments"
            
            # 检查m3u8类型
            if grep -q "#EXT-X-STREAM-INF" "$temp_file"; then
                log "${YELLOW}m3u8类型: ${NC}主播放列表 (包含不同码率)"
            else
                log "${YELLOW}m3u8类型: ${NC}媒体播放列表 (ts片段列表)"
            fi
            
            rm -f "$temp_file"
            return 0
        else
            log "${RED}源URL返回了200状态码，但不是有效的m3u8文件${NC}"
        fi
    else
        log "${RED}源流测试失败! HTTP状态码: $result${NC}"
    fi
    
    rm -f "$temp_file"
    return 1
}

# 主菜单
show_menu() {
    clear
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${BLUE}       M3U8 代理中转管理工具 v1.0.0     ${NC}"
    echo -e "${BLUE}=========================================${NC}"
    echo -e "1. ${YELLOW}安装必要组件${NC}"
    echo -e "2. ${YELLOW}设置/修改中转源${NC}"
    echo -e "3. ${YELLOW}配置密码保护${NC}"
    echo -e "4. ${YELLOW}设置域名和SSL${NC}"
    echo -e "5. ${YELLOW}重新生成NGINX配置${NC}"
    echo -e "6. ${YELLOW}查看当前配置${NC}"
    echo -e "7. ${YELLOW}重启NGINX服务${NC}"
    echo -e "8. ${YELLOW}测试流可用性${NC}"
    echo -e "9. ${YELLOW}备份当前配置${NC
