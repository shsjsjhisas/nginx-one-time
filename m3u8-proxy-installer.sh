#!/bin/bash

# m3u8-proxy-installer.sh
# 一键安装配置m3u8中转代理脚本

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # 恢复默认颜色

# 检查root权限
if [ "$(id -u)" != "0" ]; then
   echo -e "${RED}错误: 此脚本需要root权限，请使用sudo或root用户运行${NC}" 1>&2
   exit 1
fi

# 配置文件路径
CONFIG_DIR="/etc/m3u8-proxy"
NGINX_CONFIG="/etc/nginx/sites-available/m3u8-proxy"
NGINX_ENABLED="/etc/nginx/sites-enabled/m3u8-proxy"
AUTH_FILE="/etc/nginx/.htpasswd"
SOURCE_FILE="$CONFIG_DIR/source.conf"

# 创建配置目录
mkdir -p $CONFIG_DIR

# 安装必要软件
install_dependencies() {
    echo -e "${BLUE}正在安装必要的软件...${NC}"
    apt update -y
    apt install -y nginx certbot python3-certbot-nginx apache2-utils curl
    
    # 检查安装结果
    if [ $? -ne 0 ]; then
        echo -e "${RED}安装软件失败，请检查网络或系统状态后重试。${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}软件安装完成!${NC}"
}

# 设置反向代理源
set_proxy_source() {
    local current_source=""
    
    # 检查是否已存在源配置
    if [ -f "$SOURCE_FILE" ]; then
        current_source=$(cat "$SOURCE_FILE")
        echo -e "${YELLOW}当前中转源: ${current_source}${NC}"
    fi
    
    echo "请输入要中转的m3u8源地址 (例如: https://example.com/live/):"
    read -p "> " source_url
    
    # 验证URL格式
    if [[ ! $source_url =~ ^https?:// ]]; then
        echo -e "${RED}错误: 源地址必须以http://或https://开头${NC}"
        return 1
    fi
    
    # 确保URL以/结尾
    [[ $source_url != */ ]] && source_url="${source_url}/"
    
    # 保存源地址到配置文件
    echo "$source_url" > "$SOURCE_FILE"
    echo -e "${GREEN}源地址已设置为: $source_url${NC}"
    
    # 提示是否刷新nginx配置
    if [ -f "$NGINX_CONFIG" ]; then
        echo -e "${YELLOW}已检测到现有配置。需要应用新的源地址吗?${NC}"
        read -p "应用新配置 [Y/n]: " refresh
        if [[ $refresh != "n" && $refresh != "N" ]]; then
            generate_nginx_config
            systemctl reload nginx
            echo -e "${GREEN}NGINX配置已更新!${NC}"
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
        
        # 检查用户名有效性
        if [[ -z "$username" || "$username" =~ [^a-zA-Z0-9_] ]]; then
            echo -e "${RED}错误: 用户名只能包含字母、数字和下划线${NC}"
            return 1
        fi
        
        # 创建密码文件
        htpasswd -c $AUTH_FILE $username
        
        if [ $? -ne 0 ]; then
            echo -e "${RED}创建密码文件失败${NC}"
            return 1
        fi
        
        AUTH_ENABLED=true
        echo -e "${GREEN}认证已启用! 用户名: $username${NC}"
    else
        AUTH_ENABLED=false
        # 如果密码文件存在，询问是否删除
        if [ -f "$AUTH_FILE" ]; then
            echo "是否删除现有密码保护? [Y/n]"
            read -p "> " remove_auth
            if [[ $remove_auth != "n" && $remove_auth != "N" ]]; then
                rm -f $AUTH_FILE
                echo -e "${GREEN}密码保护已移除${NC}"
            else
                AUTH_ENABLED=true
            fi
        fi
    fi
    
    echo "$AUTH_ENABLED" > "$CONFIG_DIR/auth_enabled"
    return 0
}

# 设置域名和SSL
setup_domain() {
    local current_domain=""
    
    # 检查是否已存在域名配置
    if [ -f "$CONFIG_DIR/domain.conf" ]; then
        current_domain=$(cat "$CONFIG_DIR/domain.conf")
        echo -e "${YELLOW}当前设置的域名: ${current_domain}${NC}"
    fi
    
    echo "请输入您的域名 (例如: stream.example.com):"
    echo "注意: 请确保该域名已正确解析到此服务器IP"
    read -p "> " domain
    
    # 验证域名格式
    if [[ ! $domain =~ ^[a-zA-Z0-9][a-zA-Z0-9\.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${RED}错误: 无效的域名格式${NC}"
        return 1
    fi
    
    # 保存域名到配置文件
    echo "$domain" > "$CONFIG_DIR/domain.conf"
    
    # 询问是否配置SSL
    echo "是否为此域名配置SSL证书? [Y/n]"
    read -p "> " setup_ssl
    
    if [[ $setup_ssl != "n" && $setup_ssl != "N" ]]; then
        echo -e "${BLUE}正在申请SSL证书...${NC}"
        certbot --nginx -d $domain --non-interactive --agree-tos --email admin@$domain
        
        if [ $? -ne 0 ]; then
            echo -e "${RED}SSL证书申请失败。将使用HTTP配置。${NC}"
            echo "false" > "$CONFIG_DIR/ssl_enabled"
            return 1
        else
            echo "true" > "$CONFIG_DIR/ssl_enabled"
            # 设置自动续期
            echo "0 0,12 * * * root python -c 'import random; import time; time.sleep(random.random() * 3600)' && certbot renew -q" > /etc/cron.d/certbot-renew
            echo -e "${GREEN}SSL证书已配置成功并已设置自动续期!${NC}"
        fi
    else
        echo "false" > "$CONFIG_DIR/ssl_enabled"
    fi
    
    return 0
}

# 生成NGINX配置
generate_nginx_config() {
    if [ ! -f "$SOURCE_FILE" ]; then
        echo -e "${RED}错误: 未设置源地址，请先设置源地址${NC}"
        return 1
    fi
    
    local source_url=$(cat "$SOURCE_FILE")
    local auth_enabled="false"
    
    if [ -f "$CONFIG_DIR/auth_enabled" ]; then
        auth_enabled=$(cat "$CONFIG_DIR/auth_enabled")
    fi
    
    local domain="localhost"
    if [ -f "$CONFIG_DIR/domain.conf" ]; then
        domain=$(cat "$CONFIG_DIR/domain.conf")
    fi
    
    local ssl_enabled="false"
    if [ -f "$CONFIG_DIR/ssl_enabled" ]; then
        ssl_enabled=$(cat "$CONFIG_DIR/ssl_enabled")
    fi
    
    # 创建基本配置
    cat > $NGINX_CONFIG << EOF
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

    # m3u8和ts文件代理
    location /proxy/ {
EOF

    # 添加验证配置
    if [ "$auth_enabled" = "true" ]; then
        cat >> $NGINX_CONFIG << EOF
        auth_basic "Protected Stream";
        auth_basic_user_file $AUTH_FILE;
EOF
    fi

    # 添加代理设置和m3u8内容替换
    cat >> $NGINX_CONFIG << EOF
        proxy_pass $source_url;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        
        # 替换m3u8中的源站地址
        sub_filter_types text/plain application/vnd.apple.mpegurl;
        sub_filter "$source_url" "/proxy/";
        sub_filter_once off;
        
        # 关闭缓存，确保实时性
        proxy_cache off;
        expires -1;
    }
}
EOF

    # 启用NGINX配置
    ln -sf $NGINX_CONFIG $NGINX_ENABLED
    
    # 创建简单的HTML欢迎页
    mkdir -p /var/www/html/m3u8-proxy
    cat > /var/www/html/m3u8-proxy/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>M3U8 Proxy</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { color: #333; }
        .info { background: #f5f5f5; padding: 20px; border-radius: 5px; }
        .success { color: #4CAF50; }
    </style>
</head>
<body>
    <div class="container">
        <h1>M3U8 代理服务</h1>
        <div class="info">
            <p class="success">✓ 服务运行中</p>
            <p>您的流媒体地址: <code>http://$domain/proxy/playlist.m3u8</code></p>
            <p>将此地址用于您的媒体播放器</p>
        </div>
    </div>
</body>
</html>
EOF
    
    echo -e "${GREEN}NGINX配置文件已生成!${NC}"
    return 0
}

# 显示配置信息
show_config() {
    echo -e "${BLUE}=== M3U8代理配置信息 ===${NC}"
    
    if [ -f "$SOURCE_FILE" ]; then
        echo -e "${YELLOW}中转源: ${NC}$(cat $SOURCE_FILE)"
    else
        echo -e "${YELLOW}中转源: ${NC}未设置"
    fi
    
    local auth_status="禁用"
    if [ -f "$CONFIG_DIR/auth_enabled" ] && [ "$(cat $CONFIG_DIR/auth_enabled)" = "true" ]; then
        auth_status="启用"
    fi
    echo -e "${YELLOW}密码保护: ${NC}$auth_status"
    
    if [ -f "$CONFIG_DIR/domain.conf" ]; then
        echo -e "${YELLOW}域名: ${NC}$(cat $CONFIG_DIR/domain.conf)"
    else
        echo -e "${YELLOW}域名: ${NC}未设置"
    fi
    
    local ssl_status="禁用"
    if [ -f "$CONFIG_DIR/ssl_enabled" ] && [ "$(cat $CONFIG_DIR/ssl_enabled)" = "true" ]; then
        ssl_status="启用"
    fi
    echo -e "${YELLOW}SSL: ${NC}$ssl_status"
    
    # 显示访问URL
    if [ -f "$CONFIG_DIR/domain.conf" ]; then
        local domain=$(cat "$CONFIG_DIR/domain.conf")
        local protocol="http"
        
        if [ -f "$CONFIG_DIR/ssl_enabled" ] && [ "$(cat $CONFIG_DIR/ssl_enabled)" = "true" ]; then
            protocol="https"
        fi
        
        echo -e "${GREEN}代理访问地址: ${NC}$protocol://$domain/proxy/playlist.m3u8"
    fi
}

# 主菜单
show_menu() {
    clear
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${BLUE}       M3U8 代理中转管理工具            ${NC}"
    echo -e "${BLUE}=========================================${NC}"
    echo -e "1. ${YELLOW}安装必要组件${NC}"
    echo -e "2. ${YELLOW}设置/修改中转源${NC}"
    echo -e "3. ${YELLOW}配置密码保护${NC}"
    echo -e "4. ${YELLOW}设置域名和SSL${NC}"
    echo -e "5. ${YELLOW}生成NGINX配置${NC}"
    echo -e "6. ${YELLOW}查看当前配置${NC}"
    echo -e "7. ${YELLOW}重启NGINX服务${NC}"
    echo -e "0. ${RED}退出${NC}"
    echo -e "${BLUE}=========================================${NC}"
    echo -e "选择操作:"
}

# 初始化配置
init_setup() {
    install_dependencies
    set_proxy_source
    setup_authentication
    setup_domain
    generate_nginx_config
    
    # 重启NGINX服务
    systemctl restart nginx
    
    echo -e "${GREEN}初始化配置完成!${NC}"
    show_config
}

# 如果没有配置文件，执行初始化安装
if [ ! -f "$CONFIG_DIR/initialized" ]; then
    echo -e "${BLUE}首次运行，开始初始化安装...${NC}"
    init_setup
    touch "$CONFIG_DIR/initialized"
else
    # 显示菜单
    while true; do
        show_menu
        read -p "> " choice
        
        case "$choice" in
            1)  install_dependencies ;;
            2)  set_proxy_source ;;
            3)  setup_authentication ;;
            4)  setup_domain ;;
            5)  generate_nginx_config ;;
            6)  show_config ;;
            7)  systemctl restart nginx
                echo -e "${GREEN}NGINX已重启!${NC}" ;;
            0)  echo -e "${GREEN}感谢使用，再见!${NC}"
                exit 0 ;;
            *)  echo -e "${RED}无效选项，请重新选择${NC}" ;;
        esac
        
        echo
        read -p "按Enter键继续..." input
    done
fi