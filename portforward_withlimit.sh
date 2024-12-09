#!/bin/bash

# 检查参数数量
if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
    echo "Usage: $0 <local_port> <destination_ip> <destination_port> <limit_in_gb> [protocol]"
    echo "Example: $0 999 8.217.73.121 80 5 tcp"
    echo "Example: $0 999 8.217.73.121 80 5 udp"
    echo "Example: $0 999 8.217.73.121 80 5 both"
    echo "If protocol is not specified, 'both' will be used"
    exit 1
fi

# 获取参数
LOCAL_PORT=$1
DEST_IP=$2
DEST_PORT=$3
LIMIT_GB=$4
PROTOCOL=${5:-both}  # 如果未指定协议，默认使用 both

# 转换GB为字节
LIMIT_BYTES=$((LIMIT_GB * 1024 * 1024 * 1024))

# 转换协议参数为小写
PROTOCOL=$(echo "$PROTOCOL" | tr '[:upper:]' '[:lower:]')

# 验证协议参数
if [[ ! "$PROTOCOL" =~ ^(tcp|udp|both)$ ]]; then
    echo "Invalid protocol. Please use 'tcp', 'udp', or 'both'"
    exit 1
fi

# 检查是否以root权限运行
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# 创建流量记录目录
TRAFFIC_DIR="/var/log/portforward"
mkdir -p "$TRAFFIC_DIR"

# 保存规则句柄的临时文件
HANDLE_FILE="/tmp/portforward_handles_${LOCAL_PORT}"

# 创建转发规则函数
create_forward_rules() {
    # 创建 portforward 表、prerouting 和 postrouting 链（如果不存在）
    if ! nft list tables | grep -q "^table ip portforward$"; then
        nft add table ip portforward
        nft add chain ip portforward prerouting { type nat hook prerouting priority 0 \; }
        nft add chain ip portforward postrouting { type nat hook postrouting priority 100 \; }
    fi

    # 确保filter表和forward链存在
    if ! nft list tables | grep -q "^table ip filter$"; then
        nft add table ip filter
    fi
    if ! nft list chain ip filter forward >/dev/null 2>&1; then
        nft add chain ip filter forward { type filter hook forward priority 0\; policy accept\; }
    fi

    # 清空句柄文件
    > "$HANDLE_FILE"

    # 添加 NAT 规则
    if [[ "$PROTOCOL" == "tcp" ]] || [[ "$PROTOCOL" == "both" ]]; then
        nft --handle add rule ip portforward prerouting tcp dport $LOCAL_PORT counter dnat to $DEST_IP:$DEST_PORT | grep -oP 'handle \K\d+' >> "$HANDLE_FILE"
        nft --handle add rule ip portforward postrouting ip daddr $DEST_IP tcp dport $DEST_PORT counter masquerade | grep -oP 'handle \K\d+' >> "$HANDLE_FILE"
    fi

    if [[ "$PROTOCOL" == "udp" ]] || [[ "$PROTOCOL" == "both" ]]; then
        nft --handle add rule ip portforward prerouting udp dport $LOCAL_PORT counter dnat to $DEST_IP:$DEST_PORT | grep -oP 'handle \K\d+' >> "$HANDLE_FILE"
        nft --handle add rule ip portforward postrouting ip daddr $DEST_IP udp dport $DEST_PORT counter masquerade | grep -oP 'handle \K\d+' >> "$HANDLE_FILE"
    fi

    if [[ "$PROTOCOL" == "tcp" ]] || [[ "$PROTOCOL" == "both" ]]; then
        nft --handle add rule ip filter forward ip daddr "$DEST_IP" tcp dport "$DEST_PORT" counter comment \"forward traffic from port ${LOCAL_PORT} to ${DEST_IP}:${DEST_PORT}\" | grep -oP 'handle \K\d+' >> "$HANDLE_FILE"
        nft --handle add rule ip filter forward ip saddr "$DEST_IP" tcp sport "$DEST_PORT" counter comment \"return traffic from ${DEST_IP}:${DEST_PORT} to port ${LOCAL_PORT}\" | grep -oP 'handle \K\d+' >> "$HANDLE_FILE"
    fi
    
    if [[ "$PROTOCOL" == "udp" ]] || [[ "$PROTOCOL" == "both" ]]; then
        nft --handle add rule ip filter forward ip daddr "$DEST_IP" udp dport "$DEST_PORT" counter comment \"forward traffic from port ${LOCAL_PORT} to ${DEST_IP}:${DEST_PORT}\" | grep -oP 'handle \K\d+' >> "$HANDLE_FILE"
        nft --handle add rule ip filter forward ip saddr "$DEST_IP" udp sport "$DEST_PORT" counter comment \"return traffic from ${DEST_IP}:${DEST_PORT} to port ${LOCAL_PORT}\" | grep -oP 'handle \K\d+' >> "$HANDLE_FILE"
    fi




    # 开启IP转发
    echo 1 > /proc/sys/net/ipv4/ip_forward
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
}

# 检查流量使用情况：从prerouting链中读取当前转发的总字节数
# 检查流量使用情况：从forward链中读取双向转发数据的总字节数
check_traffic() {
    local TOTAL_BYTES=0
    local RULE_BYTES

    # 从forward链中查找我们添加的计数规则行，通过注释中的关键词匹配
    # 我们在添加规则时有类似：
    # comment "count forward traffic ${LOCAL_PORT}->${DEST_IP}:${DEST_PORT}"
    # comment "count return traffic ${DEST_IP}:${DEST_PORT}->${LOCAL_PORT}"
    #
    # 使用grep筛选包含这两种注释的行并提取bytes值，然后求和。

    RULE_BYTES=$(nft list chain ip filter forward \
    | grep -E 'comment "(forward|return) traffic ' \
    | grep -E "${DEST_IP}:${DEST_PORT}" \
    | grep -oP 'packets \d+ bytes \K\d+' \
    | awk '{sum += $1} END {print sum}')


    TOTAL_BYTES=$((TOTAL_BYTES + ${RULE_BYTES:-0}))

    echo "$TOTAL_BYTES"
}


# 删除特定端口的转发规则
remove_rules() {
    if [ -f "$HANDLE_FILE" ]; then
        # 从句柄文件中读取并删除每条规则
        while IFS= read -r handle; do
            # 先尝试删除nat链的规则
            nft delete rule ip portforward prerouting handle "$handle" 2>/dev/null
            nft delete rule ip portforward postrouting handle "$handle" 2>/dev/null
            # 再尝试删除filter forward链的规则
            nft delete rule ip filter forward handle "$handle" 2>/dev/null
        done < "$HANDLE_FILE"
        rm "$HANDLE_FILE"
    fi
}

# 清理函数
cleanup() {
    remove_rules
    exit 0
}

# 监控流量的后台进程
monitor_traffic() {
    while true; do
        CURRENT_BYTES=$(check_traffic)
        USED_MB=$((CURRENT_BYTES/1024/1024))
        TOTAL_GB=$LIMIT_GB
        
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Used: ${USED_MB}MB of ${TOTAL_GB}GB (${CURRENT_BYTES} bytes)" >> "$TRAFFIC_DIR/traffic_${LOCAL_PORT}.log"
        
        if [ "$CURRENT_BYTES" -gt "$LIMIT_BYTES" ]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') - Traffic limit reached ($LIMIT_GB GB). Removing forwarding rules..." >> "$TRAFFIC_DIR/traffic_${LOCAL_PORT}.log"
            cleanup
        fi
        
        sleep 60
    done
}

# 设置信号处理
trap cleanup SIGINT SIGTERM

# 主程序
echo "Setting up port forwarding from local port $LOCAL_PORT to $DEST_IP:$DEST_PORT (Protocol: $PROTOCOL)"
echo "Traffic limit: $LIMIT_GB GB"
create_forward_rules
monitor_traffic &

echo "Port forwarding has been set up successfully!"
echo "Traffic logs are stored in: $TRAFFIC_DIR/traffic_${LOCAL_PORT}.log"
