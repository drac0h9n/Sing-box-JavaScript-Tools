#!/bin/bash

# 检查参数数量
if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
    echo "Usage: $0 <local_port> <destination_ip> <destination_port> <limit_in_gb> [protocol]"
    echo "Example: $0 999 8.217.73.121 80 5 tcp"
    echo "Example: $0 999 8.217.73.121 80 0.5 both"
    echo "If protocol is not specified, 'both' will be used"
    exit 1
fi

# 获取参数
LOCAL_PORT=$1
DEST_IP=$2
DEST_PORT=$3
LIMIT_GB=$4
PROTOCOL=${5:-both}  # 如果未指定协议，默认使用 both

# 使用awk转换GB为字节，支持浮点数
LIMIT_BYTES=$(echo "$LIMIT_GB * 1024 * 1024 * 1024" | bc)
LIMIT_BYTES=${LIMIT_BYTES%.*}  # 取整

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

# 保存监控进程PID的文件
PID_FILE="/tmp/portforward_pid_${LOCAL_PORT}"

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

    # 确保handle文件存在并清空
    touch "$HANDLE_FILE"
    > "$HANDLE_FILE"

    echo "Adding rules and collecting handles..."

    # TCP rules
    if [[ "$PROTOCOL" == "tcp" ]] || [[ "$PROTOCOL" == "both" ]]; then
        # Prerouting TCP
        nft add rule ip portforward prerouting tcp dport $LOCAL_PORT counter dnat to $DEST_IP:$DEST_PORT
        HANDLE=$(nft --handle list chain ip portforward prerouting | grep "dport $LOCAL_PORT" | grep -oP 'handle \K\d+')
        echo "TCP prerouting handle: $HANDLE"
        [ ! -z "$HANDLE" ] && echo "$HANDLE" >> "$HANDLE_FILE"

        # Postrouting TCP
        nft add rule ip portforward postrouting ip daddr $DEST_IP tcp dport $DEST_PORT counter masquerade
        HANDLE=$(nft --handle list chain ip portforward postrouting | grep "dport $DEST_PORT" | grep -oP 'handle \K\d+')
        echo "TCP postrouting handle: $HANDLE"
        [ ! -z "$HANDLE" ] && echo "$HANDLE" >> "$HANDLE_FILE"

        # Forward TCP
        nft add rule ip filter forward ip daddr $DEST_IP tcp dport $DEST_PORT counter comment '"forward traffic from port '"$LOCAL_PORT"' to '"$DEST_IP:$DEST_PORT"'"'
        HANDLE=$(nft --handle list chain ip filter forward | grep "dport $DEST_PORT" | grep -oP 'handle \K\d+')
        echo "TCP forward handle: $HANDLE"
        [ ! -z "$HANDLE" ] && echo "$HANDLE" >> "$HANDLE_FILE"

        # Return TCP
        nft add rule ip filter forward ip saddr $DEST_IP tcp sport $DEST_PORT counter comment '"return traffic from '"$DEST_IP:$DEST_PORT"' to port '"$LOCAL_PORT"'"'
        HANDLE=$(nft --handle list chain ip filter forward | grep "sport $DEST_PORT" | grep -oP 'handle \K\d+')
        echo "TCP return handle: $HANDLE"
        [ ! -z "$HANDLE" ] && echo "$HANDLE" >> "$HANDLE_FILE"
    fi

    # UDP rules
    if [[ "$PROTOCOL" == "udp" ]] || [[ "$PROTOCOL" == "both" ]]; then
        # Prerouting UDP
        nft add rule ip portforward prerouting udp dport $LOCAL_PORT counter dnat to $DEST_IP:$DEST_PORT
        HANDLE=$(nft --handle list chain ip portforward prerouting | grep "udp.*dport $LOCAL_PORT" | grep -oP 'handle \K\d+')
        echo "UDP prerouting handle: $HANDLE"
        [ ! -z "$HANDLE" ] && echo "$HANDLE" >> "$HANDLE_FILE"

        # Postrouting UDP
        nft add rule ip portforward postrouting ip daddr $DEST_IP udp dport $DEST_PORT counter masquerade
        HANDLE=$(nft --handle list chain ip portforward postrouting | grep "udp.*dport $DEST_PORT" | grep -oP 'handle \K\d+')
        echo "UDP postrouting handle: $HANDLE"
        [ ! -z "$HANDLE" ] && echo "$HANDLE" >> "$HANDLE_FILE"

        # Forward UDP
        nft add rule ip filter forward ip daddr $DEST_IP udp dport $DEST_PORT counter comment '"forward traffic from port '"$LOCAL_PORT"' to '"$DEST_IP:$DEST_PORT"'"'
        HANDLE=$(nft --handle list chain ip filter forward | grep "udp.*dport $DEST_PORT" | grep -oP 'handle \K\d+')
        echo "UDP forward handle: $HANDLE"
        [ ! -z "$HANDLE" ] && echo "$HANDLE" >> "$HANDLE_FILE"

        # Return UDP
        nft add rule ip filter forward ip saddr $DEST_IP udp sport $DEST_PORT counter comment '"return traffic from '"$DEST_IP:$DEST_PORT"' to port '"$LOCAL_PORT"'"'
        HANDLE=$(nft --handle list chain ip filter forward | grep "udp.*sport $DEST_PORT" | grep -oP 'handle \K\d+')
        echo "UDP return handle: $HANDLE"
        [ ! -z "$HANDLE" ] && echo "$HANDLE" >> "$HANDLE_FILE"
    fi

    echo "Created handle file: $HANDLE_FILE"
    echo "Handles collected:"
    cat "$HANDLE_FILE"
    chmod 644 "$HANDLE_FILE"

    # 显示所有规则用于验证
    echo "Current nft rules:"
    nft --handle list ruleset

    # 开启IP转发
    echo 1 > /proc/sys/net/ipv4/ip_forward
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
}

# 检查流量使用情况
check_traffic() {
    local TOTAL_BYTES=0
    local RULE_BYTES

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
    echo "Starting to remove rules..."

    if [ -f "$HANDLE_FILE" ]; then
        echo "Found handle file: $HANDLE_FILE"
        echo "Current handles:"
        cat "$HANDLE_FILE"

        while IFS= read -r handle; do
            echo "Attempting to remove rule with handle: $handle"

            echo "Removing from portforward prerouting..."
            if nft delete rule ip portforward prerouting handle "$handle" 2>/dev/null; then
                echo "Successfully removed rule from portforward prerouting"
            else
                echo "No matching rule found in portforward prerouting"
            fi

            echo "Removing from portforward postrouting..."
            if nft delete rule ip portforward postrouting handle "$handle" 2>/dev/null; then
                echo "Successfully removed rule from portforward postrouting"
            else
                echo "No matching rule found in portforward postrouting"
            fi

            echo "Removing from filter forward..."
            if nft delete rule ip filter forward handle "$handle" 2>/dev/null; then
                echo "Successfully removed rule from filter forward"
            else
                echo "No matching rule found in filter forward"
            fi

        done < "$HANDLE_FILE"

        echo "Removing handle file..."
        rm "$HANDLE_FILE"
        echo "Handle file removed"
    else
        echo "Handle file not found: $HANDLE_FILE"
    fi

    echo "Rule removal process completed"

    # 显示当前的nft规则，用于验证
    echo "Current nft rules after removal:"
    nft list ruleset
}


# 清理函数
cleanup() {
    # 添加锁定机制防止重复执行
    local LOCK_FILE="/tmp/cleanup_lock_${LOCAL_PORT}"
    if [ -f "$LOCK_FILE" ]; then
        echo "Cleanup already in progress"
        return
    fi
    touch "$LOCK_FILE"

    echo "Cleaning up rules and terminating..."
    remove_rules

    # 终止监控进程
    if [ -f "$PID_FILE" ]; then
        local MONITOR_PID=$(cat "$PID_FILE")
        kill "$MONITOR_PID" 2>/dev/null
        rm -f "$PID_FILE"
    fi

    rm -f "$LOCK_FILE"
}

# 监控流量的后台进程
monitor_traffic() {
    echo $$ > "$PID_FILE"

    if [ ! -f "$HANDLE_FILE" ]; then
        echo "Error: Handle file not found at startup: $HANDLE_FILE"
        exit 1
    fi

    echo "Starting traffic monitoring with handle file: $HANDLE_FILE"
    echo "Current handles:"
    cat "$HANDLE_FILE"

    local LOG_FILE="$TRAFFIC_DIR/traffic_${LOCAL_PORT}.log"
    local TEMP_LOG="/tmp/traffic_${LOCAL_PORT}.temp"

    while true; do
        if [ ! -f "$HANDLE_FILE" ]; then
            echo "Error: Handle file lost during monitoring: $HANDLE_FILE"
            exit 1
        fi

        CURRENT_BYTES=$(check_traffic)
        USED_MB=$((CURRENT_BYTES/1024/1024))

        # 获取当前时间
        current_time=$(date '+%Y-%m-%d %H:%M:%S')

        # 保存新日志记录
        echo "$current_time - Used: ${USED_MB}MB of ${LIMIT_GB}GB (${CURRENT_BYTES} bytes)" >> "$LOG_FILE"

        # 清理超过3分钟的日志
        if [ -f "$LOG_FILE" ]; then
            # 计算3分钟前的时间戳
            cutoff_time=$(date -d '3 minutes ago' '+%Y-%m-%d %H:%M:%S')
    
            # 使用awk过滤最近3分钟的日志
            awk -v cutoff="$cutoff_time" '
            {
                log_time = substr($0, 1, 19)
                if (log_time >= cutoff) {
                    print $0
                }
            }' "$LOG_FILE" > "$TEMP_LOG"
    
            # 用临时文件替换原日志文件
            mv "$TEMP_LOG" "$LOG_FILE"
        fi

        if [[ $(echo "$CURRENT_BYTES > $LIMIT_BYTES" | bc) -eq 1 ]]; then
            echo "$current_time - Traffic limit reached ($LIMIT_GB GB). Removing forwarding rules..." >> "$LOG_FILE"
            cleanup
            # 等待清理完成
            sleep 2
            exit 0
        fi

        sleep 5
    done
}

# 检查并安装依赖
check_dependencies() {
    for dep in nft bc; do
        if ! command -v "$dep" &> /dev/null; then
            echo "Installing $dep..."
            apt-get update
            apt-get install -y "$dep"
        fi
    done
}

# 设置信号处理
trap cleanup SIGINT SIGTERM

# 主程序
check_dependencies
echo "Setting up port forwarding from local port $LOCAL_PORT to $DEST_IP:$DEST_PORT (Protocol: $PROTOCOL)"
echo "Traffic limit: $LIMIT_GB GB"
create_forward_rules
monitor_traffic &

echo "Port forwarding has been set up successfully!"
echo "Traffic logs are stored in: $TRAFFIC_DIR/traffic_${LOCAL_PORT}.log"

wait
