#!/bin/bash
# TacoSys行号断点跟踪器部署脚本

set -e

REMOTE_HOST="192.168.56.255"
REMOTE_USER="root"
REMOTE_PASS="123456"
REMOTE_DIR="/root/tracer"

echo "🚀 部署TacoSys行号断点跟踪器到远程主机"
echo "目标主机: $REMOTE_HOST"
echo "=================================================="

# 检查sshpass
if ! command -v sshpass &> /dev/null; then
    echo "❌ 错误: 未安装sshpass"
    echo "请安装: sudo apt-get install sshpass"
    exit 1
fi

# 创建临时目录
TEMP_DIR=$(mktemp -d)
echo "📁 临时目录: $TEMP_DIR"

# 获取当前脚本目录
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# 复制文件到临时目录
echo "📋 准备文件..."
cp "$SCRIPT_DIR/line_breakpoint_tracer.py" "$TEMP_DIR/"
cp "$SCRIPT_DIR/line_breakpoint_config.json" "$TEMP_DIR/"
cp "$SCRIPT_DIR/README.md" "$TEMP_DIR/" 2>/dev/null || echo "⚠️  README.md 不存在，跳过"

# 在远程主机创建目录
echo "📂 在远程主机创建目录..."
sshpass -p "$REMOTE_PASS" ssh -o StrictHostKeyChecking=no "$REMOTE_USER@$REMOTE_HOST" \
    "mkdir -p $REMOTE_DIR"

# 上传文件
echo "📤 上传文件到远程主机..."
sshpass -p "$REMOTE_PASS" scp -o StrictHostKeyChecking=no \
    "$TEMP_DIR"/* "$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR/"

# 设置执行权限
echo "🔧 设置文件权限..."
sshpass -p "$REMOTE_PASS" ssh -o StrictHostKeyChecking=no "$REMOTE_USER@$REMOTE_HOST" \
    "chmod +x $REMOTE_DIR/line_breakpoint_tracer.py"

# 安装依赖
echo "📦 安装依赖..."
sshpass -p "$REMOTE_PASS" ssh -o StrictHostKeyChecking=no "$REMOTE_USER@$REMOTE_HOST" \
    "apt-get update && apt-get install -y python3-bpfcc python3-pip && pip3 install pyelftools"

# 清理临时目录
rm -rf "$TEMP_DIR"

echo ""
echo "✅ 部署完成！"
echo ""
echo "🎯 使用方法:"
echo "1. SSH登录到远程主机:"
echo "   ssh root@$REMOTE_HOST"
echo ""
echo "2. 进入跟踪器目录:"
echo "   cd $REMOTE_DIR"
echo ""
echo "3. 查看帮助:"
echo "   python3 line_breakpoint_tracer.py --help"
echo ""
echo "4. 生成配置文件（如果需要）:"
echo "   python3 line_breakpoint_tracer.py --generate-config"
echo ""
echo "5. 运行跟踪器:"
echo "   python3 line_breakpoint_tracer.py /path/to/tacosys.ko line_breakpoint_config.json"
echo ""
echo "📝 注意事项:"
echo "- 确保.ko文件包含DWARF调试信息（使用-g编译）"
echo "- 需要root权限运行跟踪器"
echo "- 根据实际情况修改配置文件中的源文件名和行号"