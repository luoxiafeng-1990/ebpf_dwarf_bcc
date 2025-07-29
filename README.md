# TacoSys行号断点跟踪器

## 🎯 功能描述

基于eBPF+DWARF+BCC技术栈的高级内核驱动调试工具，支持在源码的特定行号设置断点，实时查看局部变量值。

## ✨ 核心特性

- 🎯 **精确行号断点**: 在源码的任意行设置断点
- 🔍 **局部变量跟踪**: 实时查看函数内局部变量的值
- 📊 **DWARF调试信息**: 基于调试符号精确定位变量
- ⚡ **高性能**: 使用eBPF技术，对系统性能影响最小
- 🛠️ **配置化**: 通过JSON文件灵活配置跟踪目标

## 🖥️ 系统要求

- Linux内核支持eBPF
- Python 3.6+
- BCC工具链
- 带DWARF调试信息的内核模块
- Root权限

## 📦 安装依赖

### Ubuntu/Debian
```bash
sudo apt-get install python3-bpfcc python3-pip
pip3 install pyelftools
```

### CentOS/RHEL
```bash
sudo yum install python3-bcc python3-pip
pip3 install pyelftools
```

## 🚀 快速开始

### 1. 生成配置文件

```bash
python3 line_breakpoint_tracer.py --generate-config
```

### 2. 编辑配置文件

```json
{
  "breakpoints": [
    {
      "function_name": "your_function",
      "source_file": "your_driver.c", 
      "line_number": 42,
      "variables": ["variable1", "variable2"]
    }
  ]
}
```

### 3. 运行跟踪

```bash
sudo python3 line_breakpoint_tracer.py your_driver.ko config.json
```

## ⚙️ 配置文件格式

```json
{
  "description": "跟踪配置描述",
  "version": "1.0",
  "breakpoints": [
    {
      "function_name": "函数名",
      "source_file": "源文件名",
      "line_number": 行号,
      "description": "断点描述（可选）",
      "variables": ["变量1", "变量2", "变量3"]
    }
  ]
}
```

### 📋 字段说明

- `function_name`: 函数名（**必需**，避免变量名冲突）
- `source_file`: 源文件名（只需文件名，不需要完整路径）
- `line_number`: 要设置断点的行号
- `variables`: 要跟踪的局部变量名列表
- `description`: 断点描述（可选）

### 🔍 为什么需要函数名？

1. **避免变量名冲突**: 不同函数可能有相同的变量名
2. **精确定位**: 函数名 + 行号 = 精确定位，避免歧义
3. **DWARF解析**: 需要函数上下文来正确解析变量位置
4. **调试清晰**: 用户明确知道在跟踪哪个函数的变量

```c
// 示例：不同函数的同名变量
int func1() {
    int i = 0;  // 第58行
    return i;
}

int func2() {
    int i = 100; // 也可能是第58行
    return i;
}
```

## 💡 使用示例

### TacoSys驱动跟踪

```json
{
  "description": "TacoSys驱动调试",
  "breakpoints": [
    {
      "function_name": "mmz_param_parse",
      "source_file": "base_mod_init.c",
      "line_number": 58,
      "description": "找到anonymous时的变量状态",
      "variables": ["i", "anonymous_index"]
    },
    {
      "function_name": "base_init",
      "source_file": "base_mod_init.c",
      "line_number": 120,
      "description": "调用mmz_param_parse前",
      "variables": ["ret"]
    }
  ]
}
```

## 📺 输出示例

```
🎯 行号断点eBPF+DWARF+BCC跟踪器
📍 支持在源码行号设置断点，实时查看局部变量
================================================================================
[18:45:01.123] ✅ [SUCCESS] [       断点创建] 📍 mmz_param_parse() @ base_mod_init.c:58 -> 0x12345678
[18:45:01.124] ✅ [SUCCESS] [      跟踪开始] 开始跟踪 1 个断点
================================================================================
⚡ 等待断点触发... (按 Ctrl+C 停止)
================================================================================
[18:45:02.456] 🎯 [TRACE] [      断点触发] 🎯 mmz_param_parse() @ base_mod_init.c:58 | PID:1234
```

## 🛠️ 部署到远程主机

### 自动部署

```bash
# 使用提供的部署脚本
chmod +x deploy_tracer.sh
./deploy_tracer.sh
```

### 手动部署

```bash
# 上传文件
scp line_breakpoint_tracer.py root@192.168.56.255:/root/
scp line_breakpoint_config.json root@192.168.56.255:/root/

# SSH登录
ssh root@192.168.56.255

# 安装依赖
apt-get update
apt-get install -y python3-bpfcc python3-pip
pip3 install pyelftools

# 运行跟踪器
python3 line_breakpoint_tracer.py --help
```

## 🔧 命令行选项

```bash
# 显示帮助
python3 line_breakpoint_tracer.py --help

# 生成示例配置文件
python3 line_breakpoint_tracer.py --generate-config

# 运行跟踪
python3 line_breakpoint_tracer.py <ko文件> <配置文件>
```

## 🐛 故障排除

### 常见问题

1. **"ko文件缺少DWARF调试信息"**
   ```bash
   # 解决：使用 -g 选项重新编译内核模块
   make EXTRA_CFLAGS="-g" -C /lib/modules/$(uname -r)/build M=$(pwd) modules
   ```

2. **"需要root权限运行"**
   ```bash
   # 解决：使用 sudo 运行脚本
   sudo python3 line_breakpoint_tracer.py ...
   ```

3. **"未找到对应地址"**
   - 检查源文件名和行号是否正确
   - 确保使用的是带调试信息的.ko文件
   - 检查该行代码是否被编译器优化掉

4. **"无法附加探针"**
   - 确保内核模块已加载
   - 检查函数名是否存在于`/proc/kallsyms`
   - 尝试使用函数级别跟踪作为备用方案

### 调试技巧

1. 使用 `objdump -g your_driver.ko` 检查DWARF信息
2. 使用 `nm your_driver.ko` 查看符号表
3. 检查 `/proc/kallsyms` 确认函数是否已加载
4. 使用 `dmesg` 查看内核日志

## 🔬 技术原理

### DWARF调试信息解析

1. **解析ELF文件的DWARF段**
   - 读取编译单元 (Compilation Units)
   - 提取调试信息条目 (DIEs - Debug Information Entries)

2. **提取行号表 (Line Number Table)**
   - 建立源码行号到机器指令地址的映射
   - 处理编译器优化和内联函数

3. **分析变量位置信息 (Location Lists)**
   - 解析DWARF位置表达式
   - 确定变量在栈帧或寄存器中的位置

### eBPF探针机制

1. **kprobe探针设置**
   - 在目标地址设置内核探针
   - 动态插入BPF程序

2. **事件捕获**
   - 当执行到断点位置时触发eBPF程序
   - 读取CPU寄存器和栈内存

3. **变量值提取**
   - 根据DWARF位置信息读取变量值
   - 通过perf buffer传递到用户空间

4. **实时监控**
   - 用户空间程序接收并显示事件
   - 格式化输出调试信息

## ⚠️ 限制和注意事项

- 需要带调试符号的内核模块
- 编译优化可能影响变量跟踪精度
- 某些内联函数可能无法跟踪
- 需要root权限运行
- 对系统性能有轻微影响

## 📄 许可证

MIT License

## 👥 作者

AI助手 - 专业的内核调试工具开发

## 🤝 贡献

欢迎提交问题和改进建议！

---

**注意**: 这是一个高级调试工具，请谨慎在生产环境中使用。建议先在测试环境中验证功能。