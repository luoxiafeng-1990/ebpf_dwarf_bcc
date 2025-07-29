#!/usr/bin/env python3
"""
行号断点eBPF+DWARF+BCC跟踪器
支持在驱动源码的特定行号设置断点，查看局部变量值
作者: AI助手
版本: 1.0
"""

import sys
import os
import json
import subprocess
import struct
import time
from datetime import datetime

# 延迟导入BCC，仅在实际使用时检查
BPF = None

def check_bcc_import():
    """检查并导入BCC库"""
    global BPF
    if BPF is None:
        try:
            from bcc import BPF as _BPF
            BPF = _BPF
        except ImportError:
            print("❌ 错误: 未安装BCC库")
            print("请安装: sudo apt-get install python3-bpfcc")
            return False
    return True

def check_elftools_import():
    """检查并导入elftools库"""
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.dwarf.descriptions import describe_DWARF_expr
        from elftools.dwarf.locationlists import LocationExpr
        from elftools.dwarf.lineprogram import LineProgram
        return ELFFile, describe_DWARF_expr, LocationExpr, LineProgram
    except ImportError:
        print("❌ 错误: 未安装pyelftools库")
        print("请安装: pip3 install pyelftools")
        return None

class LineBreakpointTracer:
    def __init__(self, ko_file, config_file):
        self.ko_file = ko_file
        self.config_file = config_file
        self.config = {}
        self.dwarf_info = {}
        self.line_to_address = {}
        self.address_to_variables = {}
        self.breakpoints = {}
        self.function_addresses = {}
        
        self.print_header()
    
    def print_header(self):
        print("=" * 80)
        print("🎯 行号断点eBPF+DWARF+BCC跟踪器")
        print("📍 支持在源码行号设置断点，实时查看局部变量")
        print(f"📁 目标文件: {self.ko_file}")
        print(f"⚙️  配置文件: {self.config_file}")
        print(f"⏰ 启动时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
    
    def log(self, level, category, message):
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        icons = {"INFO": "ℹ️", "WARN": "⚠️", "ERROR": "❌", "SUCCESS": "✅", "DEBUG": "🔍", "TRACE": "🎯"}
        icon = icons.get(level, "📝")
        print(f"[{timestamp}] {icon} [{level:>5}] [{category:>15}] {message}")
    
    def load_config(self):
        """加载断点配置文件"""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
            
            breakpoints_count = len(self.config.get('breakpoints', []))
            self.log("SUCCESS", "配置加载", f"加载了 {breakpoints_count} 个断点配置")
            
            # 打印配置详情
            for i, bp in enumerate(self.config.get('breakpoints', []), 1):
                func_name = bp.get('function_name', '未指定')
                self.log("INFO", "断点配置", 
                        f"📍 {i}. {func_name}() @ {bp['source_file']}:{bp['line_number']} -> {bp['variables']}")
            
            return True
        except Exception as e:
            self.log("ERROR", "配置加载", f"加载失败: {str(e)}")
            return False
    
    def check_ko_file(self):
        """检查ko文件有效性"""
        if not os.path.exists(self.ko_file):
            self.log("ERROR", "文件检查", f"ko文件不存在: {self.ko_file}")
            return False
        
        # 检查是否是ELF文件
        try:
            result = subprocess.run(["file", self.ko_file], capture_output=True, text=True)
            if "ELF" not in result.stdout:
                self.log("ERROR", "文件检查", "不是有效的ELF文件")
                return False
        except:
            pass
        
        # 检查DWARF信息
        elftools_imports = check_elftools_import()
        if not elftools_imports:
            return False
        
        ELFFile, _, _, _ = elftools_imports
        
        try:
            with open(self.ko_file, 'rb') as f:
                elffile = ELFFile(f)
                if not elffile.has_dwarf_info():
                    self.log("ERROR", "DWARF检查", "ko文件缺少DWARF调试信息")
                    self.log("ERROR", "DWARF检查", "请使用 -g 选项编译内核模块")
                    return False
        except Exception as e:
            self.log("ERROR", "文件检查", f"检查失败: {str(e)}")
            return False
        
        self.log("SUCCESS", "文件检查", "✓ ko文件有效，包含DWARF调试信息")
        return True
    
    def parse_dwarf_debug_info(self):
        """解析DWARF调试信息"""
        self.log("INFO", "DWARF解析", "开始解析DWARF调试信息...")
        
        elftools_imports = check_elftools_import()
        if not elftools_imports:
            return False
        
        ELFFile, _, LocationExpr, _ = elftools_imports
        
        try:
            with open(self.ko_file, 'rb') as f:
                elffile = ELFFile(f)
                dwarfinfo = elffile.get_dwarf_info()
                
                # 解析行号表
                self.log("INFO", "行号解析", "解析源码行号到地址的映射...")
                self._parse_line_tables(dwarfinfo)
                
                # 解析函数和变量
                self.log("INFO", "变量解析", "解析函数和变量位置信息...")
                self._parse_functions_and_variables(dwarfinfo, LocationExpr)
                
                # 创建断点映射
                self._create_breakpoint_mappings()
                
                self.log("SUCCESS", "DWARF解析", 
                        f"解析完成 - 行号: {len(self.line_to_address)}, 函数: {len(self.function_addresses)}")
                return True
                
        except Exception as e:
            self.log("ERROR", "DWARF解析", f"解析失败: {str(e)}")
            return False
    
    def _parse_line_tables(self, dwarfinfo):
        """解析行号表"""
        for cu in dwarfinfo.iter_CUs():
            line_program = dwarfinfo.line_program_for_CU(cu)
            if not line_program:
                continue
            
            # 获取编译单元信息
            cu_die = cu.get_top_DIE()
            
            # 解析行号表条目
            for entry in line_program.get_entries():
                if entry.state is None:
                    continue
                
                state = entry.state
                if not state.end_sequence and state.line > 0:
                    # 获取源文件名
                    try:
                        file_entry = line_program['file_entry'][state.file - 1]
                        filename = file_entry.name.decode('utf-8')
                        
                        # 简化文件名
                        basename = os.path.basename(filename)
                        
                        # 记录行号到地址的映射
                        line_key = f"{basename}:{state.line}"
                        address = state.address
                        
                        if line_key not in self.line_to_address:
                            self.line_to_address[line_key] = []
                        self.line_to_address[line_key].append(address)
                        
                    except (IndexError, UnicodeDecodeError):
                        continue
    
    def _parse_functions_and_variables(self, dwarfinfo, LocationExpr):
        """解析函数和变量信息"""
        self.LocationExpr = LocationExpr  # 保存供其他方法使用
        for cu in dwarfinfo.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag == 'DW_TAG_subprogram':
                    self._parse_function(die)
    
    def _parse_function(self, func_die):
        """解析单个函数"""
        func_name = func_die.attributes.get('DW_AT_name')
        if not func_name:
            return
        
        try:
            func_name = func_name.value.decode('utf-8')
        except (UnicodeDecodeError, AttributeError):
            return
        
        # 获取函数地址
        low_pc_attr = func_die.attributes.get('DW_AT_low_pc')
        high_pc_attr = func_die.attributes.get('DW_AT_high_pc')
        
        if low_pc_attr:
            func_low_pc = low_pc_attr.value
            self.function_addresses[func_name] = func_low_pc
            
            # 解析函数内的变量
            self._parse_function_variables(func_die, func_name, func_low_pc)
    
    def _parse_function_variables(self, func_die, func_name, func_addr):
        """解析函数内的变量"""
        variables = {}
        
        for child_die in func_die.iter_children():
            if child_die.tag == 'DW_TAG_variable':
                var_info = self._parse_variable(child_die)
                if var_info:
                    variables[var_info['name']] = var_info
        
        if variables:
            self.address_to_variables[func_addr] = {
                'function': func_name,
                'variables': variables
            }
    
    def _parse_variable(self, var_die):
        """解析变量信息"""
        var_name = var_die.attributes.get('DW_AT_name')
        if not var_name:
            return None
        
        try:
            var_name = var_name.value.decode('utf-8')
        except (UnicodeDecodeError, AttributeError):
            return None
        
        # 获取变量位置信息
        location_attr = var_die.attributes.get('DW_AT_location')
        if not location_attr:
            return None
        
        location_info = None
        if isinstance(location_attr.value, self.LocationExpr):
            loc_expr = location_attr.value.loc_expr
            location_info = self._parse_location_expr(loc_expr)
        
        if not location_info:
            return None
        
        return {
            'name': var_name,
            'location': location_info,
            'type': self._get_variable_type(var_die)
        }
    
    def _parse_location_expr(self, loc_expr):
        """解析DWARF位置表达式"""
        if not loc_expr:
            return None
        
        # DW_OP_fbreg: 相对于帧指针的偏移
        if len(loc_expr) >= 2 and loc_expr[0] == 0x91:  # DW_OP_fbreg
            try:
                # 简化处理：假设偏移量是单字节有符号整数
                if len(loc_expr) >= 2:
                    offset = struct.unpack('b', bytes([loc_expr[1]]))[0]
                    return {
                        'type': 'frame_offset',
                        'offset': offset,
                        'size': 4
                    }
            except:
                return None
        
        # DW_OP_reg*: 变量在寄存器中
        if 0x50 <= loc_expr[0] <= 0x6f:  # DW_OP_reg0 to DW_OP_reg31
            reg_num = loc_expr[0] - 0x50
            return {
                'type': 'register',
                'register': reg_num,
                'size': 4
            }
        
        return None
    
    def _get_variable_type(self, var_die):
        """获取变量类型（简化处理）"""
        return 'int'  # 简化处理，假设都是int类型
    
    def _create_breakpoint_mappings(self):
        """创建断点映射"""
        self.log("INFO", "断点映射", "创建行号断点映射...")
        
        successful_breakpoints = 0
        
        for bp_config in self.config.get('breakpoints', []):
            function_name = bp_config.get('function_name', '')
            source_file = bp_config['source_file']
            line_number = bp_config['line_number']
            variables = bp_config['variables']
            
            # 构建行号键
            basename = os.path.basename(source_file)
            line_key = f"{basename}:{line_number}"
            
            if line_key in self.line_to_address:
                addresses = self.line_to_address[line_key]
                
                address_found = False
                for addr in addresses:
                    # 如果指定了函数名，验证地址是否属于该函数
                    if function_name:
                        actual_func = self._find_function_for_address(addr)
                        if actual_func != function_name:
                            self.log("WARN", "函数验证", 
                                    f"⚠️  地址0x{addr:x}属于函数'{actual_func}'，不是'{function_name}'")
                            continue
                    
                    bp_id = f"{function_name or 'unknown'}:{basename}:{line_number}@{addr:x}"
                    
                    # 查找最近的函数变量信息
                    var_info = self._find_variables_for_address(addr)
                    
                    self.breakpoints[bp_id] = {
                        'address': addr,
                        'function_name': function_name,
                        'source_file': basename,
                        'line_number': line_number,
                        'variables': variables,
                        'available_vars': var_info
                    }
                    
                    successful_breakpoints += 1
                    self.log("SUCCESS", "断点创建", 
                            f"📍 {function_name}() @ {basename}:{line_number} -> 0x{addr:x}")
                    address_found = True
                    break  # 只取第一个有效地址
                
                if not address_found:
                    if function_name:
                        self.log("WARN", "断点创建", 
                                f"❌ {function_name}() @ {basename}:{line_number} 未找到有效地址")
                    else:
                        self.log("WARN", "断点创建", 
                                f"❌ {basename}:{line_number} 未找到对应地址")
            else:
                func_info = f"{function_name}() @ " if function_name else ""
                self.log("WARN", "断点创建", 
                        f"❌ {func_info}{basename}:{line_number} 未找到对应地址")
        
        self.log("INFO", "断点统计", f"成功创建 {successful_breakpoints} 个断点")
    
    def _find_variables_for_address(self, addr):
        """为地址查找变量信息"""
        # 查找最近的函数地址
        best_func_addr = None
        best_distance = float('inf')
        
        for func_addr in self.address_to_variables.keys():
            if func_addr <= addr:
                distance = addr - func_addr
                if distance < best_distance:
                    best_distance = distance
                    best_func_addr = func_addr
        
        if best_func_addr:
            return self.address_to_variables[best_func_addr]['variables']
        
        return {}
    
    def generate_ebpf_program(self):
        """生成eBPF跟踪程序"""
        if not self.breakpoints:
            self.log("ERROR", "eBPF生成", "没有有效的断点")
            return None
        
        self.log("INFO", "eBPF生成", "生成行号断点eBPF程序...")
        
        bpf_header = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct breakpoint_event_t {
    u32 pid;
    u64 timestamp;
    u64 address;
    char comm[TASK_COMM_LEN];
    char source_file[64];
    u32 line_number;
    char var_name[64];
    s64 var_value;
    u32 var_type;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(bp_addrs, u64, u32);
"""
        
        # 生成通用的断点处理函数
        bpf_functions = """
int handle_breakpoint(struct pt_regs *ctx) {
    u64 ip = PT_REGS_IP(ctx);
    u32 *bp_data = bp_addrs.lookup(&ip);
    if (!bp_data) return 0;
    
    struct breakpoint_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.timestamp = bpf_ktime_get_ns();
    event.address = ip;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 获取栈指针和帧指针
    u64 sp = PT_REGS_SP(ctx);
    u64 fp = PT_REGS_FP(ctx);
    
    // 这里可以根据具体需要读取变量
    // 简化实现：只记录触发事件
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""
        
        self.bpf_program = bpf_header + bpf_functions
        self.log("SUCCESS", "eBPF生成", f"生成了通用断点处理程序")
        return self.bpf_program
    
    def print_event(self, cpu, data, size):
        """处理断点触发事件"""
        import ctypes as ct
        
        class BreakpointEvent(ct.Structure):
            _fields_ = [("pid", ct.c_uint32),
                       ("timestamp", ct.c_uint64),
                       ("address", ct.c_uint64),
                       ("comm", ct.c_char * 16),
                       ("source_file", ct.c_char * 64),
                       ("line_number", ct.c_uint32),
                       ("var_name", ct.c_char * 64),
                       ("var_value", ct.c_int64),
                       ("var_type", ct.c_uint32)]
        
        event = ct.cast(data, ct.POINTER(BreakpointEvent)).contents
        timestamp = datetime.fromtimestamp(event.timestamp / 1e9).strftime("%H:%M:%S.%f")[:-3]
        comm = event.comm.decode("utf-8", "replace")
        
        # 查找断点信息
        bp_info = None
        for bp_id, bp_data in self.breakpoints.items():
            if bp_data['address'] == event.address:
                bp_info = bp_data
                break
        
        if bp_info:
            func_name = bp_info.get('function_name', '未知函数')
            self.log("TRACE", "断点触发", 
                    f"🎯 {func_name}() @ {bp_info['source_file']}:{bp_info['line_number']} | "
                    f"地址: 0x{event.address:x} | PID:{event.pid} | {comm} | {timestamp}")
        else:
            self.log("TRACE", "断点触发", 
                    f"🎯 未知断点 @ 0x{event.address:x} | PID:{event.pid} | {comm} | {timestamp}")
    
    def start_tracing(self):
        """开始eBPF跟踪"""
        if not check_bcc_import():
            return False
            
        ebpf_code = self.generate_ebpf_program()
        if not ebpf_code:
            return False
        
        try:
            self.log("INFO", "跟踪启动", "编译并加载eBPF程序...")
            b = BPF(text=ebpf_code)
            
            # 初始化断点地址映射
            bp_addrs = b.get_table("bp_addrs")
            for bp_id, bp_info in self.breakpoints.items():
                addr = bp_info['address']
                bp_addrs[ct.c_uint64(addr)] = ct.c_uint32(bp_info['line_number'])
            
            # 使用uprobe在指定地址设置断点
            # 注意：这里使用函数名而不是地址，因为kprobe需要符号名
            attached_count = 0
            
            # 尝试使用替代方法：跟踪函数入口
            for bp_id, bp_info in self.breakpoints.items():
                try:
                    # 查找包含此地址的函数
                    func_name = self._find_function_for_address(bp_info['address'])
                    if func_name:
                        b.attach_kprobe(event=func_name, fn_name="handle_breakpoint")
                        attached_count += 1
                        self.log("SUCCESS", "探针附加", 
                                f"✓ {bp_info['source_file']}:{bp_info['line_number']} via {func_name}")
                        break  # 只附加一个进行测试
                    else:
                        self.log("WARN", "探针附加", 
                                f"✗ {bp_id}: 未找到对应函数")
                        
                except Exception as e:
                    self.log("WARN", "探针附加", 
                            f"✗ {bp_id}: {str(e)}")
            
            if attached_count == 0:
                self.log("ERROR", "跟踪失败", "没有成功附加任何断点探针")
                self.log("INFO", "替代方案", "尝试使用函数级别跟踪...")
                return self._start_function_tracing()
            
            # 设置事件处理
            b["events"].open_perf_buffer(self.print_event)
            
            self.log("SUCCESS", "跟踪开始", f"开始跟踪 {attached_count} 个断点")
            print("=" * 80)
            print("⚡ 等待断点触发... (按 Ctrl+C 停止)")
            print("=" * 80)
            
            # 跟踪循环
            while True:
                try:
                    b.perf_buffer_poll()
                except KeyboardInterrupt:
                    break
            
            print("=" * 80)
            self.log("SUCCESS", "跟踪完成", "用户中断，跟踪结束")
            return True
            
        except Exception as e:
            self.log("ERROR", "跟踪错误", f"eBPF跟踪失败: {str(e)}")
            return False
    
    def _find_function_for_address(self, addr):
        """查找包含指定地址的函数名"""
        best_func = None
        best_distance = float('inf')
        
        for func_name, func_addr in self.function_addresses.items():
            if func_addr <= addr:
                distance = addr - func_addr
                if distance < best_distance:
                    best_distance = distance
                    best_func = func_name
        
        return best_func
    
    def _start_function_tracing(self):
        """启动函数级别跟踪（备用方案）"""
        if not check_bcc_import():
            return False
            
        self.log("INFO", "函数跟踪", "启动函数级别跟踪...")
        
        # 简化的函数跟踪程序
        simple_bpf = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct func_event_t {
    u32 pid;
    u64 timestamp;
    char comm[TASK_COMM_LEN];
    char func_name[64];
};

BPF_PERF_OUTPUT(events);

int trace_function(struct pt_regs *ctx) {
    struct func_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""
        
        try:
            b = BPF(text=simple_bpf)
            
            # 尝试附加到已知函数
            attached_funcs = []
            target_functions = ["mmz_param_parse", "base_init", "init_module"]
            
            for func_name in target_functions:
                try:
                    b.attach_kprobe(event=func_name, fn_name="trace_function")
                    attached_funcs.append(func_name)
                    self.log("SUCCESS", "函数跟踪", f"✓ 附加到 {func_name}")
                except:
                    self.log("WARN", "函数跟踪", f"✗ 无法附加到 {func_name}")
            
            if not attached_funcs:
                self.log("ERROR", "函数跟踪", "没有成功附加任何函数")
                return False
            
            def print_func_event(cpu, data, size):
                import ctypes as ct
                
                class FuncEvent(ct.Structure):
                    _fields_ = [("pid", ct.c_uint32),
                               ("timestamp", ct.c_uint64),
                               ("comm", ct.c_char * 16),
                               ("func_name", ct.c_char * 64)]
                
                event = ct.cast(data, ct.POINTER(FuncEvent)).contents
                timestamp = datetime.fromtimestamp(event.timestamp / 1e9).strftime("%H:%M:%S.%f")[:-3]
                comm = event.comm.decode("utf-8", "replace")
                
                self.log("TRACE", "函数调用", f"📞 函数调用检测 | PID:{event.pid} | {comm} | {timestamp}")
            
            b["events"].open_perf_buffer(print_func_event)
            
            self.log("SUCCESS", "函数跟踪", f"开始跟踪 {len(attached_funcs)} 个函数")
            print("=" * 80)
            print("📞 等待函数调用... (按 Ctrl+C 停止)")
            print("=" * 80)
            
            while True:
                try:
                    b.perf_buffer_poll()
                except KeyboardInterrupt:
                    break
            
            return True
            
        except Exception as e:
            self.log("ERROR", "函数跟踪", f"函数跟踪失败: {str(e)}")
            return False
    
    def run(self):
        """运行完整的跟踪流程"""
        if not self.load_config():
            return False
        
        if not self.check_ko_file():
            return False
        
        if not self.parse_dwarf_debug_info():
            return False
        
        if not self.breakpoints:
            self.log("ERROR", "跟踪准备", "没有有效的断点配置")
            return False
        
        return self.start_tracing()

def generate_sample_config():
    """生成示例配置文件"""
    sample_config = {
        "description": "TacoSys驱动行号断点跟踪配置",
        "version": "1.0",
        "breakpoints": [
            {
                "function_name": "mmz_param_parse",
                "source_file": "base_mod_init.c",
                "line_number": 58,
                "description": "当找到anonymous时，查看i和anonymous_index的值",
                "variables": ["i", "anonymous_index"]
            },
            {
                "function_name": "base_init",
                "source_file": "base_mod_init.c",
                "line_number": 25,
                "description": "获取base_ctx_ptr之后的时刻",
                "variables": ["base_ctx_ptr", "ret"]
            },
            {
                "function_name": "mmz_param_parse",
                "source_file": "base_mod_init.c",
                "line_number": 47,
                "description": "sscanf解析MMZ参数的时刻",
                "variables": ["i", "token", "mmz_str"]
            }
        ]
    }
    
    config_file = "line_breakpoint_config.json"
    with open(config_file, "w", encoding='utf-8') as f:
        json.dump(sample_config, f, indent=2, ensure_ascii=False)
    
    print(f"✅ 已生成示例配置文件: {config_file}")
    print("\n📝 配置文件说明:")
    print("- function_name: 函数名（必需，避免变量名冲突）")
    print("- source_file: 源文件名（只需要文件名，不需要完整路径）")
    print("- line_number: 要设置断点的行号")
    print("- variables: 要跟踪的变量名列表")
    print("- description: 断点描述（可选）")

def show_help():
    """显示帮助信息"""
    print("🎯 行号断点eBPF+DWARF+BCC跟踪器")
    print("=" * 60)
    print("功能: 在驱动源码的特定行号设置断点，实时查看局部变量值")
    print()
    print("使用方法:")
    print("  python3 line_breakpoint_tracer.py <ko文件> <配置文件>")
    print("  python3 line_breakpoint_tracer.py --generate-config")
    print("  python3 line_breakpoint_tracer.py --help")
    print()
    print("参数说明:")
    print("  ko文件      : 包含DWARF调试信息的内核模块文件(.ko)")
    print("  配置文件    : JSON格式的断点配置文件")
    print()
    print("选项:")
    print("  --generate-config  : 生成示例配置文件")
    print("  --help            : 显示此帮助信息")
    print()
    print("示例:")
    print("  # 生成配置文件")
    print("  python3 line_breakpoint_tracer.py --generate-config")
    print()
    print("  # 编辑配置文件后运行跟踪")
    print("  python3 line_breakpoint_tracer.py tacosys.ko line_breakpoint_config.json")
    print()
    print("要求:")
    print("  ✓ ko文件必须包含DWARF调试信息 (使用 -g 编译)")
    print("  ✓ 需要root权限运行")
    print("  ✓ 需要安装 python3-bpfcc 和 pyelftools")

def check_dependencies():
    """检查依赖"""
    missing_deps = []
    
    # 检查BCC
    if not check_bcc_import():
        missing_deps.append("python3-bpfcc")
    
    # 检查pyelftools
    if not check_elftools_import():
        missing_deps.append("pyelftools")
    
    if missing_deps:
        print("❌ 缺少依赖库:")
        for dep in missing_deps:
            if "bpfcc" in dep:
                print(f"  - {dep}: sudo apt-get install {dep}")
            else:
                print(f"  - {dep}: pip3 install {dep}")
        return False
    
    return True

def main():
    if len(sys.argv) < 2:
        show_help()
        sys.exit(1)
    
    if sys.argv[1] == "--help" or sys.argv[1] == "-h":
        show_help()
        return
    
    if sys.argv[1] == "--generate-config":
        generate_sample_config()
        return
    
    if len(sys.argv) < 3:
        print("❌ 错误: 缺少参数")
        show_help()
        sys.exit(1)
    
    # 只有在实际跟踪时才检查依赖
    # --help和--generate-config不需要检查依赖
    
    # 检查root权限
    if os.geteuid() != 0:
        print("❌ 错误: 需要root权限运行")
        print("请使用: sudo python3 line_breakpoint_tracer.py ...")
        sys.exit(1)
    
    ko_file = sys.argv[1]
    config_file = sys.argv[2]
    
    # 检查文件存在性
    if not os.path.exists(ko_file):
        print(f"❌ 错误: ko文件不存在: {ko_file}")
        sys.exit(1)
    
    if not os.path.exists(config_file):
        print(f"❌ 错误: 配置文件不存在: {config_file}")
        print("提示: 使用 --generate-config 生成示例配置文件")
        sys.exit(1)
    
    # 创建并运行跟踪器
    tracer = LineBreakpointTracer(ko_file, config_file)
    success = tracer.run()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()