#!/usr/bin/env python3
"""
TacoSys内核模块DWARF精确调试跟踪器
基于DWARF信息解析，跟踪用户断点处的函数和变量
"""

from bcc import BPF
import argparse
import signal
import sys
import time
import os
from datetime import datetime

# DWARF解析的函数和变量位置信息
DWARF_PRECISE_INFO = {
    "mmz_param_parse": {
        "dwarf_offset": 0x9b9b,
        "address_offset": 0x8,
        "size": 0x286,
        "decl_line": 18,
        "variables": {
            "ret": {
                "dwarf_offset": 0x9bbd,
                "decl_line": 19,
                "type": "int",
                "location": "const_value:0"
            },
            "base_ctx_ptr": {
                "dwarf_offset": 0x9bca,
                "decl_line": 25,
                "type": "BASE_DRV_CONTEXT_T*",
                "location": "location_list:0x2b"
            },
            "mmz_str": {
                "dwarf_offset": 0x9bd9,
                "decl_line": 26,
                "type": "char*",
                "location": "location_list:0x4c"
            },
            "token": {
                "dwarf_offset": 0x9be8,
                "decl_line": 27,
                "type": "char*",
                "location": "location_list:0x6f"
            },
            "cur": {
                "dwarf_offset": 0x9bf7,
                "decl_line": 28,
                "type": "char*",
                "location": "fbreg:-176"
            },
            "i": {
                "dwarf_offset": 0x9c06,
                "decl_line": 29,
                "type": "int",
                "location": "location_list:0x99"
            },
            "anonymous_index": {
                "dwarf_offset": 0x9c12,
                "decl_line": 30,
                "type": "int",
                "location": "location_list:0xc6"
            }
        }
    },
    "base_mod_init": {
        "dwarf_offset": 0x9b36,
        "address_offset": 0x8,
        "size": 0x42,
        "decl_line": 88,
        "variables": {
            "ret": {
                "dwarf_offset": 0x9b58,
                "decl_line": 90,
                "type": "int",
                "location": "location_list"
            }
        }
    },
    "base_mod_exit": {
        "dwarf_offset": 0x9b0a,
        "address_offset": 0x0,
        "size": 0x18,
        "decl_line": 109,
        "variables": {}
    }
}

# 用户断点映射
USER_BREAKPOINTS = [
    {"line": 18, "function": "mmz_param_parse", "vars": ["mmz"]},
    {"line": 19, "function": "mmz_param_parse", "vars": ["mmz", "ret"]},
    {"line": 26, "function": "mmz_param_parse", "vars": ["base_ctx_ptr", "ret"]},
    {"line": 27, "function": "mmz_param_parse", "vars": ["base_ctx_ptr", "mmz_str", "ret"]},
    {"line": 28, "function": "mmz_param_parse", "vars": ["base_ctx_ptr", "mmz_str", "token", "ret"]},
    {"line": 29, "function": "mmz_param_parse", "vars": ["base_ctx_ptr", "mmz_str", "token", "cur", "i", "ret"]},
    {"line": 30, "function": "mmz_param_parse", "vars": ["base_ctx_ptr", "mmz_str", "token", "cur", "i", "anonymous_index", "ret"]},
    {"line": 38, "function": "mmz_param_parse", "vars": ["mmz_str", "mmz", "ret"]},
    {"line": 44, "function": "mmz_param_parse", "vars": ["cur", "mmz_str", "ret"]},
    {"line": 90, "function": "base_mod_init", "vars": ["ret"]},
    {"line": 96, "function": "base_mod_init", "vars": ["ret"]},
    {"line": 111, "function": "base_mod_exit", "vars": []}
]

# eBPF程序
BPF_PROGRAM = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/string.h>

// 事件数据结构
struct dwarf_breakpoint_event_t {
    u32 pid;
    u32 tid;
    u64 ts;
    u32 line;
    char function[32];
    char comm[TASK_COMM_LEN];
    u64 frame_pointer;
    u64 stack_pointer;
    u64 var_values[8];
    u32 var_count;
    char var_info[256];
};

BPF_PERF_OUTPUT(breakpoint_events);

// 从栈帧读取变量
static inline u64 read_frame_var(struct pt_regs *ctx, int offset) {
    u64 fp = PT_REGS_FP(ctx);
    u64 value = 0;
    bpf_probe_read_kernel(&value, sizeof(value), (void*)(fp + offset));
    return value;
}

// mmz_param_parse函数跟踪
int trace_mmz_param_parse_entry(struct pt_regs *ctx) {
    struct dwarf_breakpoint_event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    data.pid = pid_tgid >> 32;
    data.tid = (u32)pid_tgid;
    data.ts = bpf_ktime_get_ns();
    data.line = 18;
    data.frame_pointer = PT_REGS_FP(ctx);
    data.stack_pointer = PT_REGS_SP(ctx);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(data.function, "mmz_param_parse", 16);
    
    data.var_count = 0;
    data.var_values[0] = 0;  // ret变量初始值
    data.var_count++;
    data.var_values[1] = read_frame_var(ctx, -176);  // cur变量
    data.var_count++;
    
    __builtin_memcpy(data.var_info, "ret:int:0,cur:char*:-176", 25);
    
    breakpoint_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// mmz_param_parse函数退出跟踪
int trace_mmz_param_parse_exit(struct pt_regs *ctx) {
    struct dwarf_breakpoint_event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    data.pid = pid_tgid >> 32;
    data.tid = (u32)pid_tgid;
    data.ts = bpf_ktime_get_ns();
    data.line = 0;
    data.frame_pointer = PT_REGS_FP(ctx);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(data.function, "mmz_param_parse", 16);
    
    data.var_values[0] = PT_REGS_RC(ctx);  // 返回值
    data.var_count = 1;
    __builtin_memcpy(data.var_info, "return_value:int", 17);
    
    breakpoint_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// base_mod_init函数跟踪
int trace_base_mod_init_entry(struct pt_regs *ctx) {
    struct dwarf_breakpoint_event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    data.pid = pid_tgid >> 32;
    data.tid = (u32)pid_tgid;
    data.ts = bpf_ktime_get_ns();
    data.line = 88;
    data.frame_pointer = PT_REGS_FP(ctx);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(data.function, "base_mod_init", 14);
    
    data.var_values[0] = 0;  // ret变量初始值
    data.var_count = 1;
    __builtin_memcpy(data.var_info, "ret:int:0", 10);
    
    breakpoint_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// base_mod_init函数退出跟踪
int trace_base_mod_init_exit(struct pt_regs *ctx) {
    struct dwarf_breakpoint_event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    data.pid = pid_tgid >> 32;
    data.tid = (u32)pid_tgid;
    data.ts = bpf_ktime_get_ns();
    data.line = 0;
    data.frame_pointer = PT_REGS_FP(ctx);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(data.function, "base_mod_init", 14);
    
    data.var_values[0] = PT_REGS_RC(ctx);  // 返回值
    data.var_count = 1;
    __builtin_memcpy(data.var_info, "return_value:int", 17);
    
    breakpoint_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// base_mod_exit函数跟踪
int trace_base_mod_exit_entry(struct pt_regs *ctx) {
    struct dwarf_breakpoint_event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    data.pid = pid_tgid >> 32;
    data.tid = (u32)pid_tgid;
    data.ts = bpf_ktime_get_ns();
    data.line = 109;
    data.frame_pointer = PT_REGS_FP(ctx);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(data.function, "base_mod_exit", 14);
    
    data.var_count = 0;
    
    breakpoint_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

class DwarfBasedTracer:
    def __init__(self):
        self.bpf = None
        self.start_time = time.time()
        self.event_count = 0
        
    def load_bpf_program(self):
        try:
            self.bpf = BPF(text=BPF_PROGRAM)
            print("✓ eBPF程序加载成功")
            return True
        except Exception as e:
            print(f"✗ eBPF程序加载失败: {e}")
            return False
    
    def attach_kprobes(self):
        success_count = 0
        functions = [
            ("mmz_param_parse", "trace_mmz_param_parse_entry", "trace_mmz_param_parse_exit"),
            ("base_mod_init", "trace_base_mod_init_entry", "trace_base_mod_init_exit"),
            ("base_mod_exit", "trace_base_mod_exit_entry", None)
        ]
        
        for func_name, entry_handler, exit_handler in functions:
            try:
                self.bpf.attach_kprobe(event=func_name, fn_name=entry_handler)
                print(f"✓ 已附加kprobe到 {func_name} (入口)")
                success_count += 1
                
                if exit_handler:
                    self.bpf.attach_kretprobe(event=func_name, fn_name=exit_handler)
                    print(f"✓ 已附加kretprobe到 {func_name} (退出)")
                    
            except Exception as e:
                # 静默处理错误，因为我们会定期重试
                pass
        
        if success_count == 0:
            return False
        
        print(f"✓ 成功附加 {success_count} 个函数的kprobe")
        return True
    
    def print_event(self, cpu, data, size):
        event = self.bpf["breakpoint_events"].event(data)
        self.event_count += 1
        
        relative_time = (event.ts - (self.start_time * 1000000000)) / 1000000
        function_name = event.function.decode('utf-8', 'replace').rstrip('\x00')
        
        print(f"\n\n{'='*100}")
        print(f"[{self.event_count:04d}] {datetime.now().strftime('%H:%M:%S.%f')[:-3]} | "
              f"时间: +{relative_time:.3f}ms")
        print(f"PID: {event.pid} | TID: {event.tid} | 进程: {event.comm.decode('utf-8', 'replace')}")
        print(f"函数: {function_name} | 行号: {event.line if event.line > 0 else '退出'}")
        
        if function_name in DWARF_PRECISE_INFO:
            dwarf_info = DWARF_PRECISE_INFO[function_name]
            print(f"DWARF信息: 偏移=0x{dwarf_info['dwarf_offset']:x}, "
                  f"地址=0x{dwarf_info['address_offset']:x}, 大小=0x{dwarf_info['size']:x}")
        
        print(f"栈帧: FP=0x{event.frame_pointer:x}, SP=0x{event.stack_pointer:x}")
        
        if event.var_count > 0:
            print(f"变量信息 ({event.var_count}个):")
            var_info_str = event.var_info.decode('utf-8', 'replace').rstrip('\x00')
            
            if var_info_str:
                var_infos = var_info_str.split(',')
                for i, var_info in enumerate(var_infos[:event.var_count]):
                    if ':' in var_info:
                        parts = var_info.split(':')
                        if len(parts) >= 2:
                            var_name = parts[0]
                            var_type = parts[1]
                            location = parts[2] if len(parts) > 2 else "unknown"
                            
                            if i < len(event.var_values):
                                value = event.var_values[i]
                                print(f"  {var_name}({var_type}): {value} (0x{value:x}) [DWARF位置: {location}]")
            else:
                for i in range(min(event.var_count, len(event.var_values))):
                    print(f"  var_{i}: {event.var_values[i]} (0x{event.var_values[i]:x})")
        else:
            print("变量信息: 无")
        
        matching_bp = None
        for bp in USER_BREAKPOINTS:
            if bp['line'] == event.line and bp['function'] == function_name:
                matching_bp = bp
                break
        
        if matching_bp:
            print(f"匹配断点: 行{matching_bp['line']} | 期望变量: {', '.join(matching_bp['vars'])}")
        
        print(f"{'='*100}")
    
    def run(self):
        print("TacoSys DWARF精确调试跟踪器")
        print(f"目标模块: tacosys.ko | 用户断点数量: {len(USER_BREAKPOINTS)}")
        
        print(f"\nDWARF解析的函数信息:")
        for func_name, info in DWARF_PRECISE_INFO.items():
            print(f"  {func_name}: 偏移=0x{info['dwarf_offset']:x}, 行={info['decl_line']}, 变量={len(info['variables'])}个")
        
        if not self.load_bpf_program():
            return False
        
        # 设置5分钟超时
        timeout_seconds = 5 * 60  # 5分钟
        start_time = time.time()
        kprobes_attached = False
        last_retry_time = 0
        
        print(f"\n开始跟踪... (按Ctrl+C停止)")
        print("等待tacosys.ko模块加载...")
        print("超时时间: 5分钟 (如果没有检测到ko加载将自动退出)\n")
        
        try:
            while True:
                current_time = time.time()
                elapsed_time = current_time - start_time
                
                # 检查是否超时
                if elapsed_time >= timeout_seconds:
                    print(f"\n\n超时退出: 已等待{timeout_seconds//60}分钟，未检测到ko加载事件")
                    print(f"总事件数: {self.event_count}")
                    return True
                
                # 如果kprobe还没有附加成功，每10秒重试一次
                if not kprobes_attached and (current_time - last_retry_time) >= 10:
                    print(f"尝试附加kprobe... (已等待{int(elapsed_time)}秒)")
                    if self.attach_kprobes():
                        kprobes_attached = True
                        self.bpf["breakpoint_events"].open_perf_buffer(self.print_event)
                        print("kprobe附加成功，开始监听事件...")
                    else:
                        remaining_time = timeout_seconds - elapsed_time
                        print(f"kprobe附加失败，将在10秒后重试 (剩余{int(remaining_time)}秒)")
                    last_retry_time = current_time
                
                # 如果kprobe已经附加，开始监听事件
                if kprobes_attached:
                    self.bpf.perf_buffer_poll(timeout=1000)  # 1秒超时
                else:
                    # 如果还没有附加成功，等待1秒
                    time.sleep(1)
                    
        except KeyboardInterrupt:
            print(f"\n\n跟踪完成 | 总事件数: {self.event_count}")
            return True
    
    def cleanup(self):
        if self.bpf:
            print("清理eBPF资源...")

def main():
    parser = argparse.ArgumentParser(description='TacoSys DWARF精确调试跟踪器')
    parser.add_argument('--show-dwarf', action='store_true', help='显示DWARF解析信息')
    parser.add_argument('--show-breakpoints', action='store_true', help='显示用户断点配置')
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("错误: 需要root权限运行")
        sys.exit(1)
    
    if args.show_dwarf:
        print("DWARF解析的精确信息:")
        for func_name, info in DWARF_PRECISE_INFO.items():
            print(f"\n函数: {func_name}")
            print(f"  DWARF偏移: 0x{info['dwarf_offset']:x}")
            print(f"  地址偏移: 0x{info['address_offset']:x}")
            print(f"  大小: 0x{info['size']:x}")
            print(f"  声明行: {info['decl_line']}")
            print(f"  变量:")
            for var_name, var_info in info['variables'].items():
                print(f"    {var_name}({var_info['type']}): 行{var_info['decl_line']}, 位置={var_info['location']}")
        return
    
    if args.show_breakpoints:
        print("用户设置的断点:")
        for i, bp in enumerate(USER_BREAKPOINTS, 1):
            print(f"{i:2d}. 行{bp['line']:3d} | {bp['function']:20s} | 变量: {', '.join(bp['vars']) if bp['vars'] else '无'}")
        return
    
    def signal_handler(sig, frame):
        print("\n正在停止...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    tracer = DwarfBasedTracer()
    try:
        tracer.run()
    finally:
        tracer.cleanup()

if __name__ == "__main__":
    main()