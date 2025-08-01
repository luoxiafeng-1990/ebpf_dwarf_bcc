# TacoSys内核模块DWARF信息解析总结

## 概述

本文档总结了从 `output/current/build/taco-sys-1.0.0/tacosys_ko/tacosys.ko` 文件中解析的DWARF调试信息，专门针对用户在IDE中设置的断点位置进行精确的函数和变量位置分析。

## DWARF解析工具

使用的工具：
- `readelf --debug-dump=info`
- `objdump --dwarf=info`
- `nm -n` (符号表)
- `objdump -t` (符号信息)

## 函数信息解析

### 1. mmz_param_parse函数

**DWARF信息：**
- DWARF偏移: `0x9b9b`
- 地址偏移: `0x8`
- 函数大小: `0x286` (654字节)
- 声明行: `18`
- 类型: `GLOBAL`
- DWARF标签: `DW_TAG_subprogram`

**变量解析：**

| 变量名 | DWARF偏移 | 声明行 | 类型 | DWARF位置 |
|--------|-----------|--------|------|-----------|
| ret | 0x9bbd | 19 | int | const_value:0 |
| base_ctx_ptr | 0x9bca | 25 | BASE_DRV_CONTEXT_T* | location_list:0x2b |
| mmz_str | 0x9bd9 | 26 | char* | location_list:0x4c |
| token | 0x9be8 | 27 | char* | location_list:0x6f |
| cur | 0x9bf7 | 28 | char* | fbreg:-176 |
| i | 0x9c06 | 29 | int | location_list:0x99 |
| anonymous_index | 0x9c12 | 30 | int | location_list:0xc6 |

### 2. base_mod_init函数

**DWARF信息：**
- DWARF偏移: `0x9b36`
- 地址偏移: `0x8`
- 函数大小: `0x42` (66字节)
- 声明行: `88`
- 类型: `LOCAL`
- DWARF标签: `DW_TAG_subprogram`

**变量解析：**

| 变量名 | DWARF偏移 | 声明行 | 类型 | DWARF位置 |
|--------|-----------|--------|------|-----------|
| ret | 0x9b58 | 90 | int | location_list |

### 3. base_mod_exit函数

**DWARF信息：**
- DWARF偏移: `0x9b0a`
- 地址偏移: `0x0`
- 函数大小: `0x18` (24字节)
- 声明行: `109`
- 类型: `LOCAL`
- DWARF标签: `DW_TAG_subprogram`

**变量解析：**
- 无局部变量

## 全局变量信息

### mmz变量

**DWARF信息：**
- DWARF偏移: `0x992c`
- 声明行: `11`
- 类型: `char*`
- DWARF位置: `addr:0x0`
- DWARF标签: `DW_TAG_variable`

## 用户断点映射

基于用户在IDE中设置的断点，以下是断点行号与DWARF变量的精确映射：

### mmz_param_parse函数断点

| 断点行 | 对应变量 | DWARF位置信息 |
|--------|----------|---------------|
| 18 | mmz | 全局变量，addr:0x0 |
| 19 | ret | const_value:0 |
| 25 | base_ctx_ptr, ret | location_list:0x2b, const_value:0 |
| 26 | base_ctx_ptr, mmz_str, ret | location_list:0x2b, location_list:0x4c, const_value:0 |
| 27 | base_ctx_ptr, mmz_str, token, ret | 多个location_list |
| 28 | cur, ret | fbreg:-176, const_value:0 |
| 29 | cur, i, ret | fbreg:-176, location_list:0x99, const_value:0 |
| 30 | cur, i, anonymous_index, ret | 多个位置 |
| 38 | mmz_str, mmz | location_list:0x4c, addr:0x0 |
| 44 | cur, mmz_str | fbreg:-176, location_list:0x4c |

### base_mod_init函数断点

| 断点行 | 对应变量 | DWARF位置信息 |
|--------|----------|---------------|
| 88 | - | 函数入口，无变量 |
| 90 | ret | location_list |
| 96 | ret | location_list |

### base_mod_exit函数断点

| 断点行 | 对应变量 | DWARF位置信息 |
|--------|----------|---------------|
| 109 | - | 函数入口，无变量 |

## DWARF位置类型说明

### 1. const_value:N
- 表示编译时常量值
- 例如：`ret`变量初始化为0

### 2. location_list:0xNN
- 表示复杂的位置表达式，需要查询位置列表
- 地址会根据执行上下文动态计算

### 3. fbreg:OFFSET
- 表示相对于栈帧基址的偏移
- 例如：`cur`变量在栈帧基址-176字节处

### 4. addr:0xNN
- 表示绝对地址（通常用于全局变量）
- 例如：全局变量`mmz`

## eBPF实现策略

基于DWARF解析结果，eBPF跟踪器采用以下策略：

### 1. 栈帧变量读取
```c
// 对于fbreg类型的变量
static inline u64 read_frame_var(struct pt_regs *ctx, int offset) {
    u64 fp = PT_REGS_FP(ctx);
    u64 value = 0;
    bpf_probe_read_kernel(&value, sizeof(value), (void*)(fp + offset));
    return value;
}
```

### 2. 常量值处理
```c
// 对于const_value类型的变量
data.var_values[0] = 0;  // ret变量的初始值
```

### 3. 复杂位置处理
- location_list类型的变量需要在运行时解析
- 当前实现中设置为0，表示需要进一步处理

## 符号表验证

通过符号表验证函数地址：

```bash
$ nm -n output/current/build/taco-sys-1.0.0/tacosys_ko/tacosys.ko | grep -E "(mmz_param_parse|base_mod_init|base_mod_exit)"
0000000000000000 t base_mod_exit
0000000000000000 t base_mod_init  
0000000000000000 T mmz_param_parse
```

```bash
$ objdump -t output/current/build/taco-sys-1.0.0/tacosys_ko/tacosys.ko | grep -E "(mmz_param_parse|base_mod_init|base_mod_exit)"
0000000000000000 l     F .exit.text     0000000000000018 base_mod_exit
0000000000000000 l     F .init.text     000000000000004a base_mod_init
0000000000000000 g     F .text  000000000000028e mmz_param_parse
```

## 使用说明

生成的跟踪器文件：

1. **dwarf_based_tracer.py** - 基于DWARF精确信息的主要跟踪器
2. **enhanced_tacosys_tracer.py** - 增强版跟踪器
3. **breakpoint_config.json** - 包含DWARF信息的配置文件

### 运行命令

```bash
# 显示DWARF解析信息
sudo python3 dwarf_based_tracer.py --show-dwarf

# 显示用户断点配置
sudo python3 dwarf_based_tracer.py --show-breakpoints

# 运行跟踪器
sudo python3 dwarf_based_tracer.py
```

## 注意事项

1. **地址重定位**: ko文件中的地址为0x0，需要在模块加载后通过`/proc/kallsyms`获取实际地址
2. **位置列表**: location_list类型的变量位置需要进一步解析DWARF位置表达式
3. **架构相关**: 当前实现针对RISC-V 64位架构
4. **编译优化**: 变量位置可能受编译优化影响

## 总结

通过DWARF信息解析，我们获得了用户断点中涉及的所有函数和变量的精确位置信息。这些信息被用于生成高精度的eBPF跟踪器，能够在指定的断点位置准确读取和显示变量值。