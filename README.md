# MISC-Compass 🧭

面向 CTF MISC 初学者的离线文件分析与学习引导工具。它读取文件、展示线索并解释判断依据，帮助你决定下一步检查什么。当前为 **0.2.1 版本**，使用 C99 编写，无网络请求，不执行、解压或修改待分析文件。

## 能做什么

- 通过文件头识别 PNG、JPEG、ZIP、PDF、GIF、gzip、RAR、ELF、MZ 和 RIFF 的常见签名。
- 在独立结果区扫描非零偏移处的常见文件头（最多显示 10 个），提示可能嵌入的文件；结果可能是误报。
- 输出文件大小、前 16 字节、ASCII 可打印字符比例、字节熵，以及前 10 条 ASCII 字符串。
- 根据线索提供下一步建议和判断原理。界面目前使用英文，便于跨平台终端显示。

签名只是提示：格式可能伪造或损坏，未知签名也不代表恶意。熵不是加密检测器；字符串可能包含终端控制以外的误导内容，勿直接信任。不会提取嵌入文件、递归扫描或自动破解隐写。

## 编译与使用

需要 C99 编译器和 CMake 3.16 或更新版本。Windows 可使用 Visual Studio 的 C++ 编译工具、MinGW；Linux/macOS 可使用 GCC 或 Clang。

```sh
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

运行（Windows 多配置生成器的程序通常位于 `build/Release/misc-compass.exe`）：

```sh
./build/misc-compass path/to/challenge.bin
./build/misc-compass --help
```

测试需要 Python 3；未安装 Python 时 CMake 不会注册测试。程序对文件流式读取，内存占用固定；大文件仍需完整读取，耗时随文件大小增长。

## 学习路线

从 `src/main.c` 开始：先理解二进制读取、数组和结构体，再研究频率统计与香农熵。欢迎通过 Issue 提出可复现的问题或建议，通过 Pull Request 改进文档、测试和分析能力。

## 计划

- 更多格式及结构校验；可选中文输出。
- 基于格式结构的文件尾检查和嵌入内容验证。
- 更清晰的分模块设计与可扩展规则。

这些是计划而非已有功能。请仅分析有权处理的文件。详见 [贡献指南](CONTRIBUTING.md) 和 [MIT 许可证](LICENSE)。
