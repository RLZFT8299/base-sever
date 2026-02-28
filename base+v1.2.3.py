import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import base64
import os
import re

# ==================== 卡片式设计样式配置 ====================
def setup_style():
    style = ttk.Style()
    style.theme_use('clam')
    style.configure('Card.TFrame', background='#ffffff', relief='solid', borderwidth=1)
    style.configure('Sidebar.TFrame', background='#f0f0f0', relief='flat')
    style.configure('Nav.TButton', font=('微软雅黑', 10), padding=8, width=20, anchor='w')
    style.map('Nav.TButton',
              background=[('active', '#e5e5e5'), ('pressed', '#d0d0d0')])
    style.configure('Toggle.TButton', font=('微软雅黑', 10), padding=5, width=3)
    style.map('Toggle.TButton',
              background=[('active', '#e5e5e5')])
    style.configure('TButton', font=('微软雅黑', 9), padding=5)
    style.map('TButton',
              background=[('active', '#e6e6e6')])
    style.configure('TLabel', background='#ffffff', font=('微软雅黑', 9))
    style.configure('Header.TLabel', font=('微软雅黑', 11, 'bold'))
    style.configure('TCombobox', padding=4)
    style.configure('TRadiobutton', background='#ffffff', font=('微软雅黑', 9))

    return style

# ==================== 编码转换页面 ====================
class EncodingPage(ttk.Frame):
    def __init__(self, parent, status_callback):
        super().__init__(parent, style='TFrame')
        self.status_callback = status_callback
        self.encoding_map = {
            "Base16": "base16",
            "Base32": "base32",
            "Base64 (标准)": "base64",
            "Base64 URL安全": "base64url",
            "Base85 (RFC 1924)": "base85"
        }
        self.output_formats = [
            "UTF-8 文本",
            "ASCII 文本",
            "二进制 (空格分隔)",
            "十六进制 (空格分隔)"
        ]
        self.output_format_map = {
            "UTF-8 文本": "utf8",
            "ASCII 文本": "ascii",
            "二进制 (空格分隔)": "bin",
            "十六进制 (空格分隔)": "hex"
        }
        self.create_widgets()
    def create_widgets(self):
        card = ttk.Frame(self, style='Card.TFrame', padding=15)
        card.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        title = ttk.Label(card, text="编码转换", style='Header.TLabel')
        title.grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0,10))
        ttk.Label(card, text="编码方案:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.encoding_var = tk.StringVar()
        encoding_combo = ttk.Combobox(card, textvariable=self.encoding_var,
                                      values=list(self.encoding_map.keys()),
                                      state="readonly", width=25)
        encoding_combo.grid(row=1, column=1, sticky=tk.W, pady=5, padx=(5,0))
        encoding_combo.current(0)
        ttk.Label(card, text="操作:").grid(row=2, column=0, sticky=tk.W, pady=5)
        op_frame = ttk.Frame(card, style='TFrame')
        op_frame.grid(row=2, column=1, sticky=tk.W, pady=5, padx=(5,0))
        self.operation_var = tk.StringVar(value="encode")
        ttk.Radiobutton(op_frame, text="编码", variable=self.operation_var,
                        value="encode", command=self.toggle_output_format).pack(side=tk.LEFT, padx=(0,10))
        ttk.Radiobutton(op_frame, text="解码", variable=self.operation_var,
                        value="decode", command=self.toggle_output_format).pack(side=tk.LEFT)
        input_card = ttk.Frame(card, style='Card.TFrame', padding=10)
        input_card.grid(row=3, column=0, columnspan=2, sticky=tk.EW, pady=10)
        ttk.Label(input_card, text="输入", font=('微软雅黑', 10, 'bold')).pack(anchor=tk.W)
        self.input_text = scrolledtext.ScrolledText(input_card, wrap=tk.WORD, height=8,
                                                     font=('Consolas', 10), relief='solid', borderwidth=1)
        self.input_text.pack(fill=tk.BOTH, expand=True, pady=(5,0))
        fmt_frame = ttk.Frame(card, style='TFrame')
        fmt_frame.grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=5)
        ttk.Label(fmt_frame, text="输出格式:").pack(side=tk.LEFT)
        self.output_format_var = tk.StringVar()
        output_combo = ttk.Combobox(fmt_frame, textvariable=self.output_format_var,
                                    values=self.output_formats, state="readonly", width=25)
        output_combo.pack(side=tk.LEFT, padx=(10,0))
        output_combo.current(0)
        self.output_format_frame = fmt_frame
        btn_frame = ttk.Frame(card, style='TFrame')
        btn_frame.grid(row=5, column=0, columnspan=2, pady=10)
        ttk.Button(btn_frame, text="执行转换", command=self.convert).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="清空输入", command=self.clear_input).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="清空输出", command=self.clear_output).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="复制结果", command=self.copy_output).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="交换输入输出", command=self.swap).pack(side=tk.LEFT, padx=5)
        output_card = ttk.Frame(card, style='Card.TFrame', padding=10)
        output_card.grid(row=6, column=0, columnspan=2, sticky=tk.EW, pady=10)
        ttk.Label(output_card, text="输出", font=('微软雅黑', 10, 'bold')).pack(anchor=tk.W)
        self.output_text = scrolledtext.ScrolledText(output_card, wrap=tk.WORD, height=6,
                                                      font=('Consolas', 10), relief='solid', borderwidth=1,
                                                      state=tk.DISABLED)
        self.output_text.pack(fill=tk.BOTH, expand=True, pady=(5,0))
        card.columnconfigure(1, weight=1)
        self.toggle_output_format()
    def toggle_output_format(self):
        if self.operation_var.get() == "decode":
            self.output_format_frame.grid()
        else:
            self.output_format_frame.grid_remove()
    def convert(self):
        input_data = self.input_text.get("1.0", tk.END).strip()
        if not input_data:
            messagebox.showwarning("警告", "请输入待处理的内容")
            return
        encoding_name = self.encoding_var.get()
        if not encoding_name:
            messagebox.showerror("错误", "请选择编码方案")
            return
        encoding = self.encoding_map[encoding_name]
        operation = self.operation_var.get()
        try:
            if operation == "encode":
                result = self.encode(encoding, input_data)
                self.set_output(result)
                self.status_callback("编码成功")
            else:
                output_format_display = self.output_format_var.get()
                output_format = self.output_format_map.get(output_format_display, "utf8")
                result = self.decode(encoding, input_data, output_format)
                self.set_output(result)
                self.status_callback("解码成功")
        except Exception as e:
            messagebox.showerror("转换失败", str(e))
            self.status_callback("转换失败")
    def encode(self, encoding, text):
        data = text.encode('utf-8')
        if encoding == 'base16':
            return base64.b16encode(data).decode('ascii')
        elif encoding == 'base32':
            return base64.b32encode(data).decode('ascii')
        elif encoding == 'base64':
            return base64.b64encode(data).decode('ascii')
        elif encoding == 'base64url':
            return base64.urlsafe_b64encode(data).decode('ascii')
        elif encoding == 'base85':
            return base64.b85encode(data).decode('ascii')
        else:
            raise ValueError("不支持的编码类型")
    def decode(self, encoding, encoded_str, output_format):
        encoded_str = encoded_str.strip()
        data = encoded_str.encode('ascii')
        if encoding == 'base16':
            decoded = base64.b16decode(data, casefold=False)
        elif encoding == 'base32':
            decoded = base64.b32decode(data, casefold=True)
        elif encoding == 'base64':
            decoded = base64.b64decode(data, validate=True)
        elif encoding == 'base64url':
            decoded = base64.urlsafe_b64decode(data)
        elif encoding == 'base85':
            decoded = base64.b85decode(data)
        else:
            raise ValueError("不支持的编码类型")
        if output_format == 'utf8':
            return decoded.decode('utf-8')
        elif output_format == 'ascii':
            return decoded.decode('ascii')
        elif output_format == 'bin':
            return ' '.join(format(b, '08b') for b in decoded)
        elif output_format == 'hex':
            return ' '.join(f'{b:02x}' for b in decoded)
        else:
            return decoded.decode('utf-8')
    def set_output(self, text):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert("1.0", text)
        self.output_text.config(state=tk.DISABLED)
    def clear_input(self):
        self.input_text.delete("1.0", tk.END)
        self.status_callback("输入已清空")
    def clear_output(self):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.status_callback("输出已清空")
    def copy_output(self):
        output = self.output_text.get("1.0", tk.END).strip()
        if output:
            self.clipboard_clear()
            self.clipboard_append(output)
            self.status_callback("结果已复制到剪贴板")
        else:
            messagebox.showinfo("提示", "没有输出内容可复制")
    def swap(self):
        output = self.output_text.get("1.0", tk.END).strip()
        if output:
            self.input_text.delete("1.0", tk.END)
            self.input_text.insert("1.0", output)
            self.clear_output()
            self.status_callback("已交换")

# ==================== 二进制翻译页面 ====================
class BinaryPage(ttk.Frame):
    def __init__(self, parent, status_callback):
        super().__init__(parent, style='TFrame')
        self.status_callback = status_callback
        self.create_widgets()
    def create_widgets(self):
        card = ttk.Frame(self, style='Card.TFrame', padding=15)
        card.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        title = ttk.Label(card, text="二进制翻译", style='Header.TLabel')
        title.grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0,10))
        ttk.Label(card, text="转换方向:").grid(row=1, column=0, sticky=tk.W, pady=5)
        dir_frame = ttk.Frame(card, style='TFrame')
        dir_frame.grid(row=1, column=1, sticky=tk.W, pady=5, padx=(5,0))
        self.direction_var = tk.StringVar(value="text2bin")
        ttk.Radiobutton(dir_frame, text="文本 → 二进制", variable=self.direction_var,
                        value="text2bin").pack(side=tk.LEFT, padx=(0,10))
        ttk.Radiobutton(dir_frame, text="二进制 → 文本", variable=self.direction_var,
                        value="bin2text").pack(side=tk.LEFT)
        input_card = ttk.Frame(card, style='Card.TFrame', padding=10)
        input_card.grid(row=2, column=0, columnspan=2, sticky=tk.EW, pady=10)
        ttk.Label(input_card, text="输入", font=('微软雅黑', 10, 'bold')).pack(anchor=tk.W)
        self.input_text = scrolledtext.ScrolledText(input_card, wrap=tk.WORD, height=8,
                                                     font=('Consolas', 10), relief='solid', borderwidth=1)
        self.input_text.pack(fill=tk.BOTH, expand=True, pady=(5,0))
        btn_frame = ttk.Frame(card, style='TFrame')
        btn_frame.grid(row=3, column=0, columnspan=2, pady=10)
        ttk.Button(btn_frame, text="转换", command=self.convert).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="清空输入", command=lambda: self.input_text.delete("1.0", tk.END)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="清空输出", command=self.clear_output).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="复制结果", command=self.copy_output).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="交换输入输出", command=self.swap).pack(side=tk.LEFT, padx=5)
        output_card = ttk.Frame(card, style='Card.TFrame', padding=10)
        output_card.grid(row=4, column=0, columnspan=2, sticky=tk.EW, pady=10)
        ttk.Label(output_card, text="输出", font=('微软雅黑', 10, 'bold')).pack(anchor=tk.W)
        self.output_text = scrolledtext.ScrolledText(output_card, wrap=tk.WORD, height=6,
                                                      font=('Consolas', 10), relief='solid', borderwidth=1,
                                                      state=tk.DISABLED)
        self.output_text.pack(fill=tk.BOTH, expand=True, pady=(5,0))
        card.columnconfigure(1, weight=1)
    def convert(self):
        input_data = self.input_text.get("1.0", tk.END).strip()
        if not input_data:
            messagebox.showwarning("警告", "请输入内容")
            return
        direction = self.direction_var.get()
        try:
            if direction == "text2bin":
                bytes_data = input_data.encode('utf-8')
                result = ' '.join(format(b, '08b') for b in bytes_data)
            else:
                bin_str = re.sub(r'\s', '', input_data)
                if not bin_str:
                    raise ValueError("二进制字符串为空")
                if len(bin_str) % 8 != 0:
                    raise ValueError("二进制位数不是8的倍数")
                bytes_data = bytearray()
                for i in range(0, len(bin_str), 8):
                    byte = bin_str[i:i+8]
                    if not all(c in '01' for c in byte):
                        raise ValueError(f"非法字符: {byte}")
                    bytes_data.append(int(byte, 2))
                result = bytes_data.decode('utf-8')
            self.set_output(result)
            self.status_callback("转换成功")
        except Exception as e:
            messagebox.showerror("转换失败", str(e))
            self.status_callback("转换失败")
    def set_output(self, text):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert("1.0", text)
        self.output_text.config(state=tk.DISABLED)
    def clear_output(self):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.status_callback("输出已清空")
    def copy_output(self):
        output = self.output_text.get("1.0", tk.END).strip()
        if output:
            self.clipboard_clear()
            self.clipboard_append(output)
            self.status_callback("已复制")
        else:
            messagebox.showinfo("提示", "没有输出内容")
    def swap(self):
        output = self.output_text.get("1.0", tk.END).strip()
        if output:
            self.input_text.delete("1.0", tk.END)
            self.input_text.insert("1.0", output)
            self.clear_output()
            self.status_callback("已交换")

# ==================== 十六进制翻译页面 ====================
class HexPage(ttk.Frame):
    def __init__(self, parent, status_callback):
        super().__init__(parent, style='TFrame')
        self.status_callback = status_callback
        self.create_widgets()
    def create_widgets(self):
        card = ttk.Frame(self, style='Card.TFrame', padding=15)
        card.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        title = ttk.Label(card, text="十六进制翻译", style='Header.TLabel')
        title.grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0,10))
        ttk.Label(card, text="转换方向:").grid(row=1, column=0, sticky=tk.W, pady=5)
        dir_frame = ttk.Frame(card, style='TFrame')
        dir_frame.grid(row=1, column=1, sticky=tk.W, pady=5, padx=(5,0))
        self.direction_var = tk.StringVar(value="text2hex")
        ttk.Radiobutton(dir_frame, text="文本 → 十六进制", variable=self.direction_var,
                        value="text2hex").pack(side=tk.LEFT, padx=(0,10))
        ttk.Radiobutton(dir_frame, text="十六进制 → 文本", variable=self.direction_var,
                        value="hex2text").pack(side=tk.LEFT)
        input_card = ttk.Frame(card, style='Card.TFrame', padding=10)
        input_card.grid(row=2, column=0, columnspan=2, sticky=tk.EW, pady=10)
        ttk.Label(input_card, text="输入", font=('微软雅黑', 10, 'bold')).pack(anchor=tk.W)
        self.input_text = scrolledtext.ScrolledText(input_card, wrap=tk.WORD, height=8,
                                                     font=('Consolas', 10), relief='solid', borderwidth=1)
        self.input_text.pack(fill=tk.BOTH, expand=True, pady=(5,0))
        btn_frame = ttk.Frame(card, style='TFrame')
        btn_frame.grid(row=3, column=0, columnspan=2, pady=10)
        ttk.Button(btn_frame, text="转换", command=self.convert).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="清空输入", command=lambda: self.input_text.delete("1.0", tk.END)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="清空输出", command=self.clear_output).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="复制结果", command=self.copy_output).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="交换输入输出", command=self.swap).pack(side=tk.LEFT, padx=5)
        output_card = ttk.Frame(card, style='Card.TFrame', padding=10)
        output_card.grid(row=4, column=0, columnspan=2, sticky=tk.EW, pady=10)
        ttk.Label(output_card, text="输出", font=('微软雅黑', 10, 'bold')).pack(anchor=tk.W)
        self.output_text = scrolledtext.ScrolledText(output_card, wrap=tk.WORD, height=6,
                                                      font=('Consolas', 10), relief='solid', borderwidth=1,
                                                      state=tk.DISABLED)
        self.output_text.pack(fill=tk.BOTH, expand=True, pady=(5,0))
        card.columnconfigure(1, weight=1)
    def convert(self):
        input_data = self.input_text.get("1.0", tk.END).strip()
        if not input_data:
            messagebox.showwarning("警告", "请输入内容")
            return
        direction = self.direction_var.get()
        try:
            if direction == "text2hex":
                bytes_data = input_data.encode('utf-8')
                result = ' '.join(f'{b:02x}' for b in bytes_data)
            else:
                hex_str = re.sub(r'\s', '', input_data)
                if not hex_str:
                    raise ValueError("十六进制字符串为空")
                if len(hex_str) % 2 != 0:
                    raise ValueError("十六进制位数不是2的倍数")
                if not re.match(r'^[0-9a-fA-F]+$', hex_str):
                    raise ValueError("包含非法字符")
                bytes_data = bytearray()
                for i in range(0, len(hex_str), 2):
                    byte = hex_str[i:i+2]
                    bytes_data.append(int(byte, 16))
                result = bytes_data.decode('utf-8')
            self.set_output(result)
            self.status_callback("转换成功")
        except Exception as e:
            messagebox.showerror("转换失败", str(e))
            self.status_callback("转换失败")
    def set_output(self, text):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert("1.0", text)
        self.output_text.config(state=tk.DISABLED)
    def clear_output(self):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.status_callback("输出已清空")
    def copy_output(self):
        output = self.output_text.get("1.0", tk.END).strip()
        if output:
            self.clipboard_clear()
            self.clipboard_append(output)
            self.status_callback("已复制")
        else:
            messagebox.showinfo("提示", "没有输出内容")
    def swap(self):
        output = self.output_text.get("1.0", tk.END).strip()
        if output:
            self.input_text.delete("1.0", tk.END)
            self.input_text.insert("1.0", output)
            self.clear_output()
            self.status_callback("已交换")

# ==================== 主应用程序====================
class Application(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, style='TFrame')
        self.master = master
        self.pack(fill=tk.BOTH, expand=True)
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        status_bar = ttk.Label(master, textvariable=self.status_var, relief=tk.SUNKEN,
                                anchor=tk.W, font=('微软雅黑', 9))
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.left_frame = ttk.Frame(self, style='Sidebar.TFrame', width=200)
        self.left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(5,0), pady=5)
        self.left_frame.pack_propagate(False)
        self.right_frame = ttk.Frame(self, style='TFrame')
        self.right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,5), pady=5)
        self.create_sidebar()
        self.pages = {}
        self.pages['encoding'] = EncodingPage(self.right_frame, self.set_status)
        self.pages['binary'] = BinaryPage(self.right_frame, self.set_status)
        self.pages['hex'] = HexPage(self.right_frame, self.set_status)
        for page in self.pages.values():
            page.grid(row=0, column=0, sticky='nsew')
        self.right_frame.grid_rowconfigure(0, weight=1)
        self.right_frame.grid_columnconfigure(0, weight=1)
        self.show_page('encoding')
        self.expanded = True
    def create_sidebar(self):
        toggle_frame = ttk.Frame(self.left_frame, style='Sidebar.TFrame')
        toggle_frame.pack(fill=tk.X, pady=(10,5), padx=5)
        self.toggle_btn = ttk.Button(toggle_frame, text="◀", style='Toggle.TButton',
                                      command=self.toggle_sidebar)
        self.toggle_btn.pack(side=tk.LEFT, padx=2)
        self.nav_title = ttk.Label(self.left_frame, text="功能导航", font=('微软雅黑', 12, 'bold'),
                                    background='#f0f0f0', foreground='#333333')
        self.nav_title.pack(pady=(5,10), padx=10, anchor=tk.W)
        self.nav_buttons = []
        self.nav_button_info = [
            ('🔤', '🔤 编码转换', lambda: self.show_page('encoding')),
            ('🔢', '🔢 二进制翻译', lambda: self.show_page('binary')),
            ('🔣', '🔣 十六进制翻译', lambda: self.show_page('hex'))
        ]
        for icon, full_text, cmd in self.nav_button_info:
            btn = ttk.Button(self.left_frame, text=full_text, style='Nav.TButton', command=cmd)
            btn.pack(pady=2, padx=10, fill=tk.X)
            self.nav_buttons.append((btn, icon, full_text))
        ttk.Frame(self.left_frame, style='Sidebar.TFrame').pack(expand=True)
    def toggle_sidebar(self):
        """切换侧边栏展开/折叠状态"""
        if self.expanded:
            new_width = 60
            self.toggle_btn.config(text="☰")
            self.nav_title.pack_forget()
            for btn, icon, _ in self.nav_buttons:
                btn.config(text=icon, width=3)
        else:
            new_width = 200
            self.toggle_btn.config(text="◀")
            self.nav_title.pack(pady=(5,10), padx=10, anchor=tk.W)
            for btn, _, full_text in self.nav_buttons:
                btn.config(text=full_text, width=20)
        self.left_frame.config(width=new_width)
        self.expanded = not self.expanded
    def show_page(self, page_key):
        """切换显示指定页面"""
        for key, page in self.pages.items():
            if key == page_key:
                page.grid()
            else:
                page.grid_remove()
        self.set_status(f"已切换到 {self.get_page_name(page_key)}")
    def get_page_name(self, key):
        names = {'encoding': '编码转换', 'binary': '二进制翻译', 'hex': '十六进制翻译'}
        return names.get(key, key)
    def set_status(self, message):
        self.status_var.set(message)
def main():
    root = tk.Tk()
    root.title("Base编码转换工具v1.2.2")
    root.geometry("1000x700")
    root.minsize(850, 600)
    setup_style()
    try:
        root.iconbitmap(default='icon.ico')
    except:
        pass
    app = Application(root)
    root.mainloop()
if __name__ == "__main__":
    main()