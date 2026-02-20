import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import base64

class EncoderDecoderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("保密级编码转换工具")
        self.root.geometry("700x600")
        self.root.resizable(True, True)

     
        self.encoding_map = {
            "Base16": "base16",
            "Base32": "base32",
            "Base64 (标准)": "base64",
            "Base64 URL": "base64url",
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
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

       
        ttk.Label(main_frame, text="编码方案:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.encoding_var = tk.StringVar()
        encoding_combo = ttk.Combobox(main_frame, textvariable=self.encoding_var,
                                      values=list(self.encoding_map.keys()),
                                      state="readonly", width=20)
        encoding_combo.grid(row=0, column=1, sticky=tk.W, pady=5)
        encoding_combo.current(0)


        ttk.Label(main_frame, text="操作:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.operation_var = tk.StringVar(value="encode")
        encode_radio = ttk.Radiobutton(main_frame, text="编码", variable=self.operation_var,
                                       value="encode", command=self.toggle_output_format)
        decode_radio = ttk.Radiobutton(main_frame, text="解码", variable=self.operation_var,
                                       value="decode", command=self.toggle_output_format)
        encode_radio.grid(row=1, column=1, sticky=tk.W, padx=(0,10))
        decode_radio.grid(row=1, column=1, sticky=tk.E)

        # 输入区域
        ttk.Label(main_frame, text="输入:").grid(row=2, column=0, sticky=tk.NW, pady=5)
        self.input_text = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, width=70, height=10)
        self.input_text.grid(row=2, column=1, columnspan=2, sticky=tk.W+tk.E, pady=5)

       
        self.output_format_frame = ttk.Frame(main_frame)
        self.output_format_frame.grid(row=3, column=1, sticky=tk.W, pady=5)
        ttk.Label(self.output_format_frame, text="输出格式:").pack(side=tk.LEFT, padx=(0,10))
        self.output_format_var = tk.StringVar()
        output_combo = ttk.Combobox(self.output_format_frame,
                                    textvariable=self.output_format_var,
                                    values=self.output_formats,
                                    state="readonly", width=20)
        output_combo.pack(side=tk.LEFT)
        output_combo.current(0)  # 默认 UTF-8 self.toggle_output_format()

        # 按钮区域
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=1, pady=10)

        ttk.Button(button_frame, text="执行转换", command=self.convert).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="清空输入", command=self.clear_input).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="清空输出", command=self.clear_output).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="复制结果", command=self.copy_output).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="交换输入输出", command=self.swap).pack(side=tk.LEFT, padx=5)

        # 输出区域
        ttk.Label(main_frame, text="输出:").grid(row=5, column=0, sticky=tk.NW, pady=5)
        self.output_text = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, width=70, height=10,
                                                      state=tk.DISABLED)
        self.output_text.grid(row=5, column=1, columnspan=2, sticky=tk.W+tk.E, pady=5)

        # 状态栏
        self.status_var = tk.StringVar()
        self.status_var.set("就绪 源码请访问GitHub")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        main_frame.columnconfigure(1, weight=1)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

    def toggle_output_format(self):
        """根据操作显示或隐藏输出格式选择"""
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
                self.status_var.set("编码成功")
            else:
                output_format_display = self.output_format_var.get()
                output_format = self.output_format_map.get(output_format_display, "utf8")
                result = self.decode(encoding, input_data, output_format)
                self.set_output(result)
                self.status_var.set("解码成功")
        except Exception as e:
            messagebox.showerror("转换失败", str(e))
            self.status_var.set("转换失败")

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
        data = encoded_str.encode('ascii')  # 密文必须是ASCII
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

        # 根据输出格式转换
        if output_format == 'utf8':
            return decoded.decode('utf-8')
        elif output_format == 'ascii':
            return decoded.decode('ascii')
        elif output_format == 'bin':
            # 二进制：每字节8位，空格分隔
            return ' '.join(format(b, '08b') for b in decoded)
        elif output_format == 'hex':
            # 十六进制：每字节两位，空格分隔
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
        self.status_var.set("输入已清空")

    def clear_output(self):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.status_var.set("输出已清空")

    def copy_output(self):
        output = self.output_text.get("1.0", tk.END).strip()
        if output:
            self.root.clipboard_clear()
            self.root.clipboard_append(output)
            self.status_var.set("结果已复制到剪贴板")
        else:
            messagebox.showinfo("提示", "没有输出内容可复制")

    def swap(self):
        output = self.output_text.get("1.0", tk.END).strip()
        if output:
            self.input_text.delete("1.0", tk.END)
            self.input_text.insert("1.0", output)
            self.clear_output()
            self.status_var.set("已交换")

def main():
    root = tk.Tk()
    app = EncoderDecoderApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()