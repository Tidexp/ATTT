import os
import tempfile
import time
import tkinter as tk
from tkinter import filedialog, messagebox

from aes_core import AES_Scratch
from aes_modes import (
    BLOCK_SIZE,
    build_header,
    ctr_crypt_stream,
    decrypt_stream_cbc,
    decrypt_stream_ecb,
    encrypt_stream_cbc,
    encrypt_stream_ecb,
    gcm_decrypt_stream_to_temp,
    gcm_encrypt_stream,
    parse_header_from_file,
    parse_iv_hex,
    parse_nonce12_hex,
    random_nonce12,
    random_iv as random_iv_bytes,
)


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Phần mềm Mã hóa AES - Nhóm 15")
        self.root.geometry("520x520")

        self.aes = AES_Scratch()
        self.key = b"NHOM15_BMTT_2026"  # 16 bytes (AES-128). Có thể đổi sang 24/32 bytes cho AES-192/256.

        self.mode_var = tk.StringVar(value="ECB")
        self.key_format_var = tk.StringVar(value="text")
        self.iv_hex_var = tk.StringVar(value="")
        self.nonce_hex_var = tk.StringVar(value="")
        self.key_text_var = tk.StringVar(value="")

        tk.Label(root, text="MÃ HÓA AES FILE (SCRATCH)", font=("Arial", 12, "bold")).pack(pady=10)

        mode_frame = tk.Frame(root)
        mode_frame.pack(pady=5)
        tk.Label(mode_frame, text="Chế độ:").pack(side=tk.LEFT, padx=(0, 6))
        tk.OptionMenu(mode_frame, self.mode_var, "ECB", "CBC", "CTR", "GCM").pack(side=tk.LEFT)

        key_frame = tk.LabelFrame(root, text="Nhập Key (AES-128/192/256 = 16/24/32 bytes)")
        key_frame.pack(fill="x", padx=10, pady=8)

        fmt_frame = tk.Frame(key_frame)
        fmt_frame.pack(anchor="w", padx=10, pady=(6, 2))
        tk.Radiobutton(
            fmt_frame,
            text="Text (UTF-8; 16/24/32 ký tự ASCII là dễ nhất)",
            variable=self.key_format_var,
            value="text",
        ).pack(anchor="w")
        tk.Radiobutton(
            fmt_frame,
            text="Hex (32/48/64 ký tự hex = 16/24/32 bytes)",
            variable=self.key_format_var,
            value="hex",
        ).pack(anchor="w")

        entry_frame = tk.Frame(key_frame)
        entry_frame.pack(fill="x", padx=10, pady=(2, 8))
        tk.Label(entry_frame, text="Key:").pack(side=tk.LEFT)
        self.key_entry = tk.Entry(entry_frame, textvariable=self.key_text_var)
        self.key_entry.pack(side=tk.LEFT, fill="x", expand=True, padx=6)

        key_status_frame = tk.Frame(key_frame)
        key_status_frame.pack(fill="x", padx=10, pady=(0, 6))
        self.key_len_label = tk.Label(key_status_frame, text="", fg="#555", anchor="w", justify="left")
        self.key_len_label.pack(fill="x")

        self.key_text_var.set(self.key.decode("utf-8", errors="ignore"))
        tk.Button(entry_frame, text="Áp dụng", command=self.apply_key).pack(side=tk.LEFT)

        self.iv_frame = tk.LabelFrame(root, text="IV (CBC)")
        self.iv_help = tk.Label(
            self.iv_frame,
            text="IV hex (32 ký tự). Để trống = tự tạo ngẫu nhiên khi mã hoá:",
        )
        self.iv_help.pack(anchor="w", padx=10, pady=(6, 2))
        iv_entry_frame = tk.Frame(self.iv_frame)
        iv_entry_frame.pack(fill="x", padx=10, pady=(2, 8))
        self.iv_entry = tk.Entry(iv_entry_frame, textvariable=self.iv_hex_var)
        self.iv_entry.pack(side=tk.LEFT, fill="x", expand=True)
        tk.Button(iv_entry_frame, text="Random IV", command=self.random_iv).pack(side=tk.LEFT, padx=6)

        self.nonce_frame = tk.LabelFrame(root, text="Nonce (CTR/GCM)")
        self.nonce_help = tk.Label(
            self.nonce_frame,
            text="Nonce hex (24 ký tự = 12 bytes). Để trống = tự tạo ngẫu nhiên khi mã hoá:",
        )
        self.nonce_help.pack(anchor="w", padx=10, pady=(6, 2))
        nonce_entry_frame = tk.Frame(self.nonce_frame)
        nonce_entry_frame.pack(fill="x", padx=10, pady=(2, 8))
        self.nonce_entry = tk.Entry(nonce_entry_frame, textvariable=self.nonce_hex_var)
        self.nonce_entry.pack(side=tk.LEFT, fill="x", expand=True)
        tk.Button(nonce_entry_frame, text="Random Nonce", command=self.random_nonce).pack(side=tk.LEFT, padx=6)

        self.btn_encrypt = tk.Button(root, text="Mã hóa File", command=self.run_encrypt, width=20, bg="#ffcccb")
        self.btn_encrypt.pack(pady=5)

        self.btn_decrypt = tk.Button(root, text="Giải mã File", command=self.run_decrypt, width=20, bg="#ccffcc")
        self.btn_decrypt.pack(pady=5)

        self.log = tk.Text(root, height=10, width=50)
        self.log.pack(pady=10)

        self.mode_var.trace_add("write", lambda *_: self.update_mode_ui())
        self.key_text_var.trace_add("write", lambda *_: self.update_key_length_label())
        self.key_format_var.trace_add("write", lambda *_: self.update_key_length_label())
        self.update_mode_ui()
        self.update_key_length_label()

    def update_key_length_label(self):
        raw = self.key_text_var.get() or ""
        char_count = len(raw)
        ok_color = "#2e7d32"  # green
        bad_color = "#c62828"  # red
        neutral_color = "#555"

        if self.key_format_var.get() == "hex":
            cleaned = raw.replace(" ", "")
            is_even = (len(cleaned) % 2) == 0
            is_hex = True
            if cleaned:
                try:
                    bytes.fromhex(cleaned)
                except ValueError:
                    is_hex = False
            byte_count = len(cleaned) // 2
            is_valid = is_hex and is_even and (byte_count in (16, 24, 32))

            if not cleaned:
                self.key_len_label.config(
                    text="0 ký tự (0 bytes) — cần 32/48/64 ký tự hex (= 16/24/32 bytes)",
                    fg=neutral_color,
                )
                return

            self.key_len_label.config(
                text=f"{char_count} ký tự ({byte_count} bytes) — cần 32/48/64 ký tự hex",
                fg=(ok_color if is_valid else bad_color),
            )
        else:
            byte_count = len(raw.encode("utf-8"))
            is_valid = byte_count in (16, 24, 32)

            if not raw:
                self.key_len_label.config(
                    text="0 ký tự (0 bytes) — cần 16/24/32 bytes (AES-128/192/256)",
                    fg=neutral_color,
                )
                return

            self.key_len_label.config(
                text=f"{char_count} ký tự ({byte_count} bytes UTF-8) — cần 16/24/32 bytes",
                fg=(ok_color if is_valid else bad_color),
            )

    def write_log(self, msg: str):
        self.log.insert(tk.END, msg + "\n")
        self.log.see(tk.END)

    def apply_key(self):
        raw = self.key_entry.get().strip()
        if not raw:
            messagebox.showerror("Lỗi", "Vui lòng nhập key.")
            return

        try:
            if self.key_format_var.get() == "hex":
                key_bytes = bytes.fromhex(raw.replace(" ", ""))
            else:
                key_bytes = raw.encode("utf-8")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Key không hợp lệ: {e}")
            return

        if len(key_bytes) not in (16, 24, 32):
            messagebox.showerror(
                "Lỗi",
                f"Key phải dài 16/24/32 bytes (AES-128/192/256). Hiện tại: {len(key_bytes)} bytes.",
            )
            return

        self.key = key_bytes
        bits = len(self.key) * 8
        self.write_log(f"[KEY] Đã cập nhật key ({len(self.key)} bytes = AES-{bits}).")

    def random_iv(self):
        iv = random_iv_bytes()
        self.iv_hex_var.set(iv.hex())
        self.write_log("[IV] Đã tạo IV ngẫu nhiên (hex).")

    def random_nonce(self):
        nonce = random_nonce12()
        self.nonce_hex_var.set(nonce.hex())
        self.write_log("[NONCE] Đã tạo nonce ngẫu nhiên (hex).")

    def update_mode_ui(self):
        mode = self.mode_var.get().upper()
        # Ẩn tất cả cài đặt mode trước
        self.iv_frame.pack_forget()
        self.nonce_frame.pack_forget()

        if mode == "CBC":
            self.iv_frame.pack(fill="x", padx=10, pady=8)
        elif mode in ("CTR", "GCM"):
            self.nonce_frame.pack(fill="x", padx=10, pady=8)

    def run_encrypt(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        expanded_key = self.aes.expand_key(self.key)
        mode = self.mode_var.get().upper()

        start = time.perf_counter()
        try:
            out_path = file_path + ".enc"
            with open(file_path, "rb") as infile, open(out_path, "wb") as outfile:
                if mode == "CBC":
                    iv = parse_iv_hex(self.iv_hex_var.get()) or random_iv_bytes()
                    outfile.write(build_header("CBC", iv))
                    encrypt_stream_cbc(self.aes, infile, outfile, expanded_key, iv)
                elif mode == "CTR":
                    nonce = parse_nonce12_hex(self.nonce_hex_var.get()) or random_nonce12()
                    outfile.write(build_header("CTR", nonce))
                    ctr_crypt_stream(self.aes, infile, outfile, expanded_key, nonce, initial_counter=1)
                elif mode == "GCM":
                    nonce = parse_nonce12_hex(self.nonce_hex_var.get()) or random_nonce12()
                    # header: magic + nonce + placeholder tag
                    outfile.write(b"GCM1" + nonce + (b"\x00" * 16))
                    tag = gcm_encrypt_stream(self.aes, infile, outfile, expanded_key, nonce, aad=b"")
                    # patch tag back into header
                    outfile.flush()
                    outfile.seek(4 + 12)
                    outfile.write(tag)
                else:
                    outfile.write(build_header("ECB"))
                    encrypt_stream_ecb(self.aes, infile, outfile, expanded_key)
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))
            return
        end = time.perf_counter()

        self.write_log("--- MÃ HÓA ---")
        self.write_log(f"File: {os.path.basename(file_path)}")
        self.write_log(f"File xuất: {os.path.basename(out_path)}")
        self.write_log(f"Mode: {mode}")
        self.write_log(f"Thời gian mã hóa: {end-start:.6f}s")
        messagebox.showinfo("Xong", f"Đã lưu file mã hóa: {os.path.basename(out_path)}")

    def run_decrypt(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        expanded_key = self.aes.expand_key(self.key)

        if file_path.lower().endswith(".enc"):
            out_path = file_path[:-4]
        else:
            out_path = file_path + ".dec"

        start = time.perf_counter()
        try:
            with open(file_path, "rb") as infile:
                mode, iv_or_nonce, tag = parse_header_from_file(infile)

                if mode.startswith("CBC"):
                    with open(out_path, "wb") as outfile:
                        decrypt_stream_cbc(self.aes, infile, outfile, expanded_key, iv_or_nonce)
                elif mode.startswith("ECB"):
                    with open(out_path, "wb") as outfile:
                        decrypt_stream_ecb(self.aes, infile, outfile, expanded_key)
                elif mode == "CTR":
                    with open(out_path, "wb") as outfile:
                        ctr_crypt_stream(self.aes, infile, outfile, expanded_key, iv_or_nonce, initial_counter=1)
                elif mode == "GCM":
                    # decrypt to temp first, verify tag, then move into place
                    tmp_fd, tmp_path = tempfile.mkstemp(prefix="aes_gcm_", suffix=".tmp")
                    try:
                        with os.fdopen(tmp_fd, "wb") as tmp_out:
                            ok = gcm_decrypt_stream_to_temp(
                                self.aes,
                                infile,
                                tmp_out,
                                expanded_key,
                                iv_or_nonce,
                                tag,
                                aad=b"",
                            )
                        if not ok:
                            raise ValueError("Sai tag GCM (dữ liệu bị sửa hoặc key/nonce không đúng).")
                        os.replace(tmp_path, out_path)
                    finally:
                        if os.path.exists(tmp_path):
                            try:
                                os.remove(tmp_path)
                            except OSError:
                                pass
                else:
                    raise ValueError(f"Mode không hỗ trợ: {mode}")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Giải mã thất bại: {e}")
            return
        end = time.perf_counter()

        self.write_log("--- GIẢI MÃ ---")
        self.write_log(f"File: {os.path.basename(file_path)}")
        self.write_log(f"File xuất: {os.path.basename(out_path)}")
        self.write_log(f"Mode: {mode}")
        self.write_log(f"Thời gian giải mã: {end-start:.6f}s")
        messagebox.showinfo("Xong", f"Đã lưu file giải mã: {os.path.basename(out_path)}")

