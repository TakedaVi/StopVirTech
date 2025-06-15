import os
import subprocess
import sys
from pathlib import Path
import threading
import shutil
from datetime import datetime
import hashlib
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import filedialog, messagebox, Toplevel
import requests

# Проверка и установка зависимостей с учетом внешнего окружения
try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, Toplevel
    import requests
    import reportlab
except ImportError:
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "reportlab", "--break-system-packages", "--no-cache-dir", "--retries", "0"])
        import tkinter as tk
        from tkinter import filedialog, messagebox, Toplevel
        import requests
        import reportlab
    except Exception as e:
        print(f"Не удалось установить зависимости. Установите вручную: pip install requests reportlab --break-system-packages --no-cache-dir. Ошибка: {e}")
        exit(1)

# Загрузка MD5 хешей из файла с автоматическим добавлением описаний
def load_md5_hashes(file_path):
    hashes = {}
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    hash_value = line.strip()
                    description = f"Неизвестный вредонос (хэш: {hash_value[:8]}...)"  # Автоматическое описание
                    hashes[hash_value] = description
    except Exception as e:
        print(f"Ошибка загрузки MD5 хешей: {e}")
    return hashes

# Расчет MD5 хэша файла
def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e:
        return None

# Проверка файла на угрозу (с кэшированием)
def check_file(file_path, md5_hashes, log, threats, cache):
    if file_path in cache:
        file_hash = cache[file_path]
    else:
        file_hash = calculate_md5(file_path)
        cache[file_path] = file_hash
    if file_hash and file_hash in md5_hashes:
        threat_info = f"ОБНАРУЖЕНА УГРОЗА: {file_path} [MD5: {file_hash}] - {md5_hashes[file_hash]}"
        with threading.Lock():
            threats.append((file_path, file_hash, md5_hashes[file_hash]))
            log.insert(tk.END, f"{threat_info}\n", "threat")
            log.see(tk.END)
    # Простая эвристика: подозрительные файлы больше 10MB
    elif file_path.stat().st_size > 10 * 1024 * 1024 and file_path.suffix.lower() not in ['.txt', '.log']:
        threat_info = f"ПОДОЗРИТЕЛЬНЫЙ ФАЙЛ: {file_path} (размер > 10MB)"
        with threading.Lock():
            threats.append((file_path, None, "Подозрительный файл (размер > 10MB)"))
            log.insert(tk.END, f"{threat_info}\n", "suspicious")
            log.see(tk.END)

# Основное окно приложения
class AntivirusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Антивирус в стиле Winamp")
        self.root.geometry("1024x800")
        self.root.resizable(False, False)
        self.root.configure(bg="#0e0e0e")

        self.bg_color = "#0e0e0e"
        self.fg_color = "#00ff00"
        self.button_bg = "#333333"
        self.button_fg = "#00ff00"
        self.font = ("Courier", 10, "bold")

        self.quarantine_dir = Path.home() / "Карантин"
        self.quarantine_dir.mkdir(exist_ok=True)

        self.md5_hashes = {}
        self.hash_file_path = None
        self.cache = {}

        self.threats = []
        self.is_scanning = False
        self.is_paused = False
        self.scan_thread = None
        self.total_files = 0
        self.scanned_files = 0

        self.create_gui()

    def create_gui(self):
        tk.Label(self.root, text="Stop_Virus_Tech", font=("Courier", 14, "bold"), bg=self.bg_color, fg="#ff4d00").pack(pady=10)
        self.add_hash_button = tk.Button(self.root, text="Добавить файл с хешами", command=self.add_hash_file, bg=self.button_bg, fg=self.button_fg, font=self.font, relief="raised", borderwidth=2)
        self.add_hash_button.pack(pady=5)
        self.hash_file_label = tk.Label(self.root, text="Файл хешей не выбран", bg=self.bg_color, fg=self.fg_color, font=self.font)
        self.hash_file_label.pack(pady=5)
        self.select_button = tk.Button(self.root, text="Выбрать папку", command=self.select_folder, bg=self.button_bg, fg=self.button_fg, font=self.font, relief="raised", borderwidth=2)
        self.select_button.pack(pady=5)
        self.folder_label = tk.Label(self.root, text="Папка не выбрана", bg=self.bg_color, fg=self.fg_color, font=self.font)
        self.folder_label.pack(pady=5)
        self.scan_button = tk.Button(self.root, text="Начать сканирование", command=self.start_scan, bg=self.button_bg, fg=self.button_fg, font=self.font, relief="raised", borderwidth=2)
        self.scan_button.pack(pady=5)
        self.pause_button = tk.Button(self.root, text="Пауза", command=self.pause_scan, bg=self.button_bg, fg=self.button_fg, font=self.font, relief="raised", borderwidth=2, state="disabled")
        self.pause_button.pack(pady=5)
        self.resume_button = tk.Button(self.root, text="Продолжить сканирование", command=self.resume_scan, bg=self.button_bg, fg=self.button_fg, font=self.font, relief="raised", borderwidth=2, state="disabled")
        self.resume_button.pack(pady=5)
        self.quarantine_button = tk.Button(self.root, text="Переместить в карантин", command=self.move_to_quarantine, bg=self.button_bg, fg=self.button_fg, font=self.font, relief="raised", borderwidth=2)
        self.quarantine_button.pack(pady=5)
        self.report_button = tk.Button(self.root, text="Сформировать отчет", command=self.generate_text_report, bg=self.button_bg, fg=self.button_fg, font=self.font, relief="raised", borderwidth=2, state="disabled")
        self.report_button.pack(pady=5)
        self.progress = tk.Label(self.root, text="Готов", bg=self.bg_color, fg=self.fg_color, font=self.font)
        self.progress.pack(pady=10)
        self.progress_bar = tk.Label(self.root, text="Прогресс: 0%", bg=self.bg_color, fg=self.fg_color, font=self.font)
        self.progress_bar.pack(pady=5)
        self.log = tk.Text(self.root, height=8, width=45, bg="#1a1a1a", fg=self.fg_color, font=self.font, relief="sunken", borderwidth=2)
        self.log.pack(pady=10)
        self.clear_button = tk.Button(self.root, text="Очистить лог", command=self.clear_log, bg=self.button_bg, fg=self.button_fg, font=self.font, relief="raised", borderwidth=2)
        self.clear_button.pack(pady=5)
        self.log.tag_configure("threat", foreground="#ff0000")
        self.log.tag_configure("suspicious", foreground="#ffaa00")

    def add_hash_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            self.hash_file_path = file_path
            self.md5_hashes = load_md5_hashes(file_path)
            self.hash_file_label.config(text=f"Выбран файл: {file_path}")
            self.log.insert(tk.END, f"Загружено {len(self.md5_hashes)} MD5 хешей.\n")

    def select_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder_label.config(text=f"Выбрано: {folder}")
            self.selected_folder = folder

    def start_scan(self):
        if not hasattr(self, "selected_folder") or not self.md5_hashes:
            messagebox.showwarning("Предупреждение", "Сначала выберите папку и загрузите файл с хешами!")
            return

        self.threats = []
        self.cache.clear()
        self.is_scanning = True
        self.is_paused = False
        self.scanned_files = 0
        self.total_files = sum(len(files) for _, _, files in os.walk(self.selected_folder))
        self.scan_button.config(state="disabled")
        self.pause_button.config(state="normal")
        self.resume_button.config(state="disabled")
        self.report_button.config(state="disabled")
        self.progress.config(text="Сканирование...")
        self.log.insert(tk.END, f"Начато сканирование папки: {self.selected_folder}\n")
        self.scan_thread = threading.Thread(target=self.scan_folder, daemon=True)
        self.scan_thread.start()

    def pause_scan(self):
        if self.is_scanning:
            self.is_paused = True
            self.progress.config(text="Сканирование на паузе")
            self.pause_button.config(state="disabled")
            self.resume_button.config(state="normal")

    def resume_scan(self):
        if self.is_paused:
            self.is_paused = False
            self.progress.config(text="Сканирование...")
            self.pause_button.config(state="normal")
            self.resume_button.config(state="disabled")
            self.root.event_generate("<<ResumeScan>>")

    def scan_folder(self):
        threats_found = 0
        file_paths = []
        for root, _, files in os.walk(self.selected_folder):
            for file in files:
                file_path = Path(root) / file
                try:
                    if file_path.stat().st_size > 0 and file_path.suffix.lower() not in ['.txt', '.log']:
                        file_paths.append(file_path)
                except Exception as e:
                    self.log.insert(tk.END, f"Ошибка доступа к {file_path}: {e}\n")
        self.total_files = len(file_paths)
        self.log.insert(tk.END, f"Обнаружено файлов для сканирования: {self.total_files}\n")
        
        with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
            futures = [executor.submit(check_file, file_path, self.md5_hashes, self.log, self.threats, self.cache) for file_path in file_paths]
            for future in futures:
                if not self.is_scanning:
                    break
                while self.is_paused:
                    self.root.wait_variable(self.root.register(lambda: None))
                    self.root.event_generate("<<ResumeScan>>")
                future.result()
                self.scanned_files += 1
                progress = (self.scanned_files / self.total_files) * 100 if self.total_files > 0 else 0
                self.root.after(0, lambda: self.progress_bar.config(text=f"Прогресс: {progress:.0f}%"))

        if self.is_scanning:
            threats_found = len(self.threats)
            self.progress.config(text=f"Сканирование завершено! Найдено угроз: {threats_found}")
            self.progress_bar.config(text="Прогресс: 100%")
            self.scan_button.config(state="normal")
            self.pause_button.config(state="disabled")
            self.resume_button.config(state="disabled")
            self.report_button.config(state="normal")
            self.log.insert(tk.END, f"Найдено угроз: {threats_found}\n")
            if threats_found > 0:
                self.show_threats_window(threats_found)
                self.generate_text_report(threats_found)
            self.log.insert(tk.END, f"Сканирование завершено.\n")
        self.is_scanning = False

    def show_threats_window(self, threats_found):
        threats_window = Toplevel(self.root)
        threats_window.title("Найденные угрозы")
        threats_window.geometry("800x900")
        threats_window.configure(bg=self.bg_color)
        tk.Label(threats_window, text=f"Найдено угроз: {threats_found}", font=("Courier", 12, "bold"), bg=self.bg_color, fg="#ff4d00").pack(pady=10)
        threats_text = tk.Text(threats_window, height=15, width=40, bg="#1a1a1a", fg=self.fg_color, font=self.font, relief="sunken", borderwidth=2)
        threats_text.pack(pady=10)
        for file_path, hash_value, description in self.threats:
            if hash_value:
                threats_text.insert(tk.END, f"{file_path} [MD5: {hash_value}] - {description}\n")
            else:
                threats_text.insert(tk.END, f"{file_path} - {description}\n")
        threats_text.config(state="disabled")

    def move_to_quarantine(self):
        if not self.threats:
            messagebox.showinfo("Информация", "Нет угроз для перемещения в карантин!")
            return
        for file_path, _, _ in self.threats:
            try:
                dest_path = self.quarantine_dir / file_path.name
                if not dest_path.parent.exists():
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(file_path), str(dest_path))
                self.log.insert(tk.END, f"Перемещено в карантин: {file_path}\n")
            except Exception as e:
                self.log.insert(tk.END, f"Ошибка перемещения {file_path} в карантин: {str(e)}\n")
        self.threats = []

    def generate_text_report(self, threats_found):
        if not self.threats:
            messagebox.showinfo("Информация", "Нет угроз для отчета!")
            return

        save_dir = filedialog.askdirectory(title="Выберите папку для сохранения отчета")
        if not save_dir:
            self.log.insert(tk.END, "Сохранение отменено.\n")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        txt_path = Path(save_dir) / f"отчет_угроз_{timestamp}.txt"
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write("Отчет по угрозам - Stop_VirTech\n")
            f.write(f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S CEST')}\n")
            f.write(f"Отсканированная папка: {self.selected_folder}\n")
            f.write(f"Найдено угроз: {threats_found}\n")
            f.write(f"Папка карантина: {self.quarantine_dir}\n")
            f.write("-" * 50 + "\n")
            for file_path, hash_value, description in self.threats:
                short_path = str(file_path).replace("\\", "/")[-40:] if len(str(file_path)) > 40 else str(file_path).replace("\\", "/")
                f.write(f"Файл: {short_path}\n")
                if hash_value:
                    f.write(f"  Хэш: {hash_value}\n")
                    f.write(f"  Тип угрозы: {description}\n")
                    f.write("  Рекомендация: Изолируйте файл в карантин и удалите. Проверьте систему на дополнительные угрозы.\n")
                else:
                    f.write(f"  Описание: {description}\n")
                    f.write("  Рекомендация: Проверьте файл вручную или поместите в карантин для анализа.\n")
                f.write("\n")

        self.log.insert(tk.END, f"Отчет по угрозам создан: {txt_path}\n")

    def generate_pdf_report(self, threats_found):
        pass  # Убрана генерация PDF

    def clear_log(self):
        self.log.delete(1.0, tk.END)
        self.progress.config(text="Готов")

if __name__ == "__main__":
    root = tk.Tk()
    app = AntivirusApp(root)
    root.mainloop()