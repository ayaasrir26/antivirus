import os
import tkinter as tk
from tkinter import filedialog, messagebox

class AntivirusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Antivirus Simple")
        self.file_vars = []
        self.file_paths = []

        # Choisir dossier
        self.btn_select = tk.Button(root, text="Choisir dossier", command=self.select_folder,bg="grey")
        self.btn_select.pack(pady=5)

        # sélection
        self.select_all_state = tk.BooleanVar(value=False)
        self.select_all_btn = tk.Button(root, text="✔️ Tout sélectionner", command=self.toggle_select_all, bg="light grey")
        self.select_all_btn.pack(pady=5)

        # cadre avec scrollbar
        self.canvas = tk.Canvas(root, width=400, height=400)
        self.scrollbar = tk.Scrollbar(root, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")
            )
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Supprimer les fichiers 
        self.btn_delete = tk.Button(root, text="🗑️ Supprimer fichiers sélectionnés", command=self.confirm_delete,bg="grey")
        self.btn_delete.pack(pady=10)

    def select_folder(self):
        self.clear_checkboxes()
        folder = filedialog.askdirectory()
        if not folder:
            return

        files = os.listdir(folder)
        suspicious_files = []

        # les fichiers vide et double
        duplicates = self.find_duplicates(folder)

        for file in files:
            full_path = os.path.join(folder, file)
            if os.path.isfile(full_path):
                size = os.path.getsize(full_path)
                if size == 0 or full_path in duplicates:
                    suspicious_files.append(full_path)

        if not suspicious_files:
            messagebox.showinfo("Info", "Aucun fichier vide ou doublon trouvé dans ce dossier.")
            return

        for path in suspicious_files:
            var = tk.BooleanVar()
            cb = tk.Checkbutton(self.scrollable_frame, text=path, variable=var, anchor="w", justify="left", wraplength=580)
            cb.pack(fill='x', anchor="w")
            self.file_vars.append(var)
            self.file_paths.append(path)

        self.select_all_state.set(False)
        self.select_all_btn.config(text="✔️ Tout sélectionner" ,bg="green")

    def find_duplicates(self, folder):
        # Fonction simple pour trouver fichiers doublons par contenu (hash)
        import hashlib

        hashes = {}
        duplicates = set()

        for file in os.listdir(folder):
            full_path = os.path.join(folder, file)
            if os.path.isfile(full_path) and os.path.getsize(full_path) > 0:
                file_hash = self.hash_file(full_path, hashlib.md5())
                if file_hash in hashes:
                    duplicates.add(full_path)
                    duplicates.add(hashes[file_hash])
                else:
                    hashes[file_hash] = full_path
        return duplicates

    def hash_file(self, filepath, hash_func):
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()

    def toggle_select_all(self):
        new_state = not self.select_all_state.get()
        self.select_all_state.set(new_state)
        for var in self.file_vars:
            var.set(new_state)
        if new_state:
            self.select_all_btn.config(text="❌ Tout décocher",bg="red")
        else:
            self.select_all_btn.config(text="✔️ Tout sélectionner",bg="green")

    def confirm_delete(self):
        selected_files = [ (i, path) for i, (var, path) in enumerate(zip(self.file_vars, self.file_paths)) if var.get() ]
        if not selected_files:
            messagebox.showinfo("Aucun fichier sélectionné", "⚠️ Veuillez cocher au moins un fichier à supprimer.")
            return

        confirm = messagebox.askyesno("Confirmation", f"Êtes-vous sûr de vouloir supprimer {len(selected_files)} fichier(s) ?")
        if confirm:
            deleted_count = 0
            for i, path in reversed(selected_files):
                try:
                    os.remove(path)
                    deleted_count += 1
                    self.remove_file_at_index(i)
                except Exception as e:
                    print(f"Erreur suppression {path}: {e}")

            messagebox.showinfo("Suppression terminée", f"{deleted_count} fichier(s) supprimé(s) avec succès.")

    def remove_file_at_index(self, index):
        widget = self.scrollable_frame.winfo_children()[index]
        widget.destroy()
        del self.file_vars[index]
        del self.file_paths[index]

    def clear_checkboxes(self):
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        self.file_vars.clear()
        self.file_paths.clear()
        self.select_all_state.set(False)
        self.select_all_btn.config(text="✔️ Tout sélectionner" ,bg="green")


if __name__ == "__main__":
    root = tk.Tk()
    app = AntivirusApp(root)
    root.mainloop()
