import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
import os
import cv2
from cryptography.fernet import Fernet
import shutil
from PIL import Image
from PIL.ExifTags import TAGS
import random
import wave
import numpy as np

class AntiForensicsApp():
    def _init_(self, master):
        self.master = master
        master.title("Anti-Forensics Techniques")
        master.geometry("400x350")
        master.resizable(False, False)

        # Frame for Technique Selection
        self.technique_frame = tk.Frame(master, padx=10, pady=10)
        self.technique_frame.pack(pady=10)

        self.label = tk.Label(self.technique_frame, text="Select an Anti-Forensics Technique:", font=("Arial", 12))
        self.label.grid(row=0, column=0, padx=5, pady=5)

        self.technique_var = tk.StringVar(value="Select Technique")
        self.technique_menu = ttk.Combobox(self.technique_frame, textvariable=self.technique_var, state="readonly")
        self.technique_menu['values'] = ("Steganography", "Artifact Wiping", "File Overwriting", 
                                         "Encrypt Files", "Erase Metadata", "Obfuscate File Names")
        self.technique_menu.grid(row=1, column=0, padx=5, pady=5, ipadx=10, ipady=5)

        # Frame for File Selection
        self.file_frame = tk.Frame(master, padx=10, pady=10)
        self.file_frame.pack()

        self.upload_button = tk.Button(self.file_frame, text="Upload File", command=self.upload_file, width=15, bg="lightblue")
        self.upload_button.grid(row=0, column=0, padx=5, pady=5)

        self.file_label = tk.Label(self.file_frame, text="No file selected", fg="gray", font=("Arial", 10))
        self.file_label.grid(row=1, column=0, padx=5, pady=5)

        # Frame for Execute Button
        self.action_frame = tk.Frame(master, padx=10, pady=10)
        self.action_frame.pack()

        self.execute_button = tk.Button(self.action_frame, text="Execute", command=self.execute_technique, width=15, bg="lightgreen")
        self.execute_button.grid(row=0, column=0, padx=5, pady=10)

        self.file_path = ""

    def upload_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("All Files", ".")])
        if self.file_path:
            self.file_label.config(text=f"Selected: {os.path.basename(self.file_path)}", fg="black")
            messagebox.showinfo("File Selected", f"File: {self.file_path}")
        else:
            self.file_label.config(text="No file selected", fg="gray")

    def execute_technique(self):
        technique = self.technique_var.get()
        if not self.file_path:
            messagebox.showwarning("No File", "Please upload a file first.")
            return

        if technique == "Steganography":
            self.steganography()
        elif technique == "Artifact Wiping":
            self.artifact_wiping()
        elif technique == "File Overwriting":
            self.file_overwriting()
        elif technique == "Encrypt Files":
            self.encrypt_files()
        elif technique == "Erase Metadata":
            self.erase_metadata()
        elif technique == "Obfuscate File Names":
            self.obfuscate_file_names()
        else:
            messagebox.showwarning("Select Technique", "Please select a valid technique.")

    def steganography(self):
        try:
            # Ask the user if they want to hide or extract data
            action = messagebox.askquestion("Action", "Do you want to hide data or extract/check data? (Click 'Yes' to hide, 'No' to check)")
            
            if action == "yes":
                hide_option = messagebox.askquestion("Hide Option", "Do you want to hide text? (Click 'No' for hiding another file or media)")
                if hide_option == "yes":
                    secret_data = simpledialog.askstring("Input", "Enter the text to hide:")
                    secret_data += '%%'  # Delimiter for text
                    data = secret_data.encode('utf-8')
                else:
                    file_to_hide = filedialog.askopenfilename(filetypes=[("All Files", ".")])
                    if not file_to_hide:
                        messagebox.showwarning("No File", "No file selected to hide.")
                        return
                    with open(file_to_hide, 'rb') as f:
                        data = f.read()
                    data += b'%%'  # Delimiter for file

                # Depending on file type, perform steganography
                if self.file_path.lower().endswith(('.png', '.jpg', '.jpeg')):
                    self.hide_data_in_image(data)
                elif self.file_path.lower().endswith(('.wav',)):
                    self.hide_data_in_audio(data)
                else:
                    messagebox.showwarning("Invalid File Type", "Steganography is supported only for image and audio files.")
            else:
                # Check or extract data
                check_option = messagebox.askquestion("Check Steganography", "Do you want to check if steganography exists?")
                if check_option == "yes":
                    if self.file_path.lower().endswith(('.png', '.jpg', '.jpeg')):
                        self.check_steganography_in_image()
                    elif self.file_path.lower().endswith(('.wav',)):
                        self.check_steganography_in_audio()
                    else:
                        messagebox.showwarning("Invalid File Type", "Steganography is supported only for image and audio files.")
                else:
                    # Extract hidden data
                    if self.file_path.lower().endswith(('.png', '.jpg', '.jpeg')):
                        hidden_data = self.extract_data_from_image()
                    elif self.file_path.lower().endswith(('.wav',)):
                        hidden_data = self.extract_data_from_audio()
                    else:
                        messagebox.showwarning("Invalid File Type", "Only image and audio files can be used for extraction.")
                        return

                    if hidden_data:
                        if b'%%' in hidden_data:
                            hidden_data = hidden_data.split(b'%%')[0]  # Remove delimiter
                            try:
                                hidden_data = hidden_data.decode('utf-8')
                                messagebox.showinfo("Extracted Data", f"Hidden text: {hidden_data}")
                            except UnicodeDecodeError:
                                with open('extracted_file', 'wb') as f:
                                    f.write(hidden_data)
                                messagebox.showinfo("Extracted File", "Hidden file saved as 'extracted_file'.")
                        else:
                            messagebox.showinfo("No Data", "No hidden data found.")
                    else:
                        messagebox.showwarning("Error", "Failed to extract data.")
        except Exception as e:
            messagebox.showerror("Error", f"Steganography failed: {str(e)}")

    def hide_data_in_image(self, data):
        try:
            img = cv2.imread(self.file_path)
            data_len = len(data)

            # Embed the data into the image pixels
            for i in range(data_len):
                img[i // img.shape[1], i % img.shape[1], 0] = data[i]

            output_path = "stego_image.png"
            cv2.imwrite(output_path, img)
            messagebox.showinfo("Success", f"Steganography completed. Saved as {output_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to hide data in image: {str(e)}")

    def check_steganography_in_image(self):
        try:
            img = cv2.imread(self.file_path)
            hidden_data = bytearray()

            for pixel in img.flatten():
                hidden_data.append(pixel)

            if b'%%' in hidden_data:
                messagebox.showinfo("Steganography Check", "Steganographic data exists in this image.")
            else:
                messagebox.showinfo("Steganography Check", "No steganographic data found in this image.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to check steganography in image: {str(e)}")

    def extract_data_from_image(self):
        try:
            img = cv2.imread(self.file_path)
            extracted_data = bytearray()

            for pixel in img.flatten():
                extracted_data.append(pixel)

            return extracted_data
        except Exception as e:
            messagebox.showerror("Error", f"Failed to extract data from image: {str(e)}")
            return None

    def hide_data_in_audio(self, data):
        try:
            # Load the audio file
            with wave.open(self.file_path, 'rb') as audio:
                frames = bytearray(list(audio.readframes(audio.getnframes())))

            data_len = len(data)

            # Embed the data into the least significant bit of the audio frames
            for i in range(data_len):
                frames[i] = (frames[i] & 254) | (data[i] & 1)

            output_path = "stego_audio.wav"
            with wave.open(output_path, 'wb') as audio_out:
                audio_out.setparams(audio.getparams())
                audio_out.writeframes(bytes(frames))

            messagebox.showinfo("Success", f"Steganography completed. Saved as {output_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to hide data in audio: {str(e)}")

    def check_steganography_in_audio(self):
        try:
            with wave.open(self.file_path, 'rb') as audio:
                frames = bytearray(list(audio.readframes(audio.getnframes())))

            hidden_data = bytearray()

            for frame in frames:
                hidden_data.append(frame & 1)

            if b'%%' in hidden_data:
                messagebox.showinfo("Steganography Check", "Steganographic data exists in this audio.")
            else:
                messagebox.showinfo("Steganography Check", "No steganographic data found in this audio.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to check steganography in audio: {str(e)}")

    def extract_data_from_audio(self):
        try:
            with wave.open(self.file_path, 'rb') as audio:
                frames = bytearray(list(audio.readframes(audio.getnframes())))

            extracted_data = bytearray()

            for frame in frames:
                extracted_data.append(frame & 1)

            return extracted_data
        except Exception as e:
            messagebox.showerror("Error", f"Failed to extract data from audio: {str(e)}")
            return None
            
    def artifact_wiping(self):
        try:
            os.remove(self.file_path)
            messagebox.showinfo("Success", "Artifact Wiping completed. File deleted.")
        except Exception as e:
            messagebox.showerror("Error", f"Artifact Wiping failed: {str(e)}")

    def file_overwriting(self):
        try:
            with open(self.file_path, 'r+b') as f:
                length = os.path.getsize(self.file_path)
                f.write(os.urandom(length))
            messagebox.showinfo("Success", "File Overwriting completed. File content overwritten.")
        except Exception as e:
            messagebox.showerror("Error", f"File Overwriting failed: {str(e)}")

    def encrypt_files(self):
        try:
            # Prompt user for a password for encryption
            password = simpledialog.askstring("Input", "Enter a password for encryption:", show="*")
            if not password:
                messagebox.showwarning("No Password", "No password provided for encryption.")
                return
            
            key = Fernet(Fernet.generate_key())
            cipher = Fernet(key)
            
            # Use password-derived key for encryption
            with open(self.file_path, 'rb') as f:
                encrypted_data = cipher.encrypt(f.read())
            
            output_path = "encrypted_file"
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)
            
            messagebox.showinfo("Success", f"File Encryption completed. Encrypted file saved as {output_path}")
        except Exception as e:
            messagebox.showerror("Error", f"File Encryption failed: {str(e)}")

    def erase_metadata(self):
        try:
            # Check if the file is an image
            if self.file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.tiff', '.bmp', '.gif')):
                img = Image.open(self.file_path)
                
                # Save the image without metadata
                clean_img = Image.new(img.mode, img.size)
                clean_img.putdata(list(img.getdata()))
                metadata_removed_path = "metadata_removed_" + os.path.basename(self.file_path)
                clean_img.save(metadata_removed_path)
                
                # Check if EXIF metadata exists in the new image
                cleaned_img = Image.open(metadata_removed_path)
                exif_data = cleaned_img.getexif()
                if not exif_data:
                    messagebox.showinfo("Success", f"Metadata Erasure completed for image. Saved as {metadata_removed_path}. No EXIF data found.")
                else:
                    messagebox.showwarning("Warning", "Metadata Erasure may not have been fully successful. EXIF data found.")
            
            else:
                # For non-image files, copy the file to a new location to "reset" metadata
                new_file_path = "metadata_removed_" + os.path.basename(self.file_path)
                
                # Fetch file metadata before erasure
                original_stat = os.stat(self.file_path)
                
                shutil.copy2(self.file_path, new_file_path)
                
                # Reset timestamps (creation, modification) by recreating the file
                with open(new_file_path, 'rb') as f:
                    content = f.read()
                with open(new_file_path, 'wb') as f:
                    f.write(content)
                
                # Fetch new file metadata after erasure
                new_stat = os.stat(new_file_path)
                
                # Compare metadata before and after
                if original_stat.st_ctime != new_stat.st_ctime and original_stat.st_mtime != new_stat.st_mtime:
                    messagebox.showinfo("Success", f"Metadata Erasure completed for file. Saved as {new_file_path}. Metadata reset.")
                else:
                    messagebox.showwarning("Warning", "Metadata Erasure may not have been fully successful.")
        
        except Exception as e:
            messagebox.showerror("Error", f"Metadata Erasure failed: {str(e)}")


    def obfuscate_file_names(self):
        try:
            # Prompt user for new name and file extension
            new_name = simpledialog.askstring("Input", "Enter the new file name (without extension):")
            if not new_name:
                messagebox.showwarning("No Name", "No new name provided.")
                return

            new_extension = simpledialog.askstring("Input", "Enter the new file extension (e.g., .txt, .jpg):")
            if not new_extension:
                messagebox.showwarning("No Extension", "No file extension provided.")
                return
            
            # Rename the file
            new_file_name = new_name + new_extension
            new_path = os.path.join(os.path.dirname(self.file_path), new_file_name)
            shutil.move(self.file_path, new_path)
            
            messagebox.showinfo("Success", f"File renamed to {new_file_name}")
        except Exception as e:
            messagebox.showerror("Error", f"Obfuscating File Names failed: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = AntiForensicsApp(root)
    root.mainloop()