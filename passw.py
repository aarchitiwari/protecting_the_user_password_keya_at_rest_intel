# installed pycryptodome
# importing required Libraries
import os
import struct
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from tkinter import *
from tkinter import filedialog, messagebox

#Header
magic_head = b'SECURED'

# Generating Random key for password
def rand_key():
    # AES-256 passwrd key length is 16
    return get_random_bytes(16)

# Encrypting the user chosen file
def encrypt_f(file_pt, key):
    chnk_size = 64*1024  #chunk size to read a file
    out_file_pt = file_pt + '.sealed' #file path after encryption

    i = get_random_bytes(16)  #initialization vector for AES
    ciph = AES.new(key, AES.MODE_CBC, i)  #AES cipher object

    f_size = os.path.getsize(file_pt)

    #writing iv and filesize
    with open(file_pt, 'rb') as in_file, open(out_file_pt, 'wb') as out_file:
        out_file.write(magic_head)     
        out_file.write(struct.pack('<Q', f_size)) 
        out_file.write(i) 

        while chnk := in_file.read(chnk_size):
            if len(chnk) % AES.block_size != 0:   # Reading the file in chunks
                chnk = pad(chnk, AES.block_size)   # Padding the chunk
            out_file.write(ciph.encrypt(chnk)) #writing chunk to an output file

    print(f"Encryted {file_pt} to {out_file_pt}")
    os.remove(file_pt)

# Encrypting all files in Directory
def encrypt_dir(dir_pt, key):
    for root, _, files in os.walk(dir_pt):
        for file in files:
            encrypt_f(os.path.join(root, file), key)


# Encrypting key with PBKDF2
def encrypt_wd_passphrase(key, passphrase):
    slt = get_random_bytes(16)   #generating random salt
    derived_key = PBKDF2(passphrase, slt, dkLen=16,
                         count=1000000, hmac_hash_module=SHA256)   #deriving a key
    i = get_random_bytes(16)  #generating a initialization vector
    ciph = AES.new(derived_key, AES.MODE_CBC, i)  
    encrypt_k = ciph.encrypt(pad(key, AES.block_size)) #encrypting key and padding it

    with open('encrypt_k.bin', 'wb') as e:
        e.write(slt)  #writing salt to the file
        e.write(i)    #writing iv to the file
        e.write(encrypt_k)  #writing encrypted key to the file
    print("Key saved to '{encrypt_k.bin}'")

# -----------------------------Successfully encrypted the user chosen file----------------------------------------

# Decryption
def decrypt_wd_passphrase(passphrase):
    with open('encrypt_k.bin', 'rb') as d:
        slt = d.read(16)        #Reading salt from file
        i = d.read(16)          #reading iv from file
        encrypt_k = d.read()    #reading encrypted key from file
    derived_key = PBKDF2(passphrase, slt, dkLen=16,
                         count=1000000, hmac_hash_module=SHA256) #deriving key from passphrase
    ciph = AES.new(derived_key, AES.MODE_CBC, i)   #AES object
    key = unpad(ciph.decrypt(encrypt_k), AES.block_size)    #Decrypting and unpadding the file
    return key

#checking if file is encrypted
def is_encrypted(file_pt):
    try:
        with open(file_pt, 'rb') as in_file:
            head = in_file.read(len(magic_head))  #Reading the header
            return head == magic_head
    except Exception as ex:
        print(f'Error reading file {file_pt}: {ex}')
        return False


# Decrypting if file
def decrypt_f(file_pt, key):
    out_file_pt = file_pt[:-7]  #output file without .sealed extension
    with open(file_pt, 'rb') as in_file:
        head = in_file.read(len(magic_head)) #reading the header
        if (head != magic_head):
            print(f'{file_pt} is not encrypted')
            return

        og_size = struct.unpack('<Q', in_file.read(struct.calcsize('Q')))[0] #reading the original file
        i = in_file.read(16)  #reading the iv
        ciph = AES.new(key, AES.MODE_CBC, i)  #creating AES cipher object

        with open(out_file_pt, 'wb') as out_file:
            while chnk := in_file.read(64 * 1024):  #reading file in chunks
                out_file.write(ciph.decrypt(chnk))  #Decrypting the chunk and writing it to the output file
            out_file.truncate(og_size) #converting outputfile to original file

    print(f'Decrypted {file_pt} to {out_file_pt}')
    os.remove(file_pt)

# decrypting if Directory
def decrypt_dir(directory_pt, key):
    for root, _, files in os.walk(directory_pt):
        for file in files:
            if file.endswith('.sealed') and is_encrypted(os.path.join(root, file)):
                decrypt_f(os.path.join(root, file), key)


# GUI
class Secured:

    def __init__(self, node):
        self.node = node
        self.node.title("CipherSafe")
        self.node.geometry("350x400+0+0")
        self.node.config(bg="white")
        self.main_frame()

    def main_frame(self):
        self.clear_frame()
        title = Label(self.node, text="CipherSafe", font=("times new roman", 20, "bold"),
                           bg="white", fg="black", anchor="w", padx=5).place(x=100, y=10, relwidth=50)
        self.frame_main = Frame(self.node, bg="#262626").place(
            x=20, y=70, width=300, height=200)
        self.btn_enc = Button(self.frame_main, text="Encrypt",
                              command=self.encrypt_the_file_func, font=("times new roman", 15, "bold")).place(x=45, y=120, w=250, height=35)
        self.btn_dec = Button(self.frame_main, text="Decrypt",
                              command=self.decrypt_the_file_func, font=("times new roman", 15, "bold")).place(x=45, y=180, w=250, height=35)

    def browse_file(self):
        file_pt = filedialog.askopenfilename()
        self.file_path.set(file_pt)
        print(file_pt)

    def browse_fold(self):
        folder_path = filedialog.askdirectory()
        self.folder_path.set(folder_path)
        print(folder_path)

    def encrypt_the_file_func(self):
        self.clear_frame()
        title = Label(self.node, text="CipherSafe", font=("times new roman", 20, "bold"),
                           bg="white", fg="black", anchor="w", padx=5).place(x=100, y=0, relwidth=50)
        self.file_path = StringVar()
        self.folder_path = StringVar()
        self.password = StringVar()
        self.frame = Frame(self.node, bg="#262626").place(
            x=20, y=70, width=300, height=300)
        for_file = Label(self.frame, text="If File:", font=(
            "times new roman", 10, "bold"), bg="#262626", fg="white").place(x=65, y=80)
        btn1 = Button(self.frame, text="Browse", command=self.browse_file).place(
            x=65, y=110, width=200)
        for_folder = Label(self.frame, text="If Folder:", font=(
            "times new roman", 10, "bold"), bg="#262626", fg="white").place(x=65, y=150)
        btn2 = Button(self.frame, text="Browse", command=self.browse_fold).place(
            x=65, y=180, width=200)
        for_passwrd = Label(self.frame, text="Enter your password (atmost 16 characters):", font=(
            "times new roman", 10, "bold"), bg="#262626", fg="white").place(x=55, y=220)
        passwrd = Entry(self.frame, font=("times new roman", 15), textvariable=self.password,
                        bg="LIGHTyellow", fg="black").place(x=65, y=250, width=200)
        btn_encrypt = Button(self.frame, text="Encrypt",
                             command=self.seal).place(x=100, y=300, width=100)

    def seal(self):
        pt = self.file_path.get()
        folder_pt = self.folder_path.get()
        passwrd = self.password.get()
        if passwrd == '':
            messagebox.showerror("Error", "Please provide Password")
            return
        elif len(passwrd)<6:
            messagebox.showerror("Error", "Password must have atleast 6 characters")
            return
        try:
            key = rand_key()
            encrypt_wd_passphrase(key, passwrd)
            if pt:
                if os.path.isfile(pt):
                    encrypt_f(pt, key)
                    messagebox.showinfo("Success","Success! The file encrypted successfully.")
                    self.main_frame()
            elif folder_pt:
                if os.path.isdir(folder_pt):
                    encrypt_dir(folder_pt, key)
                    messagebox.showinfo("Success","Success! The folder encrypted successfully.")
                    self.main_frame()
            else:
                messagebox.showerror("Error","Please select file or folder")
                return 
            
        except Exception as ex:
            messagebox.showerror("Error",f"Error due to: {str(ex)} ")

    def decrypt_the_file_func(self):
        self.clear_frame()
        title = Label(self.node, text="CipherSafe", font=("times new roman", 20, "bold"),
                           bg="white", fg="black", anchor="w", padx=5).place(x=100, y=0, relwidth=50)
        self.file_path = StringVar()
        self.folder_path = StringVar()
        self.password = StringVar()
        self.frame = Frame(self.node, bg="#262626").place(
            x=20, y=70, width=300, height=300)
        for_file = Label(self.frame, text="If File:", font=(
            "times new roman", 10, "bold"), bg="#262626", fg="white").place(x=65, y=80)
        # filept = Entry(self.frame, font=("times new roman", 15), textvariable=self.file_path,
        #                bg="LIGHTyellow", fg="black").place(x=30, y=110, width=200)
        btn1 = Button(self.frame, text="Browse", command=self.browse_file).place(
            x=65, y=110, width=200)
        for_folder = Label(self.frame, text="If Folder:", font=(
            "times new roman", 10, "bold"), bg="#262626", fg="white").place(x=65, y=150)
        # folderpt = Entry(self.frame, font=("times new roman", 15), textvariable=self.folder_path,
        #                  bg="LIGHTyellow", fg="black").place(x=30, y=180, width=200)
        btn2 = Button(self.frame, text="Browse", command=self.browse_fold).place(
            x=65, y=180, width=200)
        for_passwrd = Label(self.frame, text="Enter your password:", font=(
            "times new roman", 10, "bold"), bg="#262626", fg="white").place(x=65, y=220)
        passwrd = Entry(self.frame, font=("times new roman", 15), textvariable=self.password,
                        bg="LIGHTyellow", fg="black").place(x=65, y=250, width=200)
        btn_decrypt = Button(self.frame, text="Decrypt",
                             command=self.unseal).place(x=100, y=300, width=100)

    def unseal(self):
        pt = self.file_path.get()
        folder_pt = self.folder_path.get()
        passwrd = self.password.get()
        if passwrd == '':
            messagebox.showerror("Error", "Please provide Password")
            return
        try:
            key = decrypt_wd_passphrase(passwrd)
            if pt:
                if os.path.isfile(pt):
                    decrypt_f(pt, key)
                    messagebox.showinfo("Success","Success! The file decrypted successfully.")
                    self.main_frame()
            elif folder_pt:
                if os.path.isdir(folder_pt):
                    decrypt_dir(folder_pt, key)
                    messagebox.showinfo("Success","Success! The folder decrypted successfully.")
                    self.main_frame()
            else:
                messagebox.showerror("Error","Please select file or folder")
                return
        except Exception as ex:
            if "Padding is incorrect" in str(ex):
                messagebox.showerror("Error", "Password is incorrect")
            else: messagebox.showerror("Error",f"Error due to: {str(ex)} ")


    def clear_frame(self):
        for widget in self.node.winfo_children():
            widget.destroy()


node = Tk()
sec1 = Secured(node)
node.mainloop()
