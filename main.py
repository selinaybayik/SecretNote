from tkinter import *
from PIL import ImageTk,Image
from tkinter import messagebox
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


def save_encryption():
    entry_islem=my_entry1.get()
    message = my_text2.get("1.0",END)
    master_entry_islem=master_entry.get()

    if len(entry_islem)==0 or len(message)==0 or len(master_entry_islem)==0:
        messagebox.showerror(title="error!",message="please enter all info")

    else:
        message_encrypted=encode(master_entry_islem,message)
        try:
            with open("mySecret.txt","a") as data_file:
                data_file.write(f"\n{entry_islem}\n{message_encrypted}")
        except FileNotFoundError:
            with open("mySecret.txt","w") as data_file:
                data_file.write(f"\n{entry_islem}\n{message_encrypted}")
        finally:
            my_entry1.delete(0,END)
            my_text2.delete("1.0",END)
            master_entry.delete(0,END)


def decrypt_notes():
    message_encrypted= my_text2.get("1.0", END)
    master_entry_islem= master_entry.get()

    if len(message_encrypted) == 0 or len(master_entry_islem) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        try:
            decrypted_message = decode(master_entry_islem,message_encrypted)
            my_text2.delete("1.0", END)
            my_text2.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error!", message="Please make sure of encrypted info.")


window=Tk()
window.title("SecretNotes")
window.minsize(400,650)

#image
image=Image.open("topSecret.jpg")
resize_image = image.resize((90,90))

img = ImageTk.PhotoImage(resize_image)

panel=Label(image=img)
panel.config(width=100,height=100)
panel.config(padx=20,pady=20)
panel.pack()


my_label1=Label(text="Enter your title",font=("arial",18,"normal"))
my_label1.pack()

my_entry1=Entry(width=20)
my_entry1.pack()

my_label2=Label(text="Enter your secret",font=("arial",18,"normal"))
my_label2.pack()

my_text2=Text(width=30,height=16)
my_text2.pack()

my_master=Label(text="Enter master key",font=("arial",18,"normal"))
my_master.pack()

master_entry=Entry(width=20)
master_entry.pack()

save_button=Button(text="Save&Encrypt",command=save_encryption)
save_button.pack()

decrypt_button=Button(text="Decrypt",command=decrypt_notes)
decrypt_button.pack()


window.mainloop()