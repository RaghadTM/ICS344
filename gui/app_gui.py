import tkinter as tk
from tkinter import ttk, messagebox



from crypto_core.aes_gcm import (
    encrypt_aes_gcm,
    decrypt_aes_gcm,
)
from crypto_core.key_exchange import (
    generate_rsa_keypair,
    wrap_aes_key,
    unwrap_aes_key,
    encode_secure_bundle,
    decode_secure_bundle,
)
from crypto_core.signatures import (
    sign_message,
    verify_signature,
)

class SecureMessagingApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Secure Messaging App - ICS344 G10")
        self.geometry("900x600")

        # RSA KEYS
        self.sender_private_key, self.sender_public_key = generate_rsa_keypair()
        self.receiver_private_key, self.receiver_public_key = generate_rsa_keypair()

         # Flooding attack counter

        self.decrypt_attempts = 0
         


        self.seen_nonces = set()


        self._build_layout()
        self.log("Generated RSA keys for sender and receiver.")

    def _build_layout(self):
        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill="both", expand=True)

        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=0)

        # Sender
        sender_frame = ttk.LabelFrame(main_frame, text="Sender", padding=10)
        sender_frame.grid(row=0, column=0, sticky="nsew")

        self.sender_text = tk.Text(sender_frame, height=15)
        self.sender_text.pack(fill="both", expand=True)

        sender_btn = ttk.Button(sender_frame, text="Encrypt", command=self.on_encrypt_clicked)
        sender_btn.pack(pady=5)

        # Receiver
        receiver_frame = ttk.LabelFrame(main_frame, text="Receiver", padding=10)
        receiver_frame.grid(row=0, column=1, sticky="nsew")

        self.receiver_text = tk.Text(receiver_frame, height=15)
        self.receiver_text.pack(fill="both", expand=True)

        receiver_btn = ttk.Button(receiver_frame, text="Decrypt", command=self.on_decrypt_clicked)
        receiver_btn.pack(pady=5)

        # Log
        log_frame = ttk.LabelFrame(main_frame, text="Log", padding=10)
        log_frame.grid(row=1, column=0, columnspan=2, sticky="nsew")

        self.log_text = tk.Text(log_frame, height=6, state="disabled")
        self.log_text.pack(fill="both", expand=True)

    def log(self, message: str):
        self.log_text.config(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.config(state="disabled")
        self.log_text.see("end")


    #  ENCRYPT  AES + RSA WRAP
    
    def on_encrypt_clicked(self):
        plaintext = self.sender_text.get("1.0", "end").strip()
        if not plaintext:
            messagebox.showwarning("Warning", "Enter a message first!")
            return

        try:
            # Encrypt plaintext using AES-GCM
            aes = encrypt_aes_gcm(plaintext)

            # Wrap AES key with Receiver's RSA public key
            wrapped = wrap_aes_key(aes.key, self.receiver_public_key)

          
            data_to_sign = aes.nonce + aes.ciphertext

            # Sign using Sender's private key
            signature = sign_message(self.sender_private_key, data_to_sign)

            



            bundle = encode_secure_bundle(
                wrapped,
                aes.nonce,
                aes.ciphertext,
                signature,
            )

           
            self.receiver_text.delete("1.0", "end")
            self.receiver_text.insert("1.0", bundle)

            self.decrypt_attempts = 0

            self.log("[Sender] AES-GCM + RSA wrapping + digital signature created.")
        except Exception as e:
            self.log(f"[Error] Encrypt/sign: {e}")
            messagebox.showerror("Error", f"Encrypt/sign failed: {e}")


    
    #  DECRYPT RSA UNWRAP + AES
    def on_decrypt_clicked(self):
        bundle_str = self.receiver_text.get("1.0", "end").strip()
        if not bundle_str:
            messagebox.showwarning("Warning", "Paste ciphertext first!")
            return

        # Flooding Attack Detection
        self.decrypt_attempts += 1
        if self.decrypt_attempts > 5:  
            self.log("[Receiver] Flooding attack detected! Too many decrypt attempts.")
            messagebox.showerror(
                "Flooding Attack",
                "Too many decrypt attempts! Possible flooding attack."
            )
            return

        try:
            # 1) Decode bundle
            bundle = decode_secure_bundle(bundle_str)

            # Replay Attack Detection 
            if bundle.nonce in self.seen_nonces:
                self.log("[Receiver] Replay detected! Nonce reused.")
                messagebox.showerror(
                    "Replay Attack",
                    "This message was already received before!"
                )
                return

            
            self.seen_nonces.add(bundle.nonce)

            # 2 Verify signature using Sender's public key
            data_to_verify = bundle.nonce + bundle.ciphertext
            is_valid = verify_signature(
                self.sender_public_key,
                data_to_verify,
                bundle.signature,
            )

            if not is_valid:
                self.log("[Receiver] Signature verification FAILED! Possible tampering.")
                messagebox.showerror(
                    "Integrity error",
                    "Signature verification failed.\nMessage may be tampered."
                )
                return

            self.log("[Receiver] Signature verification success.")

            # 3 Unwrap AES key using Receiver's private key
            aes_key = unwrap_aes_key(bundle.wrapped_key, self.receiver_private_key)

            # 4 Decrypt using AES-GCM
            plaintext = decrypt_aes_gcm(aes_key, bundle.nonce, bundle.ciphertext)

            self.log("[Receiver] RSA unwrap + AES-GCM decrypt success.")
            messagebox.showinfo("Decrypted message", plaintext)
        except Exception as e:
            self.log(f"[Error] Unwrap/decrypt/verify: {e}")
            messagebox.showerror("Error", f"Unwrap/decrypt/verify failed: {e}")
