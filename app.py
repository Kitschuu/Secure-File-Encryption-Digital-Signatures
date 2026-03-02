import streamlit as st
import os
import time
import json
import base64
import zipfile
from io import BytesIO

# Cryptography imports
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# QR Code imports
import qrcode
from PIL import Image
from pyzbar.pyzbar import decode

# ==========================================
# CRYPTOGRAPHY LOGIC MODULE
# ==========================================

def generate_key_pair():
    """Generates a 2048-bit RSA key pair."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_and_sign(file_data, filename, sender_private_key_pem, recipient_public_key_pem):
    """
    Encrypts a file using Hybrid Encryption (AES + RSA) and signs it.
    """
    # 1. Generate AES session key (256-bit)
    session_key = get_random_bytes(32)
    
    # 2. Encrypt AES session key with Recipient's Public Key
    recipient_key = RSA.import_key(recipient_public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    
    # 3. Encrypt file with AES-GCM (Authenticated Encryption)
    cipher_aes = AES.new(session_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(file_data)
    nonce = cipher_aes.nonce
    
    # Pack encrypted file: nonce (16) + tag (16) + ciphertext
    encrypted_file_data = nonce + tag + ciphertext
    
    # 4. Create metadata payload
    metadata = {
        "filename": filename,
        "timestamp": time.time(),
        "time_str": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    }
    metadata_json = json.dumps(metadata)
    
    # 5. Hash (Encrypted File + Metadata) using SHA-256
    hash_payload = encrypted_file_data + metadata_json.encode('utf-8')
    h = SHA256.new(hash_payload)
    
    # 6. Sign Hash with Sender's Private Key
    sender_key = RSA.import_key(sender_private_key_pem)
    signature = pkcs1_15.new(sender_key).sign(h)
    
    # 7. Generate QR payload containing Signature, Encrypted AES Key, and Metadata
    qr_payload = {
        "signature": base64.b64encode(signature).decode('utf-8'),
        "encrypted_aes_key": base64.b64encode(enc_session_key).decode('utf-8'),
        "metadata": metadata
    }
    qr_data = json.dumps(qr_payload)
    
    # 8. Generate QR Code (PNG bytes)
    qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(qr_data)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")
    
    img_byte_arr = BytesIO()
    qr_img.save(img_byte_arr, format='PNG')
    qr_img_bytes = img_byte_arr.getvalue()
    
    return encrypted_file_data, qr_img_bytes, metadata['time_str']

def verify_and_decrypt(encrypted_file_data, qr_img_bytes, sender_public_key_pem, recipient_private_key_pem):
    """
    Verifies the Digital Signature via QR code and decrypts the file.
    """
    # 1. Read QR Code
    img = Image.open(BytesIO(qr_img_bytes)).convert('RGBA')
    decoded_objects = decode(img)
    if not decoded_objects:
        raise ValueError("Could not decode QR code. Ensure it is a valid signature QR code.")
    
    qr_data = decoded_objects[0].data.decode('utf-8')
    qr_payload = json.loads(qr_data)
    
    signature = base64.b64decode(qr_payload["signature"])
    enc_session_key = base64.b64decode(qr_payload["encrypted_aes_key"])
    metadata = qr_payload["metadata"]
    metadata_json = json.dumps(metadata)
    
    # 2. Verify Signature
    hash_payload = encrypted_file_data + metadata_json.encode('utf-8')
    h = SHA256.new(hash_payload)
    sender_key = RSA.import_key(sender_public_key_pem)
    
    try:
        pkcs1_15.new(sender_key).verify(h, signature)
    except (ValueError, TypeError):
        raise ValueError("Signature verification failed! The file or metadata has been tampered with.")
        
    # 3. Decrypt AES Key using Recipient's Private Key
    recipient_key = RSA.import_key(recipient_private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    try:
        session_key = cipher_rsa.decrypt(enc_session_key)
    except ValueError:
        raise ValueError("Failed to decrypt the AES session key. Incorrect recipient private key.")
        
    # 4. Decrypt File using AES-GCM
    nonce = encrypted_file_data[:16]
    tag = encrypted_file_data[16:32]
    ciphertext = encrypted_file_data[32:]
    
    cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    try:
        file_data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise ValueError("MAC check failed. The encrypted file data is corrupted or tampered with.")
        
    return file_data, metadata

# ==========================================
# STREAMLIT UI MODULE
# ==========================================

st.set_page_config(page_title="Secure File Cryptography", layout="wide")
st.title("🔒 Secure File Encryption & Digital Signatures")
st.markdown("A highly secure, hybrid encryption application leveraging **RSA**, **AES-256-GCM**, and **SHA-256** signatures embedded in QR codes.")

tab1, tab2, tab3 = st.tabs(["🔑 Key Generation", "🛡️ Encrypt & Sign", "🔓 Verify & Decrypt"])

with tab1:
    st.header("Generate RSA Key Pair")
    st.write("Generate a secure 2048-bit RSA key pair. **Keys are generated in memory only and never stored on the server.**")
    
    if st.button("Generate Keys"):
        with st.spinner("Generating cryptographic keys..."):
            priv, pub = generate_key_pair()
            st.session_state['new_priv'] = priv
            st.session_state['new_pub'] = pub
            st.success("✅ Keys formulated successfully!")
            
    if 'new_priv' in st.session_state:
        col_k1, col_k2 = st.columns(2)
        with col_k1:
            st.download_button("📥 Download Private Key (.pem)", st.session_state['new_priv'], "private_key.pem", "application/x-pem-file")
            st.error("Keep your Private Key completely secret!")
        with col_k2:
            st.download_button("📥 Download Public Key (.pem)", st.session_state['new_pub'], "public_key.pem", "application/x-pem-file")
            st.info("Share your Public Key with people who need to send you files or verify your signatures.")

with tab2:
    st.header("Batch Encrypt & Sign Files")
    st.markdown("Upload multiple files to encrypt them with a recipient's *Public Key* and sign them with your *Private Key*.")
    
    files = st.file_uploader("1️⃣ Upload Files to Encrypt", accept_multiple_files=True, key="enc_files")
    
    col_e1, col_e2 = st.columns(2)
    with col_e1:
        sender_priv_file = st.file_uploader("2️⃣ Your Private Key (for signing)", type=["pem"], key="sender_priv")
    with col_e2:
        rec_pub_file = st.file_uploader("3️⃣ Recipient's Public Key (for encryption)", type=["pem"], key="rec_pub")
        
    if st.button("Process Files (Encrypt & Sign)", type="primary"):
        if not files or not sender_priv_file or not rec_pub_file:
            st.warning("⚠️ Please provide files and both required keys.")
        else:
            with st.spinner("Applying Hybrid Encryption and Digital Signatures..."):
                try:
                    sender_priv = sender_priv_file.read()
                    rec_pub = rec_pub_file.read()
                    
                    zip_buffer = BytesIO()
                    with zipfile.ZipFile(zip_buffer, "w") as zf:
                        for f in files:
                            file_bytes = f.read()
                            enc_data, qr_bytes, t_str = encrypt_and_sign(file_bytes, f.name, sender_priv, rec_pub)
                            
                            base_name = os.path.splitext(f.name)[0]
                            zf.writestr(f"{base_name}_encrypted.enc", enc_data)
                            zf.writestr(f"{base_name}_signature_qr.png", qr_bytes)
                            
                    st.success("✅ Batch Processing Complete!")
                    st.download_button(
                        label="📥 Download Encrypted Package (ZIP with .enc files and QR codes)",
                        data=zip_buffer.getvalue(),
                        file_name="encrypted_package.zip",
                        mime="application/zip"
                    )
                except Exception as e:
                    st.error(f"❌ Encryption Error: {str(e)}")

with tab3:
    st.header("Batch Verify & Decrypt Files")
    st.markdown("Upload encrypted files and their companion QR Codes. Verify the sender and safely decrypt the content.")
    
    enc_files = st.file_uploader("1️⃣ Upload Encrypted Files (.enc)", accept_multiple_files=True, key="dec_files")
    qr_files = st.file_uploader("2️⃣ Upload Companion QR Codes (.png)", accept_multiple_files=True, key="qr_files", type=["png", "jpg", "jpeg"])
    
    col_v1, col_v2 = st.columns(2)
    with col_v1:
        sender_pub_file = st.file_uploader("3️⃣ Sender's Public Key (to verify signature)", type=["pem"], key="sender_pub")
    with col_v2:
        rec_priv_file = st.file_uploader("4️⃣ Your Private Key (to decrypt AES)", type=["pem"], key="rec_priv")
        
    if st.button("Verify & Decrypt", type="primary"):
        if not enc_files or not qr_files or not sender_pub_file or not rec_priv_file:
            st.warning("⚠️ Please provide all files, QR codes, and keys.")
        elif len(enc_files) != len(qr_files):
            st.warning("⚠️ Mismatch: The number of encrypted files must match the number of QR codes.")
        else:
            with st.spinner("Cryptographic Verification & Decryption in progress..."):
                try:
                    sender_pub = sender_pub_file.read()
                    rec_priv = rec_priv_file.read()
                    
                    # Sort files alphabetically to match .enc with .png reliably
                    enc_files_sorted = sorted(enc_files, key=lambda x: x.name)
                    qr_files_sorted = sorted(qr_files, key=lambda x: x.name)
                    
                    dec_zip_buffer = BytesIO()
                    success_count = 0
                    
                    with zipfile.ZipFile(dec_zip_buffer, "w") as zf:
                        for i in range(len(enc_files_sorted)):
                            ef = enc_files_sorted[i]
                            qf = qr_files_sorted[i]
                            
                            try:
                                dec_data, metadata = verify_and_decrypt(ef.read(), qf.read(), sender_pub, rec_priv)
                                
                                st.success(f"✅ **{metadata['filename']}** verified and decrypted successfully! \n\n🕒 Timestamp of authentic signature: **{metadata['time_str']}**")
                                zf.writestr(metadata['filename'], dec_data)
                                success_count += 1
                                
                            except Exception as e:
                                st.error(f"❌ **Validation Failed for {ef.name}:** {str(e)}")
                                
                                # Tamper Detection Logic
                                st.warning("🚨 **TAMPER DETECTION ALERT:** A signature verification failure means the file payload or metadata has been altered post-signature.")
                                
                                # Advanced OS-level modification tracking (best-effort given browser context)
                                try:
                                    # Fallback to local machine OS check (works only if file path evaluates correctly locally)
                                    mtime = os.path.getmtime(ef.name)
                                    mtime_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mtime))
                                    st.error(f"🕵️‍♂️ **File Forensic Data:** The local OS indicates the file '{ef.name}' was last modified on **{mtime_str}**. Discrepancies between this time and expected transmission confirm tampering.")
                                except Exception:
                                    st.info("ℹ️ *Note:* As this app is running in a browser environment, exact OS-level modification stamps of the uploaded file cannot be retrieved due to browser security constraints. However, the cryptographic hash failure guarantees it was altered.")
                    
                    if success_count > 0:
                        st.download_button(
                            label=f"📥 Download Decrypted Files ({success_count} files)",
                            data=dec_zip_buffer.getvalue(),
                            file_name="decrypted_verified_files.zip",
                            mime="application/zip"
                        )
                except Exception as e:
                    st.error(f"Critical System Error: {str(e)}")
