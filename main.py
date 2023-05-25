from flask import Flask, request, render_template, send_file
from Crypto.Cipher import AES, DES, Blowfish, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import base64
import tempfile
import os

app = Flask(__name__)

# Generate RSA key once
rsa_key = RSA.generate(2048)

def create_cipher(algorithm, key):
    if algorithm == 'DES':
        return DES.new(key, DES.MODE_ECB)
    elif algorithm == 'Blowfish':
        return Blowfish.new(key, Blowfish.MODE_ECB)
    elif algorithm == 'AES':
        return AES.new(key, AES.MODE_ECB)
    elif algorithm == 'RSA':
        return PKCS1_OAEP.new(key)

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        operation = request.form.get('operation')
        algorithm = request.form.get('algorithm')
        text = request.form.get('text')

        key = None

        if algorithm == 'DES':
            key = b'abcdefgh'  # Key must be 8 bytes
        elif algorithm == 'Blowfish':
            key = b'abcdefghabcdefgh'  # Key must be between 4 and 56 bytes
        elif algorithm == 'AES':
            key = b'abcdefghabcdefgh'  # Key must be 16, 24, or 32 bytes
        elif algorithm == 'RSA':
            key = rsa_key

        cipher = create_cipher(algorithm, key)
        result = ""
        show_download = False

        if operation == 'Criptează':
            if algorithm == 'RSA':
                encoded_text = text.encode()
                encrypted = cipher.encrypt(encoded_text)
                result = base64.b64encode(encrypted).decode()
            else:
                padded_text = pad(text.encode(), cipher.block_size)
                encrypted = cipher.encrypt(padded_text)
                result = base64.b64encode(encrypted).decode()
                show_download = True
        elif operation == 'Decriptează':
            decoded_text = base64.b64decode(text)
            if algorithm == 'RSA':
                decrypted = cipher.decrypt(decoded_text)
                result = decrypted.decode()
            else:
                decrypted = cipher.decrypt(decoded_text)
                unpadded_text = unpad(decrypted, cipher.block_size)
                result = unpadded_text.decode()

        if operation == 'Criptează':
            # Save encrypted text to a temporary file
            temp_file = tempfile.NamedTemporaryFile(delete=False)
            temp_file.write(result.encode())
            temp_file.close()
            file_path = temp_file.name

            return render_template('home.html', result=result, show_download=show_download, file_path=file_path)
        else:
            return render_template('home.html', result=result, show_download=show_download)
    else:
        return render_template('home.html')

@app.route('/download', methods=['GET'])
def download():
    file_path = request.args.get('file_path')
    return send_file(file_path, as_attachment=True, attachment_filename='encrypted_text.txt')

if __name__ == '__main__':
    app.run(debug=True)
