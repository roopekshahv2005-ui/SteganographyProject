import os
import io
import base64
import math
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from PIL import Image

app = Flask(__name__)

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///steganography.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'stego-secret-key-12345'

db = SQLAlchemy(app)

# Database Model
class StegoLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(20), nullable=False) # "Encode" or "Decode"
    filename = db.Column(db.String(100), nullable=False)
    message_len = db.Column(db.Integer, nullable=True)
    is_encrypted = db.Column(db.Boolean, default=False)
    psnr = db.Column(db.Float, nullable=True)
    mse = db.Column(db.Float, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "action": self.action,
            "filename": self.filename,
            "message_len": self.message_len,
            "is_encrypted": self.is_encrypted,
            "psnr": round(self.psnr, 2) if self.psnr is not None else "N/A",
            "mse": round(self.mse, 4) if self.mse is not None else "N/A",
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        }

# Helper Functions
def xor_encrypt_decrypt(data_bytes, password):
    if not password:
        return data_bytes
    key_bytes = password.encode('utf-8')
    return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data_bytes)])

def calculate_metrics(img1, img2):
    """Calculates Mean Squared Error (MSE) and Peak Signal-to-Noise Ratio (PSNR)."""
    p1 = list(img1.getdata())
    p2 = list(img2.getdata())
    
    mse_val = 0
    total_samples = 0
    
    for pix1, pix2 in zip(p1, p2):
        for c1, c2 in zip(pix1[:3], pix2[:3]):
            mse_val += (c1 - c2) ** 2
            total_samples += 1
            
    mse = mse_val / float(total_samples) if total_samples > 0 else 0
    if mse == 0:
        psnr = 100.0
    else:
        psnr = 20 * math.log10(255.0 / math.sqrt(mse))
        
    return mse, psnr

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/encode', methods=['POST'])
def encode_api():
    try:
        if 'image' not in request.files:
            return jsonify({'success': False, 'error': 'No image file uploaded'}), 400
            
        file = request.files['image']
        message = request.form.get('message', '')
        password = request.form.get('password', '')
        
        if not message:
            return jsonify({'success': False, 'error': 'Message cannot be empty'}), 400
            
        # Open source image and ensure RGB mode
        img = Image.open(file.stream)
        if img.mode != 'RGB':
            img = img.convert('RGB')
            
        width, height = img.size
        max_bytes = (width * height * 3) // 8 - 8
        
        # Prepare payload with delimiter "###END###"
        payload_text = message + "###END###"
        payload_bytes = payload_text.encode('utf-8')
        
        # Apply XOR password transformation if key provided
        final_bytes = xor_encrypt_decrypt(payload_bytes, password)
        
        if len(final_bytes) > max_bytes:
            return jsonify({'success': False, 'error': f'Message is too large. Max capacity: {max_bytes} bytes'}), 400
            
        # Convert bytes to bit array
        bit_string = ''.join(format(b, '08b') for b in final_bytes)
        
        # Embed bits into image LSB
        encoded_img = img.copy()
        pixels = encoded_img.load()
        
        bit_idx = 0
        total_bits = len(bit_string)
        done = False
        
        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]
                channels = [r, g, b]
                
                for c_idx in range(3):
                    if bit_idx < total_bits:
                        bit = int(bit_string[bit_idx])
                        channels[c_idx] = (channels[c_idx] & ~1) | bit
                        bit_idx += 1
                    else:
                        done = True
                        break
                
                pixels[x, y] = tuple(channels)
                if done:
                    break
            if done:
                break
                
        # Calculate PSNR and MSE
        mse, psnr = calculate_metrics(img, encoded_img)
        
        # Convert encoded image to PNG bytes buffer
        buffered = io.BytesIO()
        encoded_img.save(buffered, format="PNG")
        buffered.seek(0)
        
        encoded_b64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
        img_src = f"data:image/png;base64,{encoded_b64}"
        
        # Save log entry into SQLite
        log_entry = StegoLog(
            action="Encode",
            filename=file.filename or "uploaded_image.png",
            message_len=len(message),
            is_encrypted=bool(password),
            psnr=psnr,
            mse=mse
        )
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'result_image': img_src,
            'psnr': round(psnr, 2),
            'mse': round(mse, 4)
        })
        
    except Exception as e:
        print("Encode Error:", str(e))
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/decode', methods=['POST'])
def decode_api():
    try:
        if 'image' not in request.files:
            return jsonify({'success': False, 'error': 'No image file uploaded'}), 400
            
        file = request.files['image']
        password = request.form.get('password', '')
        
        img = Image.open(file.stream).convert('RGB')
        width, height = img.size
        pixels = img.load()
        
        # Extract LSB bits
        extracted_bits = []
        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]
                extracted_bits.append(str(r & 1))
                extracted_bits.append(str(g & 1))
                extracted_bits.append(str(b & 1))
                
        bit_str = ''.join(extracted_bits)
        all_bytes = bytearray()
        
        delimiter = "###END###".encode('utf-8')
        found_message = None
        
        for i in range(0, len(bit_str) - 8, 8):
            b_val = int(bit_str[i:i+8], 2)
            all_bytes.append(b_val)
            
            # Check for delimiter in decrypted stream
            current_decrypted = xor_encrypt_decrypt(bytes(all_bytes), password)
            if delimiter in current_decrypted:
                found_message = current_decrypted.split(delimiter)[0].decode('utf-8', errors='replace')
                break
                
        if found_message is None:
            return jsonify({'success': False, 'error': 'No hidden message found or incorrect passphrase!'}), 400
            
        # Log decode event
        log_entry = StegoLog(
            action="Decode",
            filename=file.filename or "stego_image.png",
            message_len=len(found_message),
            is_encrypted=bool(password),
            psnr=None,
            mse=None
        )
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': found_message
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/logs', methods=['GET'])
def get_logs():
    logs = StegoLog.query.order_by(StegoLog.timestamp.desc()).limit(20).all()
    return jsonify({'success': True, 'logs': [l.to_dict() for l in logs]})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)