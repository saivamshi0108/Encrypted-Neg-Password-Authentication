from django.shortcuts import render,HttpResponse,redirect,get_object_or_404 
from home.models import UserDetails
from django.contrib import messages
import hashlib
import os
from cryptography.hazmat.primitives import padding,hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Create your views here.
def index(request):
    return render(request,'index.html')

def login(request):
    return render(request,'login.html')

def create(request):
    return render(request,'createaccount.html')

def logout(request):
    if request.method == "POST":
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            user = UserDetails.objects.get(email = email)
        except UserDetails.DoesNotExist:
            user = None
        
        if user is not None:
            stored_encrypted_password = user.encrypted_password  # Convert to bytes
            stored_key = b'\xaa\x89t\xda\xc5\xdd#\xb3\x82\x80\xec\xff\xb70\x00`\xc8\xb0\xfa\xc8iU\x13\xd4\xa1\xcf\xac\xdc\xd3PF\xdc'
            decrypted_password = decrypt_password(stored_encrypted_password, stored_key)
            print(decrypted_password.decode())

            negative_password = generate_binary_negative_password(password)
            hashed_password = hash_password(password)
            print("Negative pass",user.negative_password)
            print("")
   
            if(hashed_password == user.hashed_password and decrypted_password == negative_password.encode()):
                messages.success(request, 'You have successfully logged in.')
                request.session['user_id'] = user.id
                request.session['email'] = user.email
                return redirect("/") 
            else:
                messages.error(request, 'Wrong password')
                return redirect("/login")

        else:
            messages.error(request, 'Account not found')
            return redirect("/login")

    return render(request, 'logout.html')

def failed(request):
    if request.method == "POST":
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirmPassword = request.POST.get('confirmPassword')
        hashed_password,negative_password,encrypted_password  = getpasswords(password)
        
        if UserDetails.objects.filter(email=email).exists():
            messages.error(request, 'Email already exists. Please Log In')
            return redirect("/create") 
        
        if password!=confirmPassword:
            return render(request, 'failed.html')
        else:
            user = UserDetails( email = email,
                                hashed_password = hashed_password,
                                negative_password = negative_password,
                                encrypted_password = encrypted_password)
            user.save()
            messages.success(request, 'Account created successfully!')
            return redirect("/") 

    return render(request, 'failed.html')

def logout_2(request):
    request.session.clear()
    return redirect('/')

# def generate_key(password, salt=b'salt'):
#     # Derive a 32-byte key using PBKDF2 with SHA-256
#     kdf = PBKDF2HMAC(
#         algorithm=hashes.SHA256(),
#         length=32,
#         salt=salt,
#         iterations=100000, 
#         backend=default_backend()
#     )
#     key = kdf.derive(password.encode())
#     return key

def getpasswords(password):
    # salt = os.urandom(16)  
    # key = generate_key(password, salt)
    key = b'\xaa\x89t\xda\xc5\xdd#\xb3\x82\x80\xec\xff\xb70\x00`\xc8\xb0\xfa\xc8iU\x13\xd4\xa1\xcf\xac\xdc\xd3PF\xdc'
    hashed_password = hash_password(password)
    negative_password = generate_binary_negative_password(password)
    encrypted_password = encrypt_password(negative_password, key)
    decrypted_password = decrypt_password(encrypted_password, key)
    return hashed_password, negative_password, encrypted_password

def hash_password(password):
    digest = hashlib.sha256()
    digest.update(password.encode())
    hashed_password = digest.digest()
    return hashed_password

def generate_negative_password(password):
    negative_password = ''.join(str(-ord(char)) for char in password)
    return negative_password

def generate_binary_negative_password(password):
    negative_password = ''.join(str(-ord(char)) for char in password)
    binary_password = '*'.join(format(ord(char), '08b') for char in negative_password)
    return binary_password


def encrypt_password(password, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_password = padder.update(password.encode()) + padder.finalize()

    encrypted_password = encryptor.update(padded_password) + encryptor.finalize()
    return encrypted_password

def decrypt_password(encrypted_password, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_password = decryptor.update(encrypted_password) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_password = unpadder.update(decrypted_password) + unpadder.finalize()
    return unpadded_password