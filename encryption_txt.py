# pyEncrypt

from Crypto.Cipher import AES
from Crypto.Hash import MD5
from binascii import a2b_hex, b2a_hex
import getpass
import os
import time

# 补全字符
def align_bytes(raw_str, isKey=False):
    # 如果str是密码，确保其长度是16
    if isKey is True:
        if len(raw_str) > 16:
            return raw_str[0:16]
        else:
            return align_bytes(raw_str)
    # 如果接受的字符串是明文或长度不足的密码，确保其长度为16的整数倍
    else:
        if len(raw_str)%16 != 0:
            zerocount = 16 - len(raw_str)%16
            raw_str = raw_str + b'\0'*zerocount
        return raw_str

# 补全字符
def align(raw_str, isKey=False):
    # 将str转换成bytearray
    raw_str = raw_str.encode('utf-8')
    # 如果str是密码，确保其长度是16
    if isKey is True:
        if len(raw_str) > 16:
            return raw_str[0:16]

    # 如果接受的字符串是明文或长度不足的密码，确保其长度为16的整数倍
    zerocount = 16 - len(raw_str)%16
    raw_str = raw_str + b'\0'*zerocount
    return raw_str

# CBC加密
def encrypt_cbc(raw_b, key_b):
    # 补全字符串
    raw_b_align = align_bytes(raw_b)
    key_b_align = align_bytes(key_b, True)
    # 初始化AES，引入初始向量
    AESCipher = AES.new(key_b_align, AES.MODE_CBC, b'1234567890123456')
    # 加密
    cipher = AESCipher.encrypt(raw_b_align)
    return b2a_hex(cipher)

# CBC解密
def decrypt_cbc(raw_str, key_str):
    # 补全字符串
    raw_str = align_bytes(raw_str)
    key_str = align_bytes(key_str, True)
    # 初始化AES
    AESCipher = AES.new(key_str, AES.MODE_CBC, b'1234567890123456')
    # 解密
    paint_b = AESCipher.decrypt(a2b_hex(raw_str))
    paint_b = paint_b.rstrip(b'\0')
    return paint_b



# # 尝试读取密文文件，如果密文文件不存在，则不进行解密，直接进入加密过程
# try:
#     fcipher = open('PWencrypt', 'r')
#     fpaint = open('PW.txt', 'w+')
#     # 读取密文文件
#     fcipherText = fcipher.read()
#     # 读取密文和哈希校验值
#     cipherText = fcipherText.split(',')[0]
#     painhash = fcipherText.split(',')[1]
#     # 用密码解密
#     paintText = decrypt_cbc(cipherText, key_str)
#     # 去除/0
#     paintText = paintText.rstrip('\0')
#     # 校验密码：计算本次解密后明文的哈希值
#     MD5hash = MD5.new()
#     MD5hash.update(paintText)
#     # 对比哈希值判断密码是否正确
#     if painhash != MD5hash.hexdigest():
#         print('Wrong Password!!!')
#     else:
#         fpaint.write(paintText)
#         fpaint.close()
#         fcipher.close()
#         # 打开PW.txt后脚本会被挂起
#         print("\'Don\'t Close!!!")
#         os.system('notepad PW.txt')
# except Exception as ex:
#     print('Something wrong when Decrypt!!!', ex)

# # 加密明文文件，写入密文文件并删除明文文件
# try:
#     fpaint = open('PW.txt', 'r')
#     # 读取明文文件
#     paintText = fpaint.read()
#     # 如果明文为空，则不执行加密
#     if len(paintText) > 0:
#         fcipher = open('PWencrypt', 'w')
#         # 加密
#         cipherText = encrypt_cbc(paintText, key_str)
#         # 计算明文哈希值
#         MD5hash = MD5.new()
#         MD5hash.update(paintText.encode('utf-8'))
#         # 将密文和校验码写入密文文件
#         cipherText = cipherText + ',' + MD5hash.hexdigest()
#         fcipher.write(cipherText)
#         fcipher.close()
#     fpaint.close()
#     # 删除明文文件
#     os.remove('PW.txt')
# except Exception as ex:
#     print('Something wrong when Encrypt!!!', ex)

# # 延时，方便看控制台的输出
# print('Quit after 3 seconds...')
# time.sleep(3)
#%% 输入密码
key_str = getpass.getpass('Password Please:')

#%% 加密
try:
    # 读取明文文件
    fpaint = open('PW.txt', 'r')
    paint_txt = fpaint.read()
    # 将str转换为bytearray
    key_b = key_str.encode('utf-8')
    paint_b = paint_txt.encode('utf-8')
    # 调用加密函数进行加密
    cipher_b = encrypt_cbc(paint_b, key_b)
    print(cipher_b, len(cipher_b), type(cipher_b))
    # 计算原文的MD5哈希码
    MD5hash = MD5.new()
    MD5hash.update(paint_b)
    paint_md5_b = MD5hash.hexdigest().encode('utf-8')
    print(paint_md5_b, len(paint_md5_b), type(paint_md5_b))
    # 合成密文
    cipher_b = cipher_b + b',' + paint_md5_b
    cipher = cipher_b.decode('utf-8')
    print(cipher_b, len(cipher_b), type(cipher_b))
    # 写入文件
    fcipher = open('PWencrypt', 'w')
    fcipher.write(cipher)
    fcipher.close()
    fpaint.close()
except Exception as ex:
    print(ex)

#%% 解密

try:
    # 读取密文文件
    fcipher = open('PWencrypt', 'r')
    ciper_txt = fcipher.read()
    ciper_str = ciper_txt.split(',')[0]
    paint_md5_record = ciper_txt.split(',')[1]
    # 将str转换为bytearray
    key_b = key_str.encode('utf-8')
    cipher_b = ciper_str.encode('utf-8')
    paint_md5_record_b = paint_md5_record.encode('utf-8')
    # 调用解密函数进行加密
    paint_b = decrypt_cbc(cipher_b, key_b)
    print(paint_b, len(paint_b), type(paint_b))
    # 计算解密内容的MD5哈希码
    MD5hash = MD5.new()
    MD5hash.update(paint_b)
    paint_md5_b = MD5hash.hexdigest().encode('utf-8')
    print(paint_md5_record_b)
    print(paint_md5_b, len(paint_md5_b), type(paint_md5_b))
    
    if paint_md5_b == paint_md5_record_b:
        print('文件解密成功')
    else:
        print('MD5码不匹配')
    # 将明文写入问价
    fpaint = open('PW-fake.txt', 'w')
    paint_txt = paint_b.decode('utf-8')
    fpaint.write(paint_txt)
    fpaint.close()
    fcipher.close()

except Exception as ex:
    print(ex)   


    
