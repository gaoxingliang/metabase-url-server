#!/usr/bin/env python3
"""
测试新的HMAC签名认证机制
"""

import hashlib
import hmac
import base64
import time
import uuid
import requests
import json

# 测试配置
APP_KEY = "dev_app_key_12345"
APP_SECRET = "dev_app_secret_67890"
API_ENDPOINT = "http://localhost:7070/api/metabase/urls"

def test_signature_generation():
    """测试签名生成"""
    print("=== 测试签名生成 ===")
    
    http_method = "POST"
    uri_path = "/api/metabase/urls"
    timestamp = str(int(time.time()))
    nonce = str(uuid.uuid4())
    request_body = '{"resource": "dashboard", "id": 123}'
    
    # 构建待签名字符串
    string_to_sign = (
        f"{http_method}\n"
        f"{uri_path}\n"
        f"{timestamp}\n"
        f"{nonce}\n"
        f"{request_body}"
    )

    # POST
    # /api/metabase/urls
    # 1755825946
    # a438c1d4-18c2-4259-8c96-91028d904f8a
    # {"resource": "dashboard", "id": 123}

    print(f"待签名字符串:\n{string_to_sign}")
    
    # 生成签名
    signature = hmac.new(
        APP_SECRET.encode('utf-8'),
        string_to_sign.encode('utf-8'),
        hashlib.sha256
    ).digest()
    
    encoded_signature = base64.b64encode(signature).decode('utf-8')
    print(f"生成的签名: {encoded_signature}")
    
    return {
        'timestamp': timestamp,
        'nonce': nonce,
        'signature': encoded_signature,
        'request_body': request_body
    }

def test_api_call():
    """测试API调用"""
    print("\n=== 测试API调用 ===")
    
    # 生成认证信息
    auth_info = test_signature_generation()
    
    # 准备请求数据
    request_data = {
        "resource": "dashboard",
        "id": 123
    }
    
    # 设置请求头
    headers = {
        'Content-Type': 'application/json',
        'X-AppKey': APP_KEY,
        'X-Timestamp': auth_info['timestamp'],
        'X-Nonce': auth_info['nonce'],
        'Authorization': f'Signature {auth_info["signature"]}'
    }
    
    print(f"请求头: {json.dumps(headers, indent=2)}")
    print(f"请求数据: {json.dumps(request_data, indent=2)}")
    
    try:
        # 发送请求
        response = requests.post(API_ENDPOINT, json=request_data, headers=headers)
        
        print(f"\n响应状态码: {response.status_code}")
        print(f"响应头: {dict(response.headers)}")
        
        if response.status_code == 200:
            print("✅ API调用成功!")
            print(f"响应数据: {json.dumps(response.json(), indent=2)}")
        else:
            print("❌ API调用失败!")
            print(f"错误响应: {response.text}")
            
    except requests.exceptions.ConnectionError:
        print("❌ 连接失败 - 请确保服务器正在运行")
    except Exception as e:
        print(f"❌ 请求失败: {e}")

def test_invalid_signature():
    """测试无效签名"""
    print("\n=== 测试无效签名 ===")
    
    # 使用错误的密钥生成签名
    wrong_secret = "wrong_secret"
    http_method = "POST"
    uri_path = "/api/metabase/urls"
    timestamp = str(int(time.time()))
    nonce = str(uuid.uuid4())
    request_body = '{"resource": "dashboard", "id": 123}'
    
    string_to_sign = (
        f"{http_method}\n"
        f"{uri_path}\n"
        f"{timestamp}\n"
        f"{nonce}\n"
        f"{request_body}"
    )
    
    # 使用错误密钥生成签名
    wrong_signature = hmac.new(
        wrong_secret.encode('utf-8'),
        string_to_sign.encode('utf-8'),
        hashlib.sha256
    ).digest()
    
    encoded_wrong_signature = base64.b64encode(wrong_signature).decode('utf-8')
    
    headers = {
        'Content-Type': 'application/json',
        'X-AppKey': APP_KEY,
        'X-Timestamp': timestamp,
        'X-Nonce': nonce,
        'Authorization': f'Signature {encoded_wrong_signature}'
    }
    
    request_data = {"resource": "dashboard", "id": 123}
    
    try:
        response = requests.post(API_ENDPOINT, json=request_data, headers=headers)
        print(f"响应状态码: {response.status_code}")
        if response.status_code == 401:
            print("✅ 正确拒绝了无效签名")
        else:
            print("❌ 应该拒绝无效签名")
        print(f"响应: {response.text}")
    except Exception as e:
        print(f"请求失败: {e}")

def main():
    """主测试函数"""
    print("Metabase URL Server - HMAC认证测试")
    print("=" * 50)
    
    # 测试签名生成
    test_signature_generation()
    
    # 测试API调用
    test_api_call()
    
    # 测试无效签名
    test_invalid_signature()
    
    print("\n测试完成!")

if __name__ == "__main__":
    main()
