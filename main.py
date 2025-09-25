import base64
import hashlib
import hmac
import time
import uuid
from datetime import datetime
from urllib.parse import quote

import requests


class HMACConfig:
    """HMAC配置类"""
    def __init__(self, url, key, secret, path="/transform", method="POST"):
        self.url = url
        self.key = key
        self.secret = secret
        self.path = path
        self.method = method
        self.accept = "application/json; charset=utf-8"
        self.content_type = "application/x-www-form-urlencoded; charset=utf-8"
        self.nonce = str(uuid.uuid4())
        self.timestamp = str(int(time.time() * 1000))
        self.date = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
        
    def get_custom_headers(self):
        return {
            "x-ca-key": self.key,
            "x-ca-nonce": self.nonce,
            "x-ca-signature-method": "HmacSHA256",
            "x-ca-timestamp": self.timestamp
        }


def generate_signature(method, accept, content_type, date, path, query_params, form_params, custom_headers, secret):
    # Step 1: Build the string to sign
    string_to_sign = []

    # HTTP method
    string_to_sign.append(method.upper())

    # Accept
    string_to_sign.append(accept if accept else "")

    # Content-MD5 (for non-form bodies; this is form data so keep empty)
    string_to_sign.append("")

    # Content-Type
    string_to_sign.append(content_type if content_type else "")

    # Date
    string_to_sign.append(date if date else "")

    # Custom headers (alphabetically sorted) - only include signature-related headers
    signature_headers = {}
    for key, value in custom_headers.items():
        if key.startswith('x-ca-') and key not in ['x-ca-signature', 'x-ca-signature-headers']:
            signature_headers[key] = value

    sorted_headers = sorted(signature_headers.items(), key=lambda x: x[0])
    for key, value in sorted_headers:
        string_to_sign.append(f"{key}:{value}")

    # Path and parameters (merge query and form params, then sort)
    all_params = {**query_params, **form_params}
    sorted_params = sorted(all_params.items(), key=lambda x: x[0])
    if sorted_params:
        # URL encode parameter values
        encoded_params = []
        for k, v in sorted_params:
            encoded_key = quote(str(k), safe='')
            encoded_value = quote(str(v), safe='')
            encoded_params.append(f"{encoded_key}={encoded_value}")
        param_string = f"{path}?" + "&".join(encoded_params)
    else:
        param_string = path
    string_to_sign.append(param_string)

    # Join the string to sign
    string_to_sign = "\n".join(string_to_sign)

    # Step 2: Generate HMAC-SHA256 signature
    secret_bytes = secret.encode('utf-8')
    string_to_sign_bytes = string_to_sign.encode('utf-8')
    hmac_obj = hmac.new(secret_bytes, string_to_sign_bytes, hashlib.sha256)
    signature = base64.b64encode(hmac_obj.digest()).decode('utf-8')

    return signature, string_to_sign


def main(test_mode=False):
    # 配置HMAC参数
    config = HMACConfig(
        url="https://apidev-extgw.clp.com.hk/transform",
        key="appKey-example-1",
        secret="appSecret-example-1",
        path="/transform",
        method="POST"
    )
    
    # 请求参数
    query_params = {}
    form_params = {"username": "xiaoming", "password": "123456789"}
    custom_headers = config.get_custom_headers()

    # Generate signature
    signature, string_to_sign = generate_signature(
        config.method, config.accept, config.content_type, config.date, 
        config.path, query_params, form_params, custom_headers, config.secret
    )

    # Build request headers
    # Calculate the list of headers included in signature
    signature_headers = [key for key in custom_headers.keys()
                         if key.startswith('x-ca-') and key not in ['x-ca-signature', 'x-ca-signature-headers']]

    # Construct request headers
    headers = {"Accept": config.accept, "Content-Type": config.content_type, "Date": config.date,
               "x-ca-key": config.key, "x-ca-nonce": config.nonce, "x-ca-signature-method": "HmacSHA256",
               "x-ca-timestamp": config.timestamp, "x-ca-signature": signature,
               "x-ca-signature-headers": ",".join(sorted(signature_headers)),
               "Authorization": f"HMAC-SHA256 {config.key}:{signature}"}

    # Try adding an Authorization header format
    # Format 1: HMAC-SHA256 key:signature

    # Build and print equivalent curl command
    query_string = "&".join(f"{k}={v}" for k, v in query_params.items())
    url_with_query = f"{config.url}?{query_string}" if query_string else config.url
    form_string = "&".join(f"{k}={v}" for k, v in form_params.items())

    curl_parts = [
        "curl",
        f"-X {config.method}",
        f"\"{url_with_query}\"",
    ]

    for hk, hv in headers.items():
        curl_parts.append(f"-H \"{hk}: {hv}\"")

    if form_string:
        curl_parts.append(f"--data \"{form_string}\"")

    curl_cmd = " ".join(curl_parts)
    # PowerShell often aliases `curl` to Invoke-WebRequest. Use curl.exe to force the real curl binary.
    curl_cmd_powershell = curl_cmd.replace("curl ", "curl.exe ", 1)

    # Output results
    print("=== HMAC Signature Test ===")
    print(f"URL: {config.url}")
    print(f"Method: {config.method}")
    print(f"Path: {config.path}")
    print(f"Query Params: {query_params}")
    print(f"Form Params: {form_params}")
    print(f"\nStringToSign:")
    print(repr(string_to_sign))
    print(f"\nSignature: {signature}")
    print(f"\nRequest Headers:")
    for key, value in headers.items():
        print(f"  {key}: {value}")
    print(f"\nEquivalent curl (bash/zsh):")
    print(curl_cmd)
    print(f"\nEquivalent curl (Windows PowerShell):")
    print(curl_cmd_powershell)
    
    if not test_mode:
        # Send request
        try:
            response = requests.post(config.url, headers=headers, params=query_params, data=form_params)
            print(f"\nResponse code: {response.status_code}")
            print(f"Response body: {response.text}")
            print(f"\nResponse headers:")
            for key, value in response.headers.items():
                print(f"  {key}: {value}")

            if response.status_code != 200:
                error_msg = response.headers.get("X-Ca-Error-Message", "No error message")
                print(f"\nError message: {error_msg}")
                if "StringToSign" in error_msg:
                    print("Server StringToSign:", error_msg)
                
                # 提供调试建议
        except requests.exceptions.ConnectionError as e:
            print(f"\nconnection error: {e}")
        except Exception as e:
            print(f"\nrequest error: {e}")



if __name__ == "__main__":
    main()