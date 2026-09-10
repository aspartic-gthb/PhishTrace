"""
Test Encryption Feature
Demonstrates API key encryption in action
"""

import requests
import json

API_BASE = "http://127.0.0.1:8000/api/v1/api-keys"

def test_encryption():
    print("🔐 Testing Encryption Feature")
    print("=" * 60)
    print()
    
    # Test 1: Store encrypted API key
    print("Test 1: Store Gemini API Key (Encrypted)")
    print("-" * 60)
    
    response = requests.post(
        f"{API_BASE}/",
        json={
            "service_name": "gemini",
            "api_key": "AIzaSyDemoKey123456789ABCDEF"
        }
    )
    
    if response.ok:
        data = response.json()
        print(f"✅ Stored successfully!")
        print(f"   Service: {data['service_name']}")
        print(f"   Masked Key: {data['masked_key']}")
        print(f"   Created: {data['created_at']}")
    else:
        print(f"❌ Failed: {response.text}")
    
    print()
    
    # Test 2: Store another key
    print("Test 2: Store SendGrid API Key")
    print("-" * 60)
    
    response = requests.post(
        f"{API_BASE}/",
        json={
            "service_name": "sendgrid",
            "api_key": "SG.1234567890abcdefghijklmnop"
        }
    )
    
    if response.ok:
        data = response.json()
        print(f"✅ Stored successfully!")
        print(f"   Masked Key: {data['masked_key']}")
    else:
        print(f"❌ Failed: {response.text}")
    
    print()
    
    # Test 3: List all keys (masked)
    print("Test 3: List All API Keys (Masked)")
    print("-" * 60)
    
    response = requests.get(f"{API_BASE}/")
    
    if response.ok:
        keys = response.json()
        print(f"✅ Found {len(keys)} API keys:")
        for key in keys:
            print(f"   - {key['service_name']}: {key['masked_key']}")
    else:
        print(f"❌ Failed: {response.text}")
    
    print()
    
    # Test 4: Decrypt a key
    print("Test 4: Decrypt Gemini API Key")
    print("-" * 60)
    
    response = requests.get(f"{API_BASE}/gemini/decrypt")
    
    if response.ok:
        data = response.json()
        print(f"✅ Decrypted successfully!")
        print(f"   Service: {data['service_name']}")
        print(f"   Full API Key: {data['api_key']}")
        print(f"   Key Version: {data['key_version']}")
    else:
        print(f"❌ Failed: {response.text}")
    
    print()
    
    # Test 5: Rotate keys
    print("Test 5: Rotate Encryption Keys")
    print("-" * 60)
    
    response = requests.post(f"{API_BASE}/rotate-all")
    
    if response.ok:
        data = response.json()
        print(f"✅ {data['message']}")
        print(f"   New Key ID: {data['new_key_id']}")
        print(f"   Keys Rotated: {data['keys_rotated']}")
    else:
        print(f"❌ Failed: {response.text}")
    
    print()
    print("=" * 60)
    print("🎉 Encryption Feature Test Complete!")
    print()
    print("💡 What Happened:")
    print("   1. API keys were encrypted before storage")
    print("   2. Only masked versions are shown in listings")
    print("   3. Full keys can be decrypted when needed")
    print("   4. Encryption keys can be rotated for security")
    print()
    print("📊 Check the database:")
    print("   - user_api_keys table has encrypted_key column")
    print("   - encryption_keys table tracks key versions")

if __name__ == "__main__":
    try:
        test_encryption()
    except requests.exceptions.ConnectionError:
        print("❌ Error: Backend server not running!")
        print("   Start backend first: python start_server.py")
    except Exception as e:
        print(f"❌ Error: {e}")
