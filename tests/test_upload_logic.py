import requests
import os

BASE_URL = "http://localhost:8000"
TEST_FILE = "test_upload.txt"

def test_upload():
    # Create a dummy file
    content = "This is a test CTI report content."
    with open(TEST_FILE, "w") as f:
        f.write(content)

    try:
        # Upload
        with open(TEST_FILE, "rb") as f:
            files = {"file": (TEST_FILE, f, "text/plain")}
            response = requests.post(f"{BASE_URL}/files/upload", files=files)
            
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        if response.status_code == 200:
            data = response.json()
            if data["content"] == content:
                print("SUCCESS: Content match!")
            else:
                print("FAILURE: Content mismatch!")
        else:
            print("FAILURE: Upload status not 200")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        if os.path.exists(TEST_FILE):
            os.remove(TEST_FILE)

if __name__ == "__main__":
    test_upload()
