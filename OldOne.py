from flask import Flask, render_template_string, request
import os, hashlib, re
from google import genai
from google.genai.errors import APIError 

# ============================
# CONFIGURATION
# ============================
UPLOAD_FOLDER = "uploads"
# IMPORTANT: This key is a placeholder. You must use your valid key here.
GEMINI_API_KEY = "AIzaSyDMpJacgbXlDr688eaH8ltTnZ0a7HoWtw8" 
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize the Gemini Client globally
try:
    # Ensure client initialization is attempted even with a placeholder key
    client = genai.Client(api_key=GEMINI_API_KEY)
except Exception as e:
    print(f"Error initializing Gemini client: {e}")
    client = None


# ============================
# FLASK SETUP
# ============================
app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# ============================
# HTML TEMPLATE (Simple UI)
# ============================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>CyberDoc Scanner</title>
    <style>
        body {
            font-family: 'Segoe UI', sans-serif;
            background: radial-gradient(circle, #000814, #001d3d);
            color: #00ffff;
            text-align: center;
            padding: 40px;
        }
        h1 { color: #00e6e6; }
        form {
            background: rgba(0, 255, 255, 0.1);
            border: 1px solid #00ffff;
            border-radius: 10px;
            padding: 30px;
            width: 400px;
            margin: 30px auto;
        }
        input[type=file] {
            background: #001d3d;
            border: 1px solid #00ffff;
            padding: 10px;
            color: #00ffff;
            border-radius: 5px;
            width: 90%;
        }
        button {
            margin-top: 15px;
            padding: 10px 20px;
            background: #00ffff;
            border: none;
            color: #001d3d;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            transition: background 0.3s;
        }
        button:hover {
            background: #33ffff;
        }
        .report {
            background: rgba(0, 255, 255, 0.08);
            border: 1px solid #00ffff;
            border-radius: 8px;
            margin-top: 25px;
            padding: 20px;
            text-align: left;
            width: 70%;
            margin-left: auto;
            margin-right: auto;
            color: #ccf;
            white-space: pre-wrap;
            box-shadow: 0 0 15px rgba(0, 255, 255, 0.4);
        }
    </style>
</head>
<body>
    <h1>🛡 Cyber Document Scanner</h1>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file" required><br><br>
        <button type="submit">Scan Now</button>
    </form>
    {% if report %}
    <div class="report">
        <h3>Scan Report</h3>
        <pre>{{ report }}</pre>
    </div>
    {% endif %}
</body>
</html>
"""

# ============================
# FUNCTION: Generate File Hashes
# ============================
def generate_hashes(file_path):
    """Computes MD5, SHA1, and SHA256 hashes for a given file."""
    hashes = {}
    with open(file_path, "rb") as f:
        data = f.read()
        hashes["MD5"] = hashlib.md5(data).hexdigest()
        hashes["SHA1"] = hashlib.sha1(data).hexdigest()
        hashes["SHA256"] = hashlib.sha256(data).hexdigest()
    return hashes

# ============================
# FUNCTION: Basic Keyword Scan
# ============================
def scan_for_keywords(file_path):
    """Performs a basic check for suspicious signatures and keywords."""
    try:
        with open(file_path, "rb") as f:
            data = f.read().decode(errors="ignore")

        keywords = ["MZ", "PK", "javascript", "macro", "vba", "cmd", "powershell", "shellcode"]
        findings = []

        for word in keywords:
            if re.search(re.escape(word), data, re.IGNORECASE):
                findings.append(f"Keyword detected: {word}")

        return findings
    except Exception as e:
        return [f"Error during keyword scan: {e}"]

# ============================
# FUNCTION: Gemini AI Threat Analysis (SDK Implementation)
# ============================
def analyze_with_gemini(text_summary):
    """Uses the Gemini SDK to analyze the scan summary for threat assessment."""
    if not client:
        return "❌ Gemini client not initialized. Please ensure GEMINI_API_KEY is correctly set."
    
    # Using gemini-2.5-flash, the current recommended default model for best performance/cost.
    MODEL_NAME = 'gemini-2.5-flash' 
    
    try:
        prompt = (
            "Analyze the following document scan summary for cybersecurity risks like malware, "
            "worms, or embedded scripts. Focus on the keyword findings. Write a short, "
            "human-readable report that includes an overall risk rating (Low, Medium, or High). "
            "Scan Summary:\n\n"
            f"{text_summary}"
        )
        
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt
        )
        
        return response.text.strip()
    
    except APIError as e:
        # Crucial Error Reporting for the User, confirming the key is the issue.
        error_message = (
            f"❌ Gemini API Error (Model: {MODEL_NAME}): The API returned 404 NOT_FOUND. "
            f"Since you generated the key on AI Studio, this strongly indicates the API key is "
            f"either invalid, expired, or the service (Generative Language API) is not enabled "
            f"for the corresponding Google Cloud project associated with your key. "
            f"Please verify the key and service enablement."
        )
        print(f"Full API Error: {e}")
        return error_message
    except Exception as e:
        return f"❌ Unexpected error (SDK): {e}"

# ============================
# ROUTE: HOME
# ============================
@app.route("/", methods=["GET", "POST"])
def home():
    """Handles file upload, scanning, and report display."""
    report = ""
    file_path = None 

    if request.method == "POST":
        uploaded_file = request.files.get("file")
        if uploaded_file and uploaded_file.filename != "":
            # Using hashing for secure filename storage
            filename_hash = hashlib.sha256(uploaded_file.filename.encode()).hexdigest()
            file_extension = os.path.splitext(uploaded_file.filename)[1]
            secure_filename = filename_hash + file_extension
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], secure_filename)
            
            try:
                uploaded_file.save(file_path)

                hashes = generate_hashes(file_path)
                findings = scan_for_keywords(file_path)
                file_size = os.path.getsize(file_path)

                summary = f"File: {uploaded_file.filename}\nType: {uploaded_file.content_type}\nSize: {file_size} bytes\n\nHashes:\n"
                for k, v in hashes.items():
                    summary += f"  {k}: {v}\n"

                summary += "\nFindings:\n" 
                summary += "\n".join([f"  - {f}" for f in findings]) if findings else "  - No suspicious keywords found."

                ai_analysis = analyze_with_gemini(summary)

                report = summary + "\n\n" + ("="*20) + "\nAI Threat Analysis:\n" + ai_analysis
            
            except Exception as e:
                report = f"An unexpected error occurred during file processing: {e}"
            finally:
                # CRITICAL: Clean up the uploaded file after scanning
                if file_path and os.path.exists(file_path):
                    os.remove(file_path)

    return render_template_string(HTML_TEMPLATE, report=report)

# ============================
# RUN APP
# ============================
if __name__ == "__main__":
    app.run(debug=False)

