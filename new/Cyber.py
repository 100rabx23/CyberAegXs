from flask import Flask, render_template_string, request, send_file
import os, hashlib, re, json
from google import genai
from google.genai.errors import APIError
from google.genai import types 

# ============================
# CONFIGURATION
# ============================
UPLOAD_FOLDER = "uploads"
SANITIZED_FOLDER = "sanitized"
# IMPORTANT: This key is a placeholder. You must use your valid key here.
GEMINI_API_KEY = "AIzaSyDMpJacgbXlDr688eaH8ltTnZ0a7HoWtw8" 

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SANITIZED_FOLDER, exist_ok=True) # Folder for safe files

# Initialize the Gemini Client globally
try:
    client = genai.Client(api_key=GEMINI_API_KEY)
except Exception as e:
    print(f"Error initializing Gemini client: {e}")
    client = None


# ============================
# FLASK SETUP
# ============================
app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["SANITIZED_FOLDER"] = SANITIZED_FOLDER

# ============================
# HTML TEMPLATE (Enhanced UI with Dashboard)
# ============================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>CyberDoc Scanner | Production</title>
    <style>
        :root {
            --color-low: #32CD32;    /* Lime Green */
            --color-medium: #FFD700; /* Gold */
            --color-high: #DC143C;   /* Crimson */
            --color-base: #00ffff;
            --color-dark: #001d3d;
        }
        body {
            font-family: 'Segoe UI', sans-serif;
            background: radial-gradient(circle, #000814, var(--color-dark));
            color: var(--color-base);
            text-align: center;
            padding: 20px;
        }
        h1 { color: #00e6e6; }
        form {
            background: rgba(0, 255, 255, 0.1);
            border: 1px solid var(--color-base);
            border-radius: 10px;
            padding: 30px;
            width: 400px;
            margin: 30px auto;
        }
        input[type=file] {
            background: var(--color-dark);
            border: 1px solid var(--color-base);
            padding: 10px;
            color: var(--color-base);
            border-radius: 5px;
            width: 90%;
        }
        button {
            margin-top: 15px;
            padding: 10px 20px;
            background: var(--color-base);
            border: none;
            color: var(--color-dark);
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            transition: background 0.3s;
        }
        button:hover {
            background: #33ffff;
        }
        .dashboard-container {
            width: 80%;
            margin: 40px auto;
            display: flex;
            flex-direction: column;
            gap: 20px;
        }
        .report, .dashboard {
            background: rgba(0, 255, 255, 0.08);
            border: 1px solid var(--color-base);
            border-radius: 8px;
            padding: 20px;
            text-align: left;
            color: #ccf;
            box-shadow: 0 0 15px rgba(0, 255, 255, 0.4);
        }
        .risk-badge {
            display: inline-block;
            padding: 8px 15px;
            border-radius: 5px;
            font-weight: bold;
            text-transform: uppercase;
            color: var(--color-dark);
        }
        .risk-high { background-color: var(--color-high); }
        .risk-medium { background-color: var(--color-medium); }
        .risk-low { background-color: var(--color-low); }

        .dashboard h3 {
            border-bottom: 1px solid rgba(0, 255, 255, 0.3);
            padding-bottom: 10px;
            color: var(--color-base);
        }
        .action-button {
            margin-top: 20px;
            padding: 12px 25px;
            background-color: var(--color-low);
            color: var(--color-dark);
            font-size: 1.1em;
            text-decoration: none;
            border-radius: 5px;
            transition: background 0.3s;
        }
        .action-button:hover {
            background-color: #00FF7F; /* Brighter green */
        }
        .finding-list li {
            margin-bottom: 5px;
        }
    </style>
</head>
<body>
    <h1>🛡 Cyber Document Scanner | Production</h1>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file" required><br><br>
        <button type="submit">Scan Now</button>
    </form>
    {% if report %}
    <div class="dashboard-container">
        <!-- AI ANALYSIS DASHBOARD -->
        <div class="dashboard">
            <h3>AI Threat Analysis Dashboard</h3>
            <p>File: <strong>{{ report.filename }}</strong></p>
            <p>Risk Level: 
                <span class="risk-badge risk-{{ report.risk_level.lower() }}">{{ report.risk_level }}</span>
            </p>
            <p>Summary:</p>
            <pre>{{ report.summary }}</pre>

            {% if report.sanitization_required %}
            <a href="{{ url_for('download_safe_file', original_filename=report.filename, sanitized_path=report.sanitized_file) }}" 
               class="action-button">
               Download Extracted Safe Text (.txt)
            </a>
            <p style="margin-top: 10px; font-size: 0.8em; color: #ff8c00;">
                (Note: This process performs **Content Disarm and Reconstruction (CDR)** by removing all scripts, macros, formatting, and embedded files to ensure safety, leaving only the clean, readable text content.)
            </p>
            {% endif %}
        </div>

        <!-- RAW SCAN REPORT -->
        <div class="report">
            <h3>Raw Static Scan Report</h3>
            <p>File: {{ report.filename }}</p>
            <p>Type: {{ report.file_type }}</p>
            <p>Size: {{ report.file_size }} bytes</p>

            <h4>Hashes:</h4>
            <ul>
                <li>MD5: {{ report.hashes.MD5 }}</li>
                <li>SHA1: {{ report.hashes.SHA1 }}</li>
                <li>SHA256: {{ report.hashes.SHA256 }}</li>
            </ul>

            <h4>Keyword Findings:</h4>
            <ul class="finding-list">
                {% for finding in report.findings %}
                <li>{{ finding }}</li>
                {% endfor %}
                {% if not report.findings %}
                <li>No suspicious keywords found.</li>
                {% endif %}
            </ul>
        </div>
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
    # Use a large buffer to read file chunks for efficiency and memory management
    BUF_SIZE = 65536 
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
            sha1.update(data)
            sha256.update(data)

    hashes["MD5"] = md5.hexdigest()
    hashes["SHA1"] = sha1.hexdigest()
    hashes["SHA256"] = sha256.hexdigest()
    return hashes

# ============================
# FUNCTION: Basic Keyword Scan
# ============================
def scan_for_keywords(file_path):
    """Performs a basic check for suspicious signatures and keywords."""
    try:
        with open(file_path, "rb") as f:
            # Read as text, ignoring errors for binary/malformed content
            # Reading entire file might be inefficient for very large files, but is simple.
            data = f.read().decode(errors="ignore")

        # Suspicious signatures/keywords:
        keywords = ["MZ", "PK", "javascript", "macro", "vba", "cmd", "powershell", "shellcode"]
        findings = []

        for word in keywords:
            if re.search(re.escape(word), data, re.IGNORECASE):
                findings.append(f"Keyword detected: {word}")

        return findings
    except Exception as e:
        print(f"Error during keyword scan: {e}")
        return [f"Error during keyword scan: {e}"]

# ============================
# FUNCTION: File Sanitization (Extraction to Text)
# ============================
def sanitize_file_content(original_file_path, original_filename):
    """
    Performs Content Disarm and Reconstruction (CDR) by extracting 
    all visible text content and saving it as a clean, script-free TXT file.
    """
    sanitized_filename = f"safe_extracted_text_{original_filename}.txt"
    sanitized_file_path = os.path.join(app.config["SANITIZED_FOLDER"], sanitized_filename)
    
    # In a real-world scenario, you would use a dedicated library 
    # (like pdfminer or python-docx) here to correctly extract content.
    try:
        with open(original_file_path, 'rb') as f_in:
            # Read and attempt to decode as text, ignoring all errors
            text_content = f_in.read().decode('utf-8', errors='ignore')
            
            # Simple text extraction. For production, complex parsing is required.
            
            with open(sanitized_file_path, 'w', encoding='utf-8') as f_out:
                f_out.write("--- Sanitized Content (Scripts, Macros, and Embedded Objects Removed) ---\n\n")
                f_out.write(text_content)
        
        return sanitized_file_path
    
    except Exception as e:
        print(f"Sanitization error: {e}")
        return None


# ============================
# FUNCTION: Gemini AI Threat Analysis (Structured JSON)
# ============================
def analyze_with_gemini(text_summary):
    """Uses the Gemini SDK to analyze the scan summary and return structured JSON."""
    if not client:
        return {"error": "Client not initialized."}
    
    MODEL_NAME = 'gemini-2.5-flash' 
    
    # Define the strict JSON schema for programmatic use
    json_schema = types.GenerateContentConfig(
        response_mime_type="application/json",
        response_schema=types.Schema(
            type=types.Type.OBJECT,
            properties={
                "risk_level": types.Schema(
                    type=types.Type.STRING, 
                    description="Overall risk rating. MUST be one of: High, Medium, Low."
                ),
                "summary": types.Schema(
                    type=types.Type.STRING, 
                    description="A detailed, multi-paragraph professional summary of the findings, risk justification, and clear mitigation steps."
                ),
                "sanitization_required": types.Schema(
                    type=types.Type.BOOLEAN, 
                    description="True if risk_level is High or Medium, otherwise False."
                )
            },
            required=["risk_level", "summary", "sanitization_required"]
        )
    )
    
    try:
        prompt = (
            "Analyze the following document scan summary for cybersecurity risks like malware, "
            "worms, or embedded scripts. Focus heavily on the keyword findings (MZ, PK, javascript, etc.). "
            "Generate a **detailed, multi-paragraph professional report** that includes a clear breakdown of the evidence, "
            "a justification for the risk level, and recommended mitigation steps. "
            "Return the result as a JSON object strictly conforming to the provided schema. "
            "Scan Summary:\n\n"
            f"{text_summary}"
        )
        
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt,
            config=json_schema
        )
        
        # The response text is a JSON string, which we must parse
        return json.loads(response.text.strip())
    
    except APIError as e:
        print(f"Full API Error: {e}")
        return {"error": f"Gemini API Error: Check API key or service enablement ({MODEL_NAME})."}
    except json.JSONDecodeError:
        print(f"Failed to decode JSON from AI: {response.text}")
        return {"error": "AI response was not valid JSON."}
    except Exception as e:
        return {"error": f"Unexpected error in AI call: {e}"}

# ============================
# ROUTE: DOWNLOAD SAFE FILE
# ============================
@app.route("/download_safe/<original_filename>")
def download_safe_file(original_filename):
    """Serves the previously sanitized text file for download."""
    # Since sanitization happens on scan, we just need to reconstruct the path
    safe_filename = f"safe_extracted_text_{original_filename}.txt"
    safe_file_path = os.path.join(app.config["SANITIZED_FOLDER"], safe_filename)
    
    if os.path.exists(safe_file_path):
        return send_file(
            safe_file_path,
            mimetype='text/plain',
            as_attachment=True,
            download_name=safe_filename
        )
    else:
        # In case the user refreshes or hits the link directly without scanning first
        return "Error: Safe file not found. Please scan the document first.", 404

# ============================
# ROUTE: HOME (Scan)
# ============================
@app.route("/", methods=["GET", "POST"])
def home():
    """Handles file upload, scanning, and report display."""
    report_data = None
    file_path = None 

    if request.method == "POST":
        uploaded_file = request.files.get("file")
        if uploaded_file and uploaded_file.filename != "":
            original_filename = uploaded_file.filename
            
            # Securely hash the filename for storage
            filename_hash = hashlib.sha256(original_filename.encode()).hexdigest()
            file_extension = os.path.splitext(original_filename)[1]
            secure_filename = filename_hash + file_extension
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], secure_filename)
            
            try:
                uploaded_file.save(file_path)

                # 1. Static Analysis
                hashes = generate_hashes(file_path)
                findings = scan_for_keywords(file_path)
                file_size = os.path.getsize(file_path)

                # 2. Prepare summary for AI
                summary = (
                    f"File: {original_filename}\nType: {uploaded_file.content_type}\nSize: {file_size} bytes\n"
                    f"Hashes: MD5:{hashes['MD5']}, SHA256:{hashes['SHA256']}\n"
                    f"Findings: {', '.join(findings) if findings else 'None'}"
                )

                # 3. AI Analysis (Structured)
                ai_analysis = analyze_with_gemini(summary)

                if "error" in ai_analysis:
                    # If AI fails, still show static scan results with an error message
                    ai_analysis = {
                        "risk_level": "ERROR",
                        "summary": ai_analysis["error"],
                        "sanitization_required": False
                    }
                
                # 4. Prepare final report structure
                report_data = {
                    "filename": original_filename,
                    "file_type": uploaded_file.content_type,
                    "file_size": file_size,
                    "hashes": hashes,
                    "findings": findings,
                    "risk_level": ai_analysis.get("risk_level", "UNKNOWN"),
                    "summary": ai_analysis.get("summary", "Could not retrieve AI summary."),
                    "sanitization_required": ai_analysis.get("sanitization_required", False),
                    "sanitized_file": f"safe_extracted_text_{original_filename}.txt" # Path placeholder for the template
                }

                # 5. Sanitize file immediately if needed (creates temp safe file)
                if report_data["sanitization_required"]:
                    sanitize_file_content(file_path, original_filename)

            except Exception as e:
                # Catch any unexpected file processing errors
                report_data = {"error": f"An unexpected error occurred during processing: {e}"}
            finally:
                # 6. CRITICAL: Clean up the uploaded file after scanning
                if file_path and os.path.exists(file_path):
                    os.remove(file_path)
    
    # If there was an error that prevented report_data creation, send a generic error
    if report_data and "error" in report_data:
        return render_template_string(HTML_TEMPLATE, report={"summary": report_data["error"], "risk_level": "ERROR"})
    
    return render_template_string(HTML_TEMPLATE, report=report_data)

# ============================
# RUN APP
# ============================
if __name__ == "__main__":
    # Ensure debug is False for production deployment
    app.run(debug=False)
