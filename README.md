HEAD
# Vajrax-X
# VAJRA-X

Unified Multi-Domain Situational Awareness Platform for
Border Security, Disaster Response,
Environmental Monitoring, and Satellite Analytics.

## 📦 Project Structure

```
vajrax/
├── app.py                  # Main Flask application
├── run.py                  # Local development runner
├── wsgi.py                 # WSGI entry point
├── pythonanywhere_wsgi.py  # PythonAnywhere WSGI config
├── requirements.txt        # Python dependencies
├── database/
│   ├── __init__.py
│   └── db.py               # SQLite database
├── modules/
│   ├── __init__.py
│   └── detection_engine.py # YOLOv8 AI engine
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── dashboard.html
│   ├── module.html
│   └── error.html
└── static/
    ├── uploads/            # Uploaded files
    └── processed/          # Processed outputs
```

---

## 📐 Architecture Naming

```text
VAJRA-X Core
├── Satellite Intelligence
├── Border Monitoring
├── Disaster Response
├── Forest Intelligence
├── Detection Engine
└── Vajra Copilot
```

---

## 🖥️ LOCAL SETUP (Windows)

### Step 1: Create Virtual Environment
```powershell
python -m venv .venv
.venv\Scripts\activate
```

### Step 2: Install Dependencies
```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Run the App
```powershell
python run.py
```
Open: http://127.0.0.1:5000

---

## ☁️ PYTHONANYWHERE DEPLOYMENT

### Step 1: Upload Files
- Zip the `vajrax` folder
- In PythonAnywhere Files tab → Upload zip → Extract to `/home/YOUR_USERNAME/vajrax`

### Step 2: Create Virtualenv in PythonAnywhere Bash
```bash
cd ~
python3.10 -m venv ~/.virtualenvs/vajra_venv
source ~/.virtualenvs/vajra_venv/bin/activate
cd vajrax
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Configure Web App
1. Go to **Web** tab → **Add new web app**
2. Choose **Manual configuration** → Python 3.10
3. Set **Source code:** `/home/YOUR_USERNAME/vajrax`
4. Set **Working directory:** `/home/YOUR_USERNAME/vajrax`
5. Set **Virtualenv:** `/home/YOUR_USERNAME/.virtualenvs/vajra_venv`

### Step 4: WSGI Configuration
In the **WSGI configuration file** (click the link in Web tab), replace everything with:

```python
import sys, os
project_home = '/home/YOUR_USERNAME/vajrax'
if project_home not in sys.path:
    sys.path.insert(0, project_home)
os.chdir(project_home)

activate_this = '/home/YOUR_USERNAME/.virtualenvs/vajra_venv/bin/activate_this.py'
with open(activate_this) as f:
    exec(f.read(), {'__file__': activate_this})

from app import create_app
application = create_app()
```

### Step 5: Static Files
In Web tab → **Static files**:
| URL          | Directory                                    |
|--------------|----------------------------------------------|
| `/static/`   | `/home/YOUR_USERNAME/vajrax/static/`     |

### Step 6: Reload & Open
Click **Reload** → Visit `https://YOUR_USERNAME.pythonanywhere.com`

---

## 🧩 MODULE DESCRIPTIONS

| Module | Purpose | Targets |
|--------|---------|---------|
| Border Security | Perimeter & intrusion detection | person, car, truck, motorcycle |
| Disaster Detection | Flood/fire/smoke monitoring | person, car, boat, fire hydrant |
| Railway Safety | Track intrusion prevention | person, bicycle, motorcycle, car |
| Smart City | Urban surveillance | person, car, bicycle, traffic light |
| Mining Activity | Site safety monitoring | person, truck, backpack |
| Forest Monitoring | Wildlife & fire detection | person, car, bear, bird |

---

## 🎥 TWO CAMERA MODES

### Browser Webcam (WebRTC)
- Works on PythonAnywhere (no server hardware needed)
- Click **"BROWSER WEBCAM"** button
- Browser captures frames → sends to server → YOLO processes → shows annotated result

### Server Camera
- Requires physical camera connected to server
- Works for local deployment
- Click **"SERVER CAMERA"** button
- Falls back with error message if camera not found

---

## 📂 UPLOAD MODE
- Drag & drop or click to browse
- Supports: JPG, PNG, BMP, WEBP, MP4, AVI, MOV, MKV
- Max size: 100MB
- Results shown with bounding boxes + threat levels

---

## ⚡ REAL-TIME FEATURES
- Live detection feed via SocketIO
- Auto-updating detection table
- Threat level alerts (toast notifications)
- System health indicators

---

## 🗃️ DATABASE
- SQLite file: `database/vajrax.db`
- Auto-created on first run
- Tables: users, detections, logs

---

## 🛠️ TROUBLESHOOTING

**Problem:** `ultralytics` or `torch` install fails on PythonAnywhere  
**Solution:** YOLOv8 nano requires minimal torch. Use CPU version:
```bash
pip install torch torchvision --index-url https://download.pytorch.org/whl/cpu
pip install ultralytics
```

**Problem:** Camera not working on PythonAnywhere  
**Solution:** PythonAnywhere is a cloud server — use **Browser Webcam** mode instead.

**Problem:** YOLO model file not found  
**Solution:** Model downloads automatically on first use. Ensure internet access or manually download `yolov8n.pt` from https://github.com/ultralytics/assets/releases and place in project root.

**Problem:** Static files not loading  
**Solution:** Configure static files mapping in PythonAnywhere Web tab as shown above.

---

## 🔒 SECURITY NOTE
This is a demo/educational system. For production:
- Set the `SECRET_KEY`, `JWT_SECRET_KEY`, and `ADMIN_PASSWORD` in `.env`
- Use strong admin credentials and rotate them before deployment
- Enable HTTPS
- Set proper file permissions
b7bdef5 (Initial commit: VAJRA-X Multi-Domain Situational Awareness Platform)
