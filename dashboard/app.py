from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import threading
import os

# Define template directory explicitly
TEMPLATE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))

app = Flask(__name__, template_folder=TEMPLATE_DIR)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global state for simple tracking
scan_state = {
    'running': False,
    'progress': 0,
    'total': 0,
    'vulnerable': 0,
    'safe': 0,
    'results': []
}

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/status')
def status():
    return jsonify(scan_state)

def broadcast_update(data):
    """Call this from scanner to update UI"""
    # specific fields
    if 'vulnerable' in data and data['vulnerable']:
        scan_state['vulnerable'] += 1
    elif 'verdict' in data and data['verdict'] == 'SAFE':
        scan_state['safe'] += 1
        
    scan_state['progress'] += 1
    scan_state['results'].append(data)
    
    socketio.emit('scan_update', {
        'progress': scan_state['progress'],
        'total': scan_state['total'],
        'latest': data,
        'stats': {
            'vulnerable': scan_state['vulnerable'],
            'safe': scan_state['safe']
        }
    })

def start_dashboard(port=5000):
    try:
        print(f"Starting dashboard on http://localhost:{port}")
        socketio.run(app, port=port, allow_unsafe_werkzeug=True)
    except Exception as e:
        print(f"Failed to start dashboard: {e}")
