from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import subprocess
import os
from concurrent.futures import ThreadPoolExecutor
import time
from datetime import timedelta
import threading

app = Flask(__name__)
app.secret_key = 'your_secret_key'

scan_state = {
    "total_subdomains": 0,
    "vulnerable": 0,
    "active": 0,
    "inactive": 0,
    "results": [],
    "progress": 0,
    "finished": False,
    "current_subdomain": "",
    "subdomains_scanned": 0,
    "subdomains_left": 0,
    "time_left": 0
}

lock = threading.Lock()  

def format_time(seconds):
    return str(timedelta(seconds=seconds))

def scan_subdomains(file_path):
    global scan_state
    results = []
    subdomains = []

    with open(file_path, 'r') as f:
        subdomains = f.read().splitlines()

    total_subdomains = len(subdomains)
    scan_state.update({
        "total_subdomains": total_subdomains,
        "progress": 0,
        "finished": False,
        "vulnerable": 0,
        "active": 0,
        "inactive": 0,
        "results": []
    })

    with ThreadPoolExecutor() as executor:
        futures = []
        for index, subdomain in enumerate(subdomains):
            futures.append(executor.submit(scan_subdomain, subdomain, index, total_subdomains, results))

        for future in futures:
            future.result()

    with lock:
        scan_state['results'] = results
        scan_state['finished'] = True

def scan_subdomain(subdomain, index, total_subdomains, results):
    global scan_state
    time.sleep(1)

    progress = (index + 1) / total_subdomains * 100
    with lock:
        scan_state.update({
            "progress": progress,
            "current_subdomain": subdomain,
            "subdomains_scanned": index + 1,
            "subdomains_left": total_subdomains - (index + 1),
            "time_left": (total_subdomains - (index + 1)) * 1
        })

    try:
       
        dig_a_result = subprocess.run(["dig", subdomain, "+short", "A"], capture_output=True, text=True)
        a_record = dig_a_result.stdout.strip()

        
        dig_cname_result = subprocess.run(["dig", subdomain, "+short", "CNAME"], capture_output=True, text=True)
        cname_output = dig_cname_result.stdout.strip()

        
        if "ID mismatch" in cname_output or "timed out" in cname_output or "connection refused" in cname_output or "no servers could be reached" in cname_output or "communications error" in cname_output:
            results.append((subdomain, "Error fetching data", "Error", "Unknown", "Inactive"))
            with lock:
                scan_state["inactive"] += 1
            return

        cname = cname_output if cname_output else "N/A"

        
        dig_status_result = subprocess.run(["dig", subdomain], capture_output=True, text=True)
        status_nxdomain = "status: NXDOMAIN" in dig_status_result.stdout

        
        vulnerable_cname_keywords = [
            "elasticbeanstalk.com", "cloudapp.net", "cloudapp.azure.com",
            "azurewebsites.net", "blob.core.windows.net", "azure-api.net",
            "azurehdinsight.net", "azureedge.net", "azurecontainer.io",
            "database.windows.net", "azuredatalakestore.net", "search.windows.net",
            "azurecr.io", "redis.cache.windows.net", "servicebus.windows.net",
            "visualstudio.com","trafficmanager.net"
        ]

        if status_nxdomain:
            if cname != "N/A":
                
                if any(keyword in cname for keyword in vulnerable_cname_keywords):
                    results.append((subdomain, cname, "NXDOMAIN", "Vulnerable", "Inactive"))
                    with lock:
                        scan_state["vulnerable"] += 1
                        scan_state["inactive"] += 1
                else:
                    results.append((subdomain, cname, "NXDOMAIN", "Safe", "Inactive"))
                    with lock:
                        scan_state["inactive"] += 1
            else:
                results.append((subdomain, "N/A", "NXDOMAIN", "Safe", "Inactive"))
                with lock:
                    scan_state["inactive"] += 1
            return

        if a_record:
            results.append((subdomain, cname, "Resolved", "Safe", "Active"))
            with lock:
                scan_state["active"] += 1
        else:
            results.append((subdomain, "N/A", "Resolved", "Safe", "Inactive"))
            with lock:
                scan_state["inactive"] += 1

    except Exception as e:
        results.append((subdomain, "N/A", "Error", "Unknown", "Inactive"))
        with lock:
            scan_state["inactive"] += 1








@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == "admin" and password == "admin@123":
            session['logged_in'] = True
            return redirect(url_for('home'))
        else:
            flash('Invalid Credentials', 'danger')
    return render_template('login.html')

@app.route('/home', methods=['GET', 'POST'])
def home():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        file = request.files.get('file')
        if file and file.filename.endswith('.txt'):
            file_path = os.path.join('uploads', file.filename)
            file.save(file_path)
            global scan_state
            scan_state.update({
                "progress": 0,
                "finished": False
            })
            ThreadPoolExecutor().submit(scan_subdomains, file_path)
            return redirect(url_for('scans'))
        else:
            flash('Please upload a valid .txt file', 'danger')
    return render_template('home.html')

@app.route('/scans', methods=['GET'])
def scans():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    return render_template('scans.html')

@app.route('/scan_status', methods=['GET'])
def scan_status():
    return jsonify({
        'progress': scan_state.get('progress', 0),
        'time_left': format_time(scan_state.get('time_left', 0)),
        'current_subdomain': scan_state.get('current_subdomain', ''),
        'subdomains_scanned': scan_state.get('subdomains_scanned', 0),
        'subdomains_left': scan_state.get('subdomains_left', 0)
    })

@app.route('/results', methods=['GET', 'POST'])
def results():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        status_filter = request.form.get('status_filter', 'all')
        vulnerability_filter = request.form.get('vulnerability_filter', 'all')

        filtered_results = [
            (subdomain, cname, status, is_vulnerable, is_active)
            for subdomain, cname, status, is_vulnerable, is_active in scan_state.get('results', [])
            if (status_filter == 'all' or status == status_filter) and (vulnerability_filter == 'all' or is_vulnerable == vulnerability_filter)
        ]
        
        return render_template(
            'results.html',
            results=filtered_results,
            status_filter=status_filter,
            vulnerability_filter=vulnerability_filter,
            total_subdomains=scan_state["total_subdomains"],
            vulnerable=scan_state["vulnerable"],
            active=scan_state["active"],
            inactive=scan_state["inactive"]
        )

    return render_template(
        'results.html',
        results=scan_state.get('results', []),
        status_filter='all',
        vulnerability_filter='all',
        total_subdomains=scan_state["total_subdomains"],
        vulnerable=scan_state["vulnerable"],
        active=scan_state["active"],
        inactive=scan_state["inactive"]
    )

@app.route('/logout', methods=['GET'])
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

