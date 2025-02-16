from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import subprocess
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datetime import timedelta, datetime
import threading
from math import ceil
import json
import os
import re

                                                  #Substrike-stable v1.0.0 release 
app = Flask(__name__)
app.secret_key = 'Dj_StWuZbx3l8YUz1Qmslw2lIfnvc9rD'

user_sessions = {
    "Admin": {
        "password": "admin@123",
        "scan_state": {
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
    }
}

def is_valid_domain(domain):
    return bool(re.match(r'^[a-zA-Z0-9.-]+$', domain))
    
def sanitize_input(subdomain):

    if re.match(r'^[a-zA-Z0-9.-]+$', subdomain):
        return subdomain
    raise ValueError("Invalid subdomain")

lock = threading.Lock()

def format_time(seconds):
    td = timedelta(seconds=int(seconds))  
    hours, remainder = divmod(td.total_seconds(), 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{int(hours):02}:{int(minutes):02}:{int(seconds):02}"  


SCAN_RESULTS_DIR = "scan_results"
os.makedirs(SCAN_RESULTS_DIR, exist_ok=True)

def get_user_scan_folder(user):
    """Return the directory path for storing user's scan results."""
    user_folder = os.path.join(SCAN_RESULTS_DIR, user)
    os.makedirs(user_folder, exist_ok=True)
    return user_folder


def save_scan_results(user, results, user_scan_file):
    """Save scan results to a JSON file with scan metadata and update user statistics."""
    scan_metadata = {
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "vulnerable_found": sum(1 for _, _, _, is_vulnerable, _ in results if is_vulnerable == "Vulnerable"),
        "safe_found": sum(1 for _, _, _, is_vulnerable, _ in results if is_vulnerable == "Safe"),
        "results": results
    }

    with open(user_scan_file, "w") as f:
        json.dump(scan_metadata, f, indent=4)

    stats_file = os.path.join(get_user_scan_folder(user), "stats.json")

    if os.path.exists(stats_file):
        with open(stats_file, 'r') as f:
            user_stats = json.load(f)
    else:
        user_stats = {"total_scans": 0, "total_vulnerable": 0, "total_safe": 0}

    user_stats["total_scans"] += 1
    user_stats["total_vulnerable"] += scan_metadata["vulnerable_found"]
    user_stats["total_safe"] += scan_metadata["safe_found"]

    with open(stats_file, "w") as f:
        json.dump(user_stats, f, indent=4)



def scan_subdomains(file_path, user, user_scan_file):
    """Perform subdomain scanning and update scan results."""
    scan_state = user_sessions[user]["scan_state"]
    scan_state.update({
        "total_subdomains": 0,
        "progress": 0,
        "finished": False,
        "vulnerable": 0,
        "active": 0,
        "inactive": 0,
        "results": [],
        "start_time": time.time() 
    })

    results = []

    with open(file_path, 'r') as f:
        subdomains = f.read().splitlines()

    total_subdomains = len(subdomains)
    scan_state["total_subdomains"] = total_subdomains

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(scan_subdomain, subdomain, index, total_subdomains, user): subdomain for index, subdomain in enumerate(subdomains)}

        for future in as_completed(futures):
            results.append(future.result())

    save_scan_results(user, results, user_scan_file)
    scan_state["results"] = results
    scan_state["finished"] = True



def scan_subdomain(subdomain, index, total_subdomains, user):
    scan_state = user_sessions[user]["scan_state"]
    time.sleep(0.1)  

    progress = (index + 1) / total_subdomains * 100
    scan_state.update({
        "progress": progress,
        "current_subdomain": subdomain,
        "subdomains_scanned": index + 1,
        "subdomains_left": total_subdomains - (index + 1),
        "time_left": (total_subdomains - (index + 1)) * 0.1 
    })

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:  
            dig_a_future = executor.submit(subprocess.run, ["dig", subdomain, "+short", "A"], capture_output=True, text=True)
            dig_cname_future = executor.submit(subprocess.run, ["dig", subdomain, "+short", "CNAME"], capture_output=True, text=True)

            a_record = dig_a_future.result().stdout.strip()
            cname_output = dig_cname_future.result().stdout.strip()

        if "ID mismatch" in cname_output or "timed out" in cname_output or "connection refused" in cname_output or "no servers could be reached" in cname_output or "communications error" in cname_output or ";; Warning: ID mismatch:" in cname_output:
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
            "visualstudio.com", "trafficmanager.net"
        ]

        if status_nxdomain:
            if cname != "N/A":
                if any(keyword in cname for keyword in vulnerable_cname_keywords):
                    scan_state["vulnerable"] += 1
                    scan_state["inactive"] += 1
                    return (subdomain, cname, "NXDOMAIN", "Vulnerable", "Inactive")
                else:
                    scan_state["inactive"] += 1
                    return (subdomain, cname, "NXDOMAIN", "Safe", "Inactive")
            else:
                scan_state["inactive"] += 1
                return (subdomain, "N/A", "NXDOMAIN", "Safe", "Inactive")

        if a_record:
            scan_state["active"] += 1
            return (subdomain, cname, "Resolved", "Safe", "Active")
        else:
            scan_state["inactive"] += 1
            return (subdomain, "N/A", "Resolved", "Safe", "Inactive")

    except Exception:
        scan_state["inactive"] += 1
        return (subdomain, "N/A", "Error", "Unknown", "Inactive")



@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in user_sessions and user_sessions[username]["password"] == password:
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('dashboard')) 
        else:
            flash('Invalid Credentials', 'danger')
    return render_template('login.html')

@app.route('/dashboard', methods=['GET'])
def dashboard():
    """Dashboard displaying scan history, in-progress scans, and user-specific statistics."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = session['username']
    page = int(request.args.get('page', 1))  
    items_per_page = 10  
    scan_state = user_sessions[user]["scan_state"]

    in_progress = not scan_state["finished"] and scan_state["total_subdomains"] > 0  

    stats_file = os.path.join(get_user_scan_folder(user), "stats.json")

    if os.path.exists(stats_file):
        with open(stats_file, 'r') as f:
            user_stats = json.load(f)
    else:
        user_stats = {"total_scans": 0, "total_vulnerable": 0, "total_safe": 0}

    def get_scan_history(user):
        """Retrieve scan history for a user, including ongoing scans."""
        user_scan_folder = get_user_scan_folder(user)
        scans = []

        for filename in os.listdir(user_scan_folder):
            if filename.endswith('.json') and filename != "stats.json":
                file_path = os.path.join(user_scan_folder, filename)
                with open(file_path, 'r') as f:
                    scan_data = json.load(f)

                scans.append({
                    "file_name": filename,
                    "scan_type": "Batch Scan",
                    "scan_date": scan_data.get("scan_date", "Unknown"),
                    "status": "Complete",
                    "vulnerabilities": f"{scan_data.get('vulnerable_found', 0)} Found" if scan_data.get('vulnerable_found', 0) > 0 else "None"
                })

        if in_progress:
            scans.append({
                "file_name": None,
                "scan_type": "Batch Scan",
                "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M"), 
                "status": "In Progress",
                "vulnerabilities": None
            })

        return sorted(scans, key=lambda x: x["scan_date"] or "", reverse=True)

    scan_history = get_scan_history(user)

    total_scans = len(scan_history)
    total_pages = (total_scans + items_per_page - 1) // items_per_page  
    paginated_scans = scan_history[(page - 1) * items_per_page: page * items_per_page] 

    start_result = (page - 1) * items_per_page + 1
    end_result = start_result + len(paginated_scans) - 1

    return render_template('dashboard.html', 
                           scan_history=paginated_scans,
                           in_progress=in_progress,
                           current_page=page,
                           total_pages=total_pages,
                           total_scans=total_scans,
                           start_result=start_result,
                           end_result=end_result,
                           user_stats=user_stats)


@app.route('/singlescan', methods=['GET'])
def singlescan():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('singlescan.html')

@app.route('/single_scan', methods=['POST'])
def single_scan():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    domain = request.form.get('domain')
    if not domain:
        flash("Please enter a valid domain.", "danger")
        return redirect(url_for('singlescan'))

    def perform_dns_lookup(domain):
        records = {}
        try:
            records['A'] = subprocess.run(["dig", "+short", domain, "A"], capture_output=True, text=True).stdout.strip()
            records['CNAME'] = subprocess.run(["dig", "+short", domain, "CNAME"], capture_output=True, text=True).stdout.strip()
            records['TXT'] = subprocess.run(["dig", "+short", domain, "TXT"], capture_output=True, text=True).stdout.strip()
            records['AAAA'] = subprocess.run(["dig", "+short", domain, "AAAA"], capture_output=True, text=True).stdout.strip()
            records['NS'] = subprocess.run(["dig", "+short", domain, "NS"], capture_output=True, text=True).stdout.strip()
            records['SOA'] = subprocess.run(["dig", "+short", domain, "SOA"], capture_output=True, text=True).stdout.strip()

            dig_status_result = subprocess.run(["dig", domain], capture_output=True, text=True).stdout
            records['status'] = "NXDOMAIN" if "status: NXDOMAIN" in dig_status_result else "Resolved"

        except Exception as e:
            records['error'] = str(e)
        
        return records

    def check_subdomain_takeover(domain, cname, status):
        vulnerable_cname_keywords = [
            "elasticbeanstalk.com", "cloudapp.net", "cloudapp.azure.com",
            "azurewebsites.net", "blob.core.windows.net", "azure-api.net",
            "azurehdinsight.net", "azureedge.net", "azurecontainer.io",
            "database.windows.net", "azuredatalakestore.net", "search.windows.net",
            "azurecr.io", "redis.cache.windows.net", "servicebus.windows.net",
            "visualstudio.com", "trafficmanager.net"
        ]

        if status == "NXDOMAIN" and cname and any(keyword in cname for keyword in vulnerable_cname_keywords):
            return True
        return False

    scan_results = perform_dns_lookup(domain)
    vulnerable = check_subdomain_takeover(domain, scan_results.get('CNAME', ''), scan_results.get('status', 'Resolved'))

    return render_template('scanresult.html', domain=domain, results=scan_results, vulnerable=vulnerable)



import os
import time
from flask import render_template, request, redirect, url_for, session, flash
from concurrent.futures import ThreadPoolExecutor

SCAN_RESULTS_DIR = "scan_results" 

@app.route('/home', methods=['GET', 'POST'])
def home():
    """Home page for starting a batch scan."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = session['username']
    scan_state = user_sessions[user]["scan_state"]

    in_progress = not scan_state["finished"] and scan_state["total_subdomains"] > 0  

    def get_user_scan_folder(user):
        """Retrieve the scan folder for the user."""
        return os.path.join(SCAN_RESULTS_DIR, user)

    def get_recent_scans(user):
        """Retrieve recent scans for a user."""
        user_scan_folder = get_user_scan_folder(user)

        scan_files = [f for f in os.listdir(user_scan_folder) if f.endswith('.json') and f != "stats.json"]

        sorted_scans = sorted(scan_files, key=lambda x: os.path.getctime(os.path.join(user_scan_folder, x)), reverse=True)

        return sorted_scans[:5]

    if request.method == 'POST':
        if in_progress:
            flash("A scan is already in progress. Please wait for it to complete.", "danger")
            return redirect(url_for('home'))

        file = request.files.get('file')
        filename = request.form.get('filename', 'default_scan')

        if file and file.filename.endswith('.txt'):
            file_path = os.path.join('uploads', file.filename)
            file.save(file_path)

            user_scan_folder = get_user_scan_folder(user)
            user_scan_file = os.path.join(user_scan_folder, f"{filename}.json")

            user_sessions[user]["scan_state"].update({
                "progress": 0,
                "finished": False
            })

            ThreadPoolExecutor().submit(scan_subdomains, file_path, user, user_scan_file)

            return redirect(url_for('scans'))
        else:
            flash('Please upload a valid .txt file', 'danger')

    recent_scans = get_recent_scans(user)

    return render_template('home.html', recent_scans=recent_scans, in_progress=in_progress)

@app.route('/scans', methods=['GET'])
def scans():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = session['username']
    return render_template('scans.html', user_sessions=user_sessions[user]["scan_state"])

@app.route('/scan_status', methods=['GET'])
def scan_status():
    user = session['username']
    scan_state = user_sessions[user]["scan_state"]

    elapsed_seconds = int(time.time() - scan_state.get("start_time", time.time()))

    return jsonify({
        'progress': scan_state.get('progress', 0),
        'time_left': format_time(scan_state.get('time_left', 0)),  
        'elapsed_time': format_time(elapsed_seconds),  
        'current_subdomain': scan_state.get('current_subdomain', ''),
        'subdomains_scanned': scan_state.get('subdomains_scanned', 0),
        'subdomains_left': scan_state.get('subdomains_left', 0)
    })


@app.route('/view/<filename>', methods=['GET', 'POST'])
def view_scan(filename):
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = session['username']
    user_scan_folder = get_user_scan_folder(user)
    user_scan_file = os.path.join(user_scan_folder, filename)

    if os.path.exists(user_scan_file):
        with open(user_scan_file, 'r') as f:
            scan_data = json.load(f)  

        scan_results = scan_data.get("results", [])  

        status_filter = request.form.get('status_filter', 'all')
        vulnerability_filter = request.form.get('vulnerability_filter', 'all')

        filtered_results = [
            result for result in scan_results
            if (status_filter == 'all' or result[2] == status_filter) and
               (vulnerability_filter == 'all' or result[3] == vulnerability_filter)
        ]

        page = request.args.get('page', 1, type=int)
        per_page = 10
        total_results = len(filtered_results)
        total_pages = (total_results + per_page - 1) // per_page

        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_results = filtered_results[start_idx:end_idx]

        file_name_without_extension = filename.rsplit('.', 1)[0]

        return render_template('view.html', 
                               results=paginated_results,
                               file_name=file_name_without_extension,
                               scan_date=scan_data.get("scan_date", "Unknown"),
                               vulnerable_found=scan_data.get("vulnerable_found", 0),
                               status_filter=status_filter,
                               vulnerability_filter=vulnerability_filter,
                               page_number=page,
                               total_pages=total_pages,
                               total_results=total_results)
    else:
        flash('Scan file not found', 'danger')
        return redirect(url_for('home'))



@app.route('/results', methods=['GET', 'POST'])
def results():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = session.get('username')
    if user not in user_sessions:
        return redirect(url_for('dashboard'))  

    scan_state = user_sessions[user].get("scan_state", {})
    results = scan_state.get('results', [])

    page_number = request.args.get('page', default=1, type=int)
    items_per_page = 10
    total_results = len(results)
    total_pages = max(1, ceil(total_results / items_per_page))

    page_number = max(1, min(page_number, total_pages))
    
    start_index = (page_number - 1) * items_per_page
    end_index = min(start_index + items_per_page, total_results)
    paginated_results = results[start_index:end_index]

    return render_template(
        'results.html',
        all_results=results,  
        results=paginated_results,
        total_subdomains=scan_state.get("total_subdomains", 0),
        vulnerable=scan_state.get("vulnerable", 0),
        active=scan_state.get("active", 0),
        inactive=scan_state.get("inactive", 0),
        page_number=page_number,
        total_pages=total_pages
    )




@app.route('/get_results')
def get_results():
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401

    user = session['username']
    scan_state = user_sessions[user]["scan_state"]
    results = scan_state.get('results', [])

    return jsonify({"results": results})


@app.route('/delete_scan/<filename>', methods=['POST'])
def delete_scan(filename):
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = session['username']
    user_scan_folder = get_user_scan_folder(user)
    user_scan_file = os.path.join(user_scan_folder, f"{filename}.json")  

    if os.path.exists(user_scan_file):
        os.remove(user_scan_file)  
        return jsonify({"success": True})  
    else:
        return jsonify({"success": False, "error": "File not found"}) 


@app.route('/logout', methods=['GET'])
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
