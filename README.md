# Substrike
Substrike is a Flask-based web application that helps identify subdomains vulnerable to takeover by analyzing their CNAME records and DNS status. It efficiently checks for misconfigured cloud services and abandoned subdomains, making it a valuable tool for penetration testers and bug bounty hunters.

## Features

- **Subdomain Scanning**: Analyze subdomains for potential takeover vulnerabilities.
- **Real-time Progress Tracking**: View scan progress, estimated time left, and subdomains scanned.
- **Batch & Single Scans**: Supports both batch file uploads and single domain scanning.
- **Statistics & History**: Track total scans, vulnerable subdomains, and safe subdomains per user.

## Prerequisites 

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install gunicorn & flask.

```bash
pip install flask gunicorn
```
```bash
sudo apt-get install dnsutils
```


## Usage

```python
git clone https://github.com/H3LLKY4T/Substrike.git
cd Substrike
```
#### To run the application
```
gunicorn -b 0.0.0.0:5000 app:app
```
OR 
```
python3 app.py```
Access the web UI at: http://127.0.0.1:5000

- Login: Default credentials are **admin:admin@123**.
- Single Scan: Enter a domain to check for vulnerabilities.
- Batch Scan: Upload a .txt file containing subdomains for bulk scanning.
- View Results: Check scan history, vulnerable subdomains, and overall statistics.


## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

This project is licensed under the [MIT](https://choosealicense.com/licenses/mit/) License.
