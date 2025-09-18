from flask import Flask, request, render_template
from dotenv import load_dotenv
from playwright.sync_api import sync_playwright
import os

# Load environment variables from .env
load_dotenv()

app = Flask(__name__)

# Retrieve the app's domain from the .env file
DOMAIN = os.getenv("DOMAIN", "localhost")
SESSION_COOKIE = os.getenv("SESSION_COOKIE")

def visit_url(url):
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()

            print(f"Admin bot visiting: {url}")

            # Set the cookie for the app's domain
            context.add_cookies([{
                "name": "session",
                "value": SESSION_COOKIE,
                "domain": DOMAIN,
                "path": "/"
            }])

            # Visit the target URL
            page.goto(url)
            page.wait_for_timeout(3000)  # Wait for 3 seconds to allow scripts to execute

            return {"status": "success", "message": f"Visited {url}"}
    except Exception as e:
        print(f"Error visiting {url}: {e}")
        return {"status": "error", "message": str(e)}

# Route to display the form
@app.route('/')
def home():
    return render_template('visit.html')

# Route to handle URL visit via POST
@app.route('/visit', methods=['POST'])
def visit():
    url = request.form.get('url')
    if not url:
        return render_template('visit.html', error="No URL provided")

    # Visit the provided URL
    result = visit_url(url)
    message = result['message'] if result['status'] == 'success' else None
    error = result['message'] if result['status'] == 'error' else None
    return render_template('visit.html', message=message, error=error)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=4444)
