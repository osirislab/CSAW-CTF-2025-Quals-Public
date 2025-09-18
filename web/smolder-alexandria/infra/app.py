from flask import Flask, request, jsonify, render_template
from random import shuffle
import re
import subprocess

app = Flask(__name__)

VAULT_FILE = "vault.txt"
DISALLOWED_RE = re.compile(r"[;|&`\'\"]")


@app.route("/")
def index():
    # return render_template("index.html")
    return render_template("console.html")


@app.route("/vault")
def vault():
    return render_template("vault.html")


@app.route("/vault/search")
def search():
    query = request.args.get("q", "").strip()
    if not query:
        return jsonify({"error": "No search term provided"}), 400

    if DISALLOWED_RE.search(query):
        return jsonify({"error": "Search term contains disallowed characters"}), 400

    cmd = f'grep -i -F "{query}" {VAULT_FILE}'
    try:
        output = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT, timeout=2, text=True
        )
        results = output.splitlines()
    except subprocess.CalledProcessError:
        results = []
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Operation timed out"}), 500
    except Exception as e:
        return jsonify({"error": f"Search failed: {e}"}), 500

    shuffle(results)
    results = [f"[*] {i}" for i in results]
    return jsonify({"results": results})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3700)
