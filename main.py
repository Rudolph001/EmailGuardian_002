from app import app

# This is required for gunicorn to find the Flask app
# gunicorn looks for the 'app' variable in this file
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
