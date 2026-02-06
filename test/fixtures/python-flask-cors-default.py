from flask import Flask
from flask_cors import CORS

app = Flask(__name__)

# This should be flagged.
CORS(app)

