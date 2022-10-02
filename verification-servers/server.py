from flask import Flask
import math
import time

app = Flask(__name__)

@app.route("/<path:path>")
def hello_world(path):
    time.sleep(0.01)
    return "echo " + str(path)

if __name__ == '__main__':
      app.run(host='0.0.0.0', port=4000)
