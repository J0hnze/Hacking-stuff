from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import cgi
import urllib.parse
import sys
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

UPLOAD_DIRECTORY = "./uploads"
MAX_UPLOAD_SIZE_MB = 10  # Maximum allowed file size (in MB)

if not os.path.exists(UPLOAD_DIRECTORY):
    os.makedirs(UPLOAD_DIRECTORY)

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/uploads/"):
            self.serve_uploaded_file(self.path)
        else:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            html = '''
            <html><head><title>File Upload</title></head><body>
            <h2>Drag and Drop to Upload</h2>
            <div id="drop-area" style="border:2px dashed #ccc;padding:40px;border-radius:10px;width:80%;margin:auto;text-align:center;">
            <p>Drop files here or <label for="fileElem" style="cursor:pointer;color:blue;">select</label> manually.</p>
            <input type="file" id="fileElem" multiple style="display:none" onchange="handleFiles(this.files)">
            </div>
            <h3>Uploaded Files:</h3><ul>
            '''

            for fname in os.listdir(UPLOAD_DIRECTORY):
                safe = urllib.parse.quote(fname)
                html += f'<li><a href="/uploads/{safe}" download>{fname}</a></li>'

            html += '''
            </ul>
            <script>
            let dropArea = document.getElementById('drop-area');
            dropArea.addEventListener('dragover', e => { e.preventDefault(); dropArea.style.borderColor = '#333'; });
            dropArea.addEventListener('dragleave', () => { dropArea.style.borderColor = '#ccc'; });
            dropArea.addEventListener('drop', e => {
                e.preventDefault(); dropArea.style.borderColor = '#ccc';
                handleFiles(e.dataTransfer.files);
            });

            function handleFiles(files) {
                for (let i = 0; i < files.length; i++) {
                    uploadFile(files[i]);
                }
            }

            function uploadFile(file) {
                if (file.size > {max_size}) {
                    alert("File too large. Max allowed: {max_mb} MB");
                    return;
                }
                let formData = new FormData();
                formData.append("file", file);
                fetch("/", {
                    method: "POST",
                    body: formData
                }).then(res => {
                    if (!res.ok) throw new Error("Upload failed");
                    alert("Upload successful!");
                    window.location.reload();
                }).catch(err => {
                    alert("Upload failed: " + err.message);
                });
            }
            </script></body></html>
            '''.replace('{max_size}', str(MAX_UPLOAD_SIZE_MB * 1024 * 1024)).replace('{max_mb}', str(MAX_UPLOAD_SIZE_MB))

            self.wfile.write(html.encode('utf-8'))

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > MAX_UPLOAD_SIZE_MB * 1024 * 1024:
            self.send_response(413)
            self.end_headers()
            self.wfile.write(b"File too large")
            return

        ctype, pdict = cgi.parse_header(self.headers.get('Content-Type'))
        if ctype != 'multipart/form-data':
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Invalid form type")
            return

        pdict['boundary'] = bytes(pdict['boundary'], "utf-8")
        pdict['CONTENT-LENGTH'] = content_length

        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={
                'REQUEST_METHOD': 'POST',
                'CONTENT_TYPE': self.headers.get('Content-Type'),
            }
        )

        if "file" in form:
            fileitem = form["file"]
            if fileitem.filename:
                filename = os.path.basename(fileitem.filename)
                base, ext = os.path.splitext(filename)
                save_path = os.path.join(UPLOAD_DIRECTORY, filename)

                count = 1
                while os.path.exists(save_path):
                    filename = f"{base}({count}){ext}"
                    save_path = os.path.join(UPLOAD_DIRECTORY, filename)
                    count += 1

                with open(save_path, 'wb') as f:
                    f.write(fileitem.file.read())

                print(f"[+] Uploaded: {save_path}")

                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Upload successful.")
                return

        self.send_response(400)
        self.end_headers()
        self.wfile.write(b"Upload failed")

    def serve_uploaded_file(self, path):
        file_path = os.path.join(UPLOAD_DIRECTORY, path[len("/uploads/"):])
        if os.path.exists(file_path):
            self.send_response(200)
            self.send_header("Content-type", "application/octet-stream")
            self.send_header("Content-Disposition", f"attachment; filename=\"{os.path.basename(file_path)}\"")
            self.end_headers()
            with open(file_path, 'rb') as f:
                self.wfile.write(f.read())
        else:
            self.send_response(404)
            self.end_headers()

def run(port=8080):
    server = HTTPServer(('', port), SimpleHTTPRequestHandler)
    print(f"Server running at http://0.0.0.0:{port}")
    server.serve_forever()

if __name__ == '__main__':
    if len(sys.argv) > 1:
        if sys.argv[1] in ('-h', '--help'):
            print("Usage: python upload_server.py [port]")
            print("Default: 8080")
            sys.exit(0)
        try:
            port = int(sys.argv[1])
        except ValueError:
            print("Invalid port number. Use an integer.")
            sys.exit(1)
    else:
        port = 8080
    run(port)
