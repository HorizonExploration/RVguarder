"""仅用于隔离验收的真实HTTP故障代理，健康探测和正常请求转发生产后端。"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time
from urllib.request import Request, urlopen
from urllib.error import HTTPError


class NativeFaultProxy:
    """不替代Guard决策；只向SDK注入明确标记的传输错误。"""
    def __init__(self, backend: str, host: str, port: int, mode: str):
        self.mode = mode
        self.requests = []
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.forward()

            def do_POST(self):
                self.forward()

            def forward(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
                mode = owner.mode if self.path == '/api/hook/before-tool-call' else 'healthy'
                owner.requests.append({'path': self.path, 'mode': mode})
                if mode != 'healthy':
                    if mode == 'timeout':
                        time.sleep(3)
                    status = 500 if mode == 'http500' else 403 if mode == 'http403' else 200
                    payload = b'not-json' if mode == 'malformed' else b'{"error":"injected-test-fault"}'
                else:
                    headers = {'Content-Type': self.headers.get('Content-Type', 'application/json')}
                    if self.headers.get('Authorization'):
                        headers['Authorization'] = self.headers['Authorization']
                    if self.headers.get('x-openclaw-guard-token'):
                        headers['x-openclaw-guard-token'] = self.headers['x-openclaw-guard-token']
                    try:
                        response = urlopen(Request(backend + self.path, data=body if self.command == 'POST' else None,
                            headers=headers, method=self.command), timeout=20)
                    except HTTPError as error:
                        response = error
                    status, payload = response.code, response.read()
                    response.close()
                try:
                    self.send_response(status)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError):
                    pass
        self.server = ThreadingHTTPServer((host, port), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def shutdown(self):
        """关闭验收自身代理，不影响真实后端和任何日常服务。"""
        self.server.shutdown()
        self.server.server_close()
