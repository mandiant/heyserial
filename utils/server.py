# Copyright (C) 2021 Alyssa Rahman, Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

#############################
# Simple Python HTTP server #
#############################
## Author: Alyssa Rahman (@ramen0x3f)
## Last Updated: 2021-12-02
## Description: Python 1 liners work for GET-only HTTP servers. For some testing, POST request support is needed.

from http.server import BaseHTTPRequestHandler,HTTPServer
class Echo(BaseHTTPRequestHandler):
	def do_POST(self):
		self.send_response(200)
		self.end_headers()
		self.wfile.write(b"echo...echo...")
		self.wfile.flush()

HTTPServer(('127.0.0.1', 12345), Echo).serve_forever()
