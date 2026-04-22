import re

config = {
    "headers": ["x-.*"],
    "cookies": [".*"]
}

from mitmproxy.http import Headers
headers = Headers(Cookie="c1=v1; x-cookie=123", X_Test="abc")

class DummyRequest:
    def __init__(self):
        self.headers = headers
        
    @property
    def cookies(self):
        from mitmproxy.net.http.cookies import CookieRequestHeader
        return CookieRequestHeader(self.headers)
        
    @cookies.setter
    def cookies(self, value):
        pass

class DummyTarget:
    def __init__(self):
        self.id = "mock-id"
        self.request = DummyRequest()

target = DummyTarget()

def remove_headers_cookies(target, config, vars_dict):
    except_h_patterns = []
    except_c_patterns = []

    headers_to_remove = config.get("headers", [])
    for h in headers_to_remove:
        pattern = h
        regex = re.compile(pattern, re.IGNORECASE)

        matched = [k for k in target.request.headers.keys() if regex.fullmatch(k)]
        for name in matched:
            del target.request.headers[name]
            print(f"Removed header: {name}")

    cookies_to_remove = config.get("cookies", [])
    if cookies_to_remove:
        removed = []
        for name, _ in list(target.request.cookies.items(multi=True)):
            if name in removed:
                continue

            for c in cookies_to_remove:
                pattern = c
                regex = re.compile(pattern, re.IGNORECASE)

                if regex.fullmatch(name):
                    del target.request.cookies[name]
                    removed.append(name)
                    print(f"Removed cookie: {name}")
                    break

print(f"Before: headers={target.request.headers}")
remove_headers_cookies(target, config, {})
print(f"After: headers={target.request.headers}")
