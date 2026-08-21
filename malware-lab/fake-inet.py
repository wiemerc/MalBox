from http import HTTPStatus
import mitmproxy.http
from mitmproxy import ctx


class FakeInternet:
    """
    Answer every request so that the malware thinks it's connected to the internet
    """
    def request(self, flow: mitmproxy.http.HTTPFlow):
        url = flow.request.pretty_url

        if url.endswith(".exe") or url.endswith(".dll"):
            # TODO
            content_type = "application/octet-stream"
        elif url.endswith(".png") or url.endswith(".jpg") or url.endswith(".gif"):
            # TODO
            pass
        else:
            # reply with a fake HTML page by default
            # TODO: load page from a file
            fake_resp_content = "<html><body><h1>So a scheener Dog :-)</h1></body></html>"
            content_type = "text/html"

        flow.response = mitmproxy.http.Response.make(
            # TODO: use a different status code for POST / PUT
            HTTPStatus.OK,
            fake_resp_content,
            {
                "Content-Type": content_type,
                "Server": "Apache/2.4.41 (Ubuntu)",  # to disguise mitmproxy
                "Connection": "close"
            }
        )


addons = [
    FakeInternet()
]
