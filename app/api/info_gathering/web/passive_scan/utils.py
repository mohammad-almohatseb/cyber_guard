from urllib.parse import urlparse

def get_domain_from_url(url_to_process):
    parsed_url = urlparse(url_to_process)
    if not parsed_url.netloc:
        raise ValueError("Invalid URL provided")
    return parsed_url.netloc
