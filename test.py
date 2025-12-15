import urllib
import urllib.parse
from models.drain3_instance import drain3_instance


def preprocess_log(log_string):
    try:
        log_string = urllib.parse.unquote(log_string)
        log_string = drain3_instance.masker.mask(log_string)
        return log_string
    except Exception as e:
        print(f"Lỗi khi xử lý log: {e}")
        return log_string

raw_log = " GET http://localhost:8080/tienda1/index.jsp HTTP/1.1 User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko) Pragma: no-cache Cache-control: no-cache Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5 Accept-Encoding: x-gzip, x-deflate, gzip, deflate Accept-Charset: utf-8, utf-8;q=0.5, *;q=0.5 Accept-Language: en Host: localhost:8080 Cookie: JSESSIONID=EA414B3E327DED6875848530C864BD8F Connection: close "

result = preprocess_log(raw_log)
print(result)