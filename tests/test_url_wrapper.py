import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from email_analyzer.analyzer import extract_urls_from_headers, unwrap_url


def test_extract_urls_from_headers_collects_urls_from_any_header():
    headers = {
        "X-Trace": "https://example.com/path",
        "X-Note": "no-url-here",
    }

    assert extract_urls_from_headers(headers) == ["https://example.com/path"]


def test_unwrap_url_recovers_wrapped_destination():
    wrapped = "https://safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Flogin"
    result = unwrap_url(wrapped)

    assert result["wrapped"] is True
    assert result["provider"] == "Microsoft Safe Links"
    assert result["decode_success"] is True
    assert result["decoded_url"] == "https://evil.example/login"
    assert result["wrapped_url"] == wrapped


def test_unwrap_url_recovers_blackspider_webdefence_payload():
    wrapped = (
        "http://webdefence.global.blackspider.com/urlwrap/?"
        "q=AXicY-FmcJnNwHB9JgNDUU6lgUmKXnFRmV5uYmZOcn5eSVF-jl5yfi6DmZmFYWZURZKhhaWZuYkpQ0lqUWpecqpeml5OZnFJfp5DYmaSXmYqQ0ZJSUGxlb5-VYZuer5uQXpqbmlOYkl-EcgQ_XCnQu-CDLPA5GC9vMT0xLx8vawCBgaGN90MDABqnywd&Z"
    )
    result = unwrap_url(wrapped)

    assert result["wrapped"] is True
    assert result["provider"] == "MailControl"
    assert result["decode_success"] is True
    assert result["decoded_url"] == "https://zh-go-pgemulator.com/WBqKph6QcS.nagano.jp"
    assert result["wrapped_url"] == wrapped
