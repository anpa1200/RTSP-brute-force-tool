from RTSP_bruteforce import get_vendor_paths, list_vendors, parse_rtsp_url


def test_parse_rtsp_url():
    target = parse_rtsp_url("rtsp://camera.local:8554/live")
    assert target is not None
    assert target.host == "camera.local"
    assert target.port == 8554
    assert target.path == "live"


def test_rejects_non_rtsp_url():
    assert parse_rtsp_url("https://camera.local/live") is None


def test_vendor_presets_include_hikvision():
    assert "hikvision" in list_vendors()
    assert get_vendor_paths("hikvision", None)
