"""
Built-in RTSP vendor presets: stream paths and default credentials.
Based on public documentation (Hikvision, Dahua, Axis, Hanwha, Uniview, etc.).
"""

from __future__ import annotations

# Vendor name -> paths (relative, no leading slash), default users, default passwords
# Paths are tried with base URL (host:port) from --url
VENDOR_PATHS: dict[str, list[str]] = {
    "hikvision": [
        "Streaming/Channels/101",
        "Streaming/Channels/102",
        "Streaming/Channels/201",
        "Streaming/Channels/202",
        "Streaming/Channels/301",
        "Streaming/Channels/302",
        "media.sdp",
    ],
    "dahua": [
        "cam/realmonitor?channel=1&subtype=0",
        "cam/realmonitor?channel=1&subtype=1",
        "cam/realmonitor?channel=2&subtype=0",
        "cam/realmonitor?channel=2&subtype=1",
    ],
    "axis": [
        "axis-media/media.amp",
        "mpeg4/media.amp",
    ],
    "hanwha": [
        "profile1/media.smp",
        "profile2/media.smp",
        "LiveChannel/0/media.smp",
        "LiveChannel/1/media.smp",
    ],
    "uniview": [
        "media/video1",
        "media/video2",
        "unicast/c1/s0/live",
        "unicast/c1/s1/live",
        "unicast/c2/s0/live",
    ],
    "arecont": [
        "h264.sdp",
    ],
    "pelco": [
        "stream1",
    ],
    "vivotek": [
        "live.sdp",
        "stream1",
    ],
    "acti": [
        "",
        "video1",
    ],
    "swann": [
        "ch01/0",
        "ch01/1",
    ],
    "scw": [
        "media/video1",
        "media/video2",
        "unicast/c1/s0/live",
        "Streaming/Channels/101",
    ],
    "amcrest": [
        "cam/realmonitor?channel=1&subtype=0",
        "Streaming/Channels/101",
    ],
    "lorex": [
        "cam/realmonitor?channel=1&subtype=0",
        "Streaming/Channels/101",
    ],
    "foscam": [
        "video1",
        "video2",
    ],
    "reolink": [
        "h264Preview_01_main",
        "h264Preview_01_sub",
    ],
    "geovision": [
        "live.sdp",
    ],
    "qsee": [
        "Streaming/Channels/101",
        "cam/realmonitor?channel=1&subtype=0",
    ],
    "jvc": [
        "stream1",
    ],
    "canon": [
        "media.amp",
    ],
    "sony": [
        "stream1",
    ],
    "basler": [
        "stream1",
    ],
    "avigilon": [
        "stream1",
    ],
    "3xlogic": [
        "Streaming/Channels/101",
    ],
    "panasonic": [
        "stream1",
    ],
    "grandstream": [
        "stream1",
    ],
}

# Default usernames/passwords per vendor (used when --vendor-defaults is set)
VENDOR_DEFAULT_USERS: dict[str, list[str]] = {
    "hikvision": ["admin", "Admin", "service"],
    "dahua": ["admin", "Admin", "default"],
    "axis": ["root", "admin"],
    "hanwha": ["admin", "root"],
    "uniview": ["admin", "Admin"],
    "amcrest": ["admin"],
    "lorex": ["admin"],
    "foscam": ["admin"],
    "reolink": ["admin"],
    "geovision": ["admin"],
    "qsee": ["admin"],
    "jvc": ["admin"],
    "canon": ["root"],
    "sony": ["admin"],
    "basler": ["admin"],
    "avigilon": ["admin", "Administrator"],
    "3xlogic": ["admin"],
    "panasonic": ["admin"],
    "grandstream": ["admin"],
    "pelco": ["admin"],
    "vivotek": ["admin", "root"],
    "acti": ["admin"],
    "swann": ["admin"],
    "scw": ["admin"],
    "arecont": ["admin"],
}

VENDOR_DEFAULT_PASSWORDS: dict[str, list[str]] = {
    "hikvision": ["12345", "123456", "admin", "888888", "666666", "abc12345", "abcd1234"],
    "dahua": ["admin", "888888", "666666", "12345", "123456", "default", "password"],
    "axis": ["pass", "admin"],
    "hanwha": ["4321", "12345", "admin"],
    "uniview": ["admin", "12345", "password"],
    "amcrest": ["admin", "12345"],
    "lorex": ["admin", "123456"],
    "foscam": ["admin", ""],
    "reolink": ["admin", ""],
    "canon": ["camera"],
    "jvc": ["jvc"],
    "3xlogic": ["12345"],
    "panasonic": ["12345", "admin"],
    "grandstream": ["admin"],
    "pelco": ["admin"],
    "vivotek": ["admin", ""],
    "acti": ["admin", "12345"],
    "swann": ["admin", "1234"],
    "scw": ["admin", "12345"],
    "geovision": ["admin"],
    "qsee": ["admin", "123456"],
    "sony": ["admin"],
    "basler": ["admin"],
    "avigilon": ["admin", ""],
    "arecont": ["admin"],
}
