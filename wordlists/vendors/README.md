# Vendor wordlists

Place vendor-specific wordlists here for use with `--vendor` and `--vendor-defaults`.

## Directory layout

- `wordlists/vendors/<vendor_name>/users.txt` — one username per line
- `wordlists/vendors/<vendor_name>/passwords.txt` — one password per line  
- `wordlists/vendors/<vendor_name>/paths.txt` — one RTSP path per line (no leading slash)

Built-in vendors (no files required): hikvision, dahua, axis, hanwha, uniview, arecont, pelco, vivotek, acti, swann, scw, amcrest, lorex, foscam, reolink, geovision, qsee, jvc, canon, sony, basler, avigilon, 3xlogic, panasonic, grandstream.

Use `--list-vendors` to see all and `--list-paths <vendor>` to see built-in paths.
