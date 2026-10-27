use super::file_url;
use std::path::Path;

#[test]
fn relative_pac_paths_are_rejected() {
    for path in ["", "epix.pac", "profile/epix.pac", "../epix.pac"] {
        let error = file_url(Path::new(path)).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("absolute file URL"));
    }
}

#[cfg(unix)]
#[test]
fn unix_pac_url_preserves_filename_bytes_and_delimiters() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    for (path, expected) in [
        ("/tmp/profile/epix.pac", "file:///tmp/profile/epix.pac"),
        (
            "/tmp/First Last/#100%20/Zoë/雪/epix.pac",
            "file:///tmp/First%20Last/%23100%2520/Zo%C3%AB/%E9%9B%AA/epix.pac",
        ),
        ("/tmp/query?/epix.pac", "file:///tmp/query%3F/epix.pac"),
        ("/tmp/quote\"/epix.pac", "file:///tmp/quote%22/epix.pac"),
        (
            r"/tmp/back\slash/epix.pac",
            "file:///tmp/back%5Cslash/epix.pac",
        ),
    ] {
        let actual = file_url(Path::new(path)).unwrap();
        assert_eq!(actual, expected);
        let parsed = url::Url::parse(&actual).unwrap();
        assert_eq!(parsed.query(), None);
        assert_eq!(parsed.fragment(), None);
        assert_eq!(parsed.to_file_path().unwrap(), Path::new(path));
    }
    let path = Path::new(OsStr::from_bytes(b"/tmp/non-utf8-\xff/epix.pac"));
    let actual = file_url(path).unwrap();
    assert_eq!(actual, "file:///tmp/non-utf8-%FF/epix.pac");
    assert_eq!(
        url::Url::parse(&actual).unwrap().to_file_path().unwrap(),
        path
    );
}

#[cfg(windows)]
#[test]
fn windows_drive_and_canonical_drive_pac_urls_match() {
    for (ordinary, canonical, expected) in [
        (
            r"C:\Users\Alice\epix.pac",
            r"\\?\C:\Users\Alice\epix.pac",
            "file:///C:/Users/Alice/epix.pac",
        ),
        (
            r"D:\First Last\#100%20\Zoë\雪\epix.pac",
            r"\\?\D:\First Last\#100%20\Zoë\雪\epix.pac",
            "file:///D:/First%20Last/%23100%2520/Zo%C3%AB/%E9%9B%AA/epix.pac",
        ),
    ] {
        for path in [ordinary, canonical] {
            let actual = file_url(Path::new(path)).unwrap();
            assert_eq!(actual, expected, "{path}");
            let parsed = url::Url::parse(&actual).unwrap();
            assert_eq!(parsed.query(), None);
            assert_eq!(parsed.fragment(), None);
            assert_eq!(parsed.to_file_path().unwrap(), Path::new(ordinary));
        }
    }
}

#[cfg(windows)]
#[test]
fn windows_unc_and_canonical_unc_pac_urls_match() {
    let ordinary = r"\\server.example\Epix Share\#100%20\Zoë\epix.pac";
    let canonical = r"\\?\UNC\server.example\Epix Share\#100%20\Zoë\epix.pac";
    for path in [ordinary, canonical] {
        let actual = file_url(Path::new(path)).unwrap();
        assert_eq!(
            actual,
            "file://server.example/Epix%20Share/%23100%2520/Zo%C3%AB/epix.pac"
        );
        let parsed = url::Url::parse(&actual).unwrap();
        assert_eq!(parsed.host_str(), Some("server.example"));
        assert_eq!(parsed.query(), None);
        assert_eq!(parsed.fragment(), None);
        assert_eq!(parsed.to_file_path().unwrap(), Path::new(ordinary));
    }
}

#[cfg(windows)]
#[test]
fn windows_non_file_prefixes_and_invalid_unicode_are_rejected() {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    for path in [
        r"C:epix.pac",
        r"\epix.pac",
        r"\\.\pipe\epix",
        r"\\?\GLOBALROOT\Device\HarddiskVolume1\epix.pac",
    ] {
        assert_eq!(
            file_url(Path::new(path)).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput,
            "{path}"
        );
    }
    let mut path: Vec<u16> = r"C:\".encode_utf16().collect();
    path.push(0xd800);
    path.extend(r"\epix.pac".encode_utf16());
    assert_eq!(
        file_url(Path::new(&OsString::from_wide(&path)))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidInput
    );
}
