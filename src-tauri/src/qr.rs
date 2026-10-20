//! Reading `otpauth://` links out of QR images (BRIEF §7.2): the "screenshot
//! the QR on the enrollment page" flow. The image bytes come from the webview
//! (file picker, drag and drop or paste); the decoded link never goes back.

use image::{ImageReader, Limits};
use std::io::Cursor;
use zeroize::Zeroizing;

pub const MAX_BYTES: usize = 20 * 1024 * 1024;
const MAX_SIDE: u32 = 8000;

/// The first `otpauth...` link found in the image.
pub fn decode(bytes: &[u8]) -> Result<Zeroizing<String>, String> {
    if bytes.len() > MAX_BYTES {
        return Err("That image is too large (20 MB max). Try a tighter screenshot.".into());
    }
    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| unreadable())?;
    // Refuse absurd dimensions before allocating for them.
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_SIDE);
    limits.max_image_height = Some(MAX_SIDE);
    limits.max_alloc = Some(512 * 1024 * 1024);
    reader.limits(limits);
    let img = reader.decode().map_err(|_| unreadable())?.to_luma8();

    let (w, h) = (img.width() as usize, img.height() as usize);
    let mut prepared =
        rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| img.get_pixel(x as u32, y as u32).0[0]);
    let grids = prepared.detect_grids();
    if grids.is_empty() {
        return Err("No QR code found in that image.".into());
    }
    let mut decoded_other = false;
    for grid in grids {
        if let Ok((_, content)) = grid.decode() {
            let content = Zeroizing::new(content);
            if content.trim_start().to_ascii_lowercase().starts_with("otpauth") {
                return Ok(content);
            }
            decoded_other = true;
        }
    }
    Err(if decoded_other {
        "That QR code isn't a 2FA setup code (it has no otpauth:// link).".into()
    } else {
        "Found a QR code but couldn't read it. Try a sharper or larger screenshot.".into()
    })
}

fn unreadable() -> String {
    "Couldn't read that image. Use a PNG or JPEG screenshot.".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{GrayImage, ImageFormat, Luma};

    const URI: &str = "otpauth://totp/Acme:me@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Acme";

    /// A real QR code as an image, `scale` pixels per module, with a quiet zone.
    fn qr_image(data: &str, scale: u32) -> GrayImage {
        let code = qrcode::QrCode::new(data).unwrap();
        let w = code.width() as i64;
        let colors = code.to_colors();
        let quiet = 4i64;
        let side = ((w + 2 * quiet) as u32) * scale;
        GrayImage::from_fn(side, side, |x, y| {
            let (mx, my) = ((x / scale) as i64 - quiet, (y / scale) as i64 - quiet);
            let dark = (0..w).contains(&mx)
                && (0..w).contains(&my)
                && colors[(my * w + mx) as usize] == qrcode::Color::Dark;
            Luma([if dark { 0 } else { 255 }])
        })
    }

    fn encode(img: &GrayImage, format: ImageFormat) -> Vec<u8> {
        let mut out = Vec::new();
        img.write_to(&mut Cursor::new(&mut out), format).unwrap();
        out
    }

    #[test]
    fn decodes_otpauth_from_png() {
        let png = encode(&qr_image(URI, 6), ImageFormat::Png);
        assert_eq!(decode(&png).unwrap().as_str(), URI);
    }

    #[test]
    fn decodes_otpauth_from_jpeg() {
        let jpg = encode(&qr_image(URI, 8), ImageFormat::Jpeg);
        assert_eq!(decode(&jpg).unwrap().as_str(), URI);
    }

    #[test]
    fn finds_the_qr_inside_a_bigger_screenshot() {
        // A QR code in the middle of an otherwise blank "page".
        let qr = qr_image(URI, 4);
        let mut page = GrayImage::from_pixel(900, 700, Luma([235]));
        image::imageops::overlay(&mut page, &qr, 300, 200);
        assert_eq!(decode(&encode(&page, ImageFormat::Png)).unwrap().as_str(), URI);
    }

    #[test]
    fn non_2fa_qr_is_explained() {
        let png = encode(&qr_image("https://example.com/menu", 6), ImageFormat::Png);
        assert!(decode(&png).unwrap_err().contains("isn't a 2FA setup code"));
    }

    #[test]
    fn google_export_qr_is_passed_through_for_a_clear_error() {
        // parse_uri explains that otpauth-migration links aren't supported yet.
        let link = "otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8";
        let png = encode(&qr_image(link, 6), ImageFormat::Png);
        assert_eq!(decode(&png).unwrap().as_str(), link);
    }

    #[test]
    fn image_without_qr_is_explained() {
        let blank = encode(&GrayImage::from_pixel(200, 200, Luma([255])), ImageFormat::Png);
        assert!(decode(&blank).unwrap_err().contains("No QR code"));
    }

    #[test]
    fn garbage_and_oversized_input_are_refused() {
        assert!(decode(b"definitely not an image").unwrap_err().contains("Couldn't read"));
        assert!(decode(&vec![0u8; MAX_BYTES + 1]).unwrap_err().contains("too large"));
    }

    #[test]
    fn absurd_dimensions_are_refused_before_allocating() {
        // A tiny PNG header claiming 100000x100000 pixels.
        let mut png = encode(&GrayImage::from_pixel(1, 1, Luma([255])), ImageFormat::Png);
        // IHDR width/height live at bytes 16..24.
        png[16..20].copy_from_slice(&100_000u32.to_be_bytes());
        png[20..24].copy_from_slice(&100_000u32.to_be_bytes());
        assert!(decode(&png).is_err());
    }
}
