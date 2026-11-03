//! QR codes as a plain matrix: the UI draws it as SVG rectangles, so no HTML
//! or image is ever built from strings (§9.1).

use serde::Serialize;

#[derive(Serialize)]
pub struct Qr {
    pub size: usize,
    pub modules: Vec<bool>,
}

pub fn matrix(text: &str) -> Result<Qr, String> {
    let code = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M)
        .map_err(|_| "Couldn't make the QR code.".to_owned())?;
    Ok(Qr {
        size: code.width(),
        modules: code
            .to_colors()
            .into_iter()
            .map(|c| c == qrcode::Color::Dark)
            .collect(),
    })
}

/// QR for a larger payload (a payment request): lower error correction so it
/// fits; shown full-size on screen, so scanning is reliable.
pub fn matrix_large(text: &str) -> Result<Qr, String> {
    let code = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::L)
        .map_err(|_| "The payment is too large for one QR code (too many coins).".to_owned())?;
    Ok(Qr {
        size: code.width(),
        modules: code
            .to_colors()
            .into_iter()
            .map(|c| c == qrcode::Color::Dark)
            .collect(),
    })
}
