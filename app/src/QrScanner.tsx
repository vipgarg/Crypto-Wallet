// Webcam QR reader: reads frames with jsQR until a code starting with
// `prefix` is seen, then stops the camera and hands the text over. The
// camera runs only while this component is on screen.
import jsQR from "jsqr";
import { useEffect, useRef, useState } from "react";

const SCAN_EVERY_MS = 200;

function cameraError(e: unknown): string {
  const name = e instanceof DOMException ? e.name : "";
  switch (name) {
    case "NotAllowedError":
    case "SecurityError":
      return "Camera access was refused. In Windows: Settings → Privacy & security → Camera, turn on “Camera access” and “Let desktop apps access your camera”.";
    case "NotFoundError":
    case "OverconstrainedError":
      return "No camera found. Connect a webcam, or paste the text instead.";
    case "NotReadableError":
      return "The camera is being used by another app. Close that app and try again.";
    default:
      return "The camera couldn't be started. Try again, or paste the text instead.";
  }
}

export function QrScanner({
  prefix,
  maxLength,
  wrongHint,
  onResult,
  onCancel,
}: {
  prefix: string;
  maxLength: number;
  wrongHint: string;
  onResult: (text: string) => void;
  onCancel: () => void;
}) {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    let stream: MediaStream | null = null;
    let timer: number | null = null;
    let stopped = false;
    const stop = () => {
      stopped = true;
      if (timer !== null) window.clearInterval(timer);
      stream?.getTracks().forEach((t) => t.stop());
      if (videoRef.current) videoRef.current.srcObject = null;
    };
    navigator.mediaDevices
      .getUserMedia({ video: { width: { ideal: 1920 }, height: { ideal: 1080 } }, audio: false })
      .then((s) => {
        if (stopped) {
          s.getTracks().forEach((t) => t.stop());
          return;
        }
        stream = s;
        const video = videoRef.current;
        if (!video) return;
        video.srcObject = s;
        void video.play().catch(() => undefined);
        const canvas = document.createElement("canvas");
        const ctx = canvas.getContext("2d", { willReadFrequently: true });
        timer = window.setInterval(() => {
          if (!ctx || video.readyState < 2 || video.videoWidth === 0) return;
          canvas.width = video.videoWidth;
          canvas.height = video.videoHeight;
          ctx.drawImage(video, 0, 0);
          const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const found = jsQR(img.data, img.width, img.height, { inversionAttempts: "dontInvert" });
          const text = found?.data?.trim();
          if (!text) return;
          if (!text.startsWith(prefix) || text.length > maxLength) {
            setNotice(wrongHint);
            return;
          }
          stop();
          onResult(text);
        }, SCAN_EVERY_MS);
      })
      .catch((e) => setError(cameraError(e)));
    return stop;
    // Start once per mount; parents remount to scan again.
  }, []);

  return (
    <div className="scanner">
      {error ? (
        <p className="error">{error}</p>
      ) : (
        <>
          <video ref={videoRef} muted playsInline className="scanner-video" />
          {notice ? <p className="warning">{notice}</p> : <p className="hint">Looking for the QR code…</p>}
        </>
      )}
      <button className="secondary" onClick={onCancel}>
        Cancel (turns the camera off)
      </button>
    </div>
  );
}
