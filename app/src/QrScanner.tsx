// Webcam QR reader: reads frames with jsQR until a code starting with
// `prefix` is seen, then stops the camera and hands the text over. The
// camera runs only while this component is on screen.
//
// Laptops often have two cameras: the normal one and an infrared one for
// Windows Hello, which looks black to apps. So: infrared cameras are avoided,
// the camera can be chosen from a list (remembered on this PC), and an
// all-black picture is detected and explained.
import jsQR from "jsqr";
import { useEffect, useRef, useState } from "react";

const SCAN_EVERY_MS = 200;
const CAMERA_KEY = "qrScanner.cameraId";
const IR = /\b(ir|infrared)\b|windows hello/i;

function cameraText(name: string): string {
  switch (name) {
    case "NotAllowedError":
    case "SecurityError":
      return "Camera access was refused. In Windows: Settings → Privacy & security → Camera, turn on “Camera access” and “Let desktop apps access your camera”.";
    case "NotFoundError":
    case "OverconstrainedError":
      return "No camera found. Connect a webcam, or choose another camera.";
    case "NotReadableError":
    case "AbortError":
      return "The camera is being used by another app (Teams, Zoom, Camera…). Close it and try again.";
    default:
      return "The camera couldn't be started. Try again or choose another camera.";
  }
}

function cameraError(e: unknown): string {
  const name = e instanceof DOMException ? e.name : "";
  return cameraText(name) + (name ? ` (${name})` : "");
}

/** Read a QR code from a photo (e.g. taken with a phone and copied to the
 * PC). Phone photos are large and the code may be small, so a few sizes are
 * tried. The file is read only here; nothing is uploaded anywhere. */
async function readQrFromFile(file: File): Promise<string | null> {
  const bitmap = await createImageBitmap(file);
  try {
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    if (!ctx) return null;
    const longest = Math.max(bitmap.width, bitmap.height);
    for (const target of [1600, 1000, 2400, longest]) {
      const scale = Math.min(1, target / longest);
      canvas.width = Math.max(1, Math.round(bitmap.width * scale));
      canvas.height = Math.max(1, Math.round(bitmap.height * scale));
      ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
      const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const found = jsQR(img.data, img.width, img.height, { inversionAttempts: "attemptBoth" });
      if (found?.data) return found.data.trim();
    }
    return null;
  } finally {
    bitmap.close();
  }
}

function savedCamera(): string | null {
  try {
    return window.localStorage.getItem(CAMERA_KEY);
  } catch {
    return null;
  }
}

function saveCamera(id: string) {
  try {
    window.localStorage.setItem(CAMERA_KEY, id);
  } catch {
    // Not important: the choice just isn't remembered.
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
  const [cameras, setCameras] = useState<MediaDeviceInfo[]>([]);
  const [cameraId, setCameraId] = useState<string | null>(savedCamera());
  const [info, setInfo] = useState<string>("");
  const [black, setBlack] = useState(false);
  const [restart, setRestart] = useState(0);
  const [photoMsg, setPhotoMsg] = useState<string | null>(null);

  const loadPhoto = async (file: File | undefined) => {
    if (!file) return;
    setPhotoMsg("Reading the photo…");
    try {
      const text = await readQrFromFile(file);
      if (!text) {
        setPhotoMsg(
          "No QR code found in that photo. Take it straight on, close enough that the code fills most of the picture, without glare.",
        );
        return;
      }
      if (!text.startsWith(prefix) || text.length > maxLength) {
        setPhotoMsg(wrongHint);
        return;
      }
      setPhotoMsg(null);
      onResult(text);
    } catch {
      setPhotoMsg("That file couldn't be opened as a picture (use a JPG or PNG).");
    }
  };

  useEffect(() => {
    let stream: MediaStream | null = null;
    let timer: number | null = null;
    let startTimer: number | null = null;
    let stopped = false;
    setError(null);
    setNotice(null);
    setBlack(false);
    setInfo("Starting the camera…");
    const stop = () => {
      stopped = true;
      if (startTimer !== null) window.clearTimeout(startTimer);
      if (timer !== null) window.clearInterval(timer);
      stream?.getTracks().forEach((t) => t.stop());
      if (videoRef.current) videoRef.current.srcObject = null;
    };

    const open = async (): Promise<MediaStream> => {
      const size = { width: { ideal: 1280 }, height: { ideal: 720 } };
      if (cameraId) {
        try {
          return await navigator.mediaDevices.getUserMedia({
            video: { deviceId: { exact: cameraId }, ...size },
            audio: false,
          });
        } catch {
          // The remembered camera is gone: fall back to choosing one.
        }
      }
      // Pick a non-infrared camera if the names are known (they are once
      // camera access has been allowed before).
      const devices = (await navigator.mediaDevices.enumerateDevices()).filter((d) => d.kind === "videoinput");
      const normal = devices.find((d) => d.label && !IR.test(d.label));
      try {
        return await navigator.mediaDevices.getUserMedia({
          video: normal ? { deviceId: { exact: normal.deviceId }, ...size } : size,
          audio: false,
        });
      } catch (first) {
        const name = first instanceof DOMException ? first.name : "";
        if (!["NotFoundError", "OverconstrainedError", "NotReadableError", "AbortError"].includes(name)) throw first;
        await new Promise((r) => window.setTimeout(r, 600));
        if (stopped) throw first;
        return navigator.mediaDevices.getUserMedia({ video: true, audio: false });
      }
    };

    const start = () => {
      open()
        .then(async (s) => {
          if (stopped) {
            s.getTracks().forEach((t) => t.stop());
            return;
          }
          stream = s;
          const track = s.getVideoTracks()[0];
          const all = (await navigator.mediaDevices.enumerateDevices()).filter((d) => d.kind === "videoinput");
          if (!stopped) setCameras(all);
          // Opened an infrared camera although a normal one exists: switch.
          const current = track?.getSettings().deviceId;
          const normal = all.find((d) => d.label && !IR.test(d.label));
          if (track && IR.test(track.label) && normal && normal.deviceId !== current) {
            saveCamera(normal.deviceId);
            setCameraId(normal.deviceId);
            return;
          }
          const video = videoRef.current;
          if (!video) return;
          video.srcObject = s;
          void video.play().catch(() => undefined);
          const canvas = document.createElement("canvas");
          const ctx = canvas.getContext("2d", { willReadFrequently: true });
          let frames = 0;
          let darkFrames = 0;
          timer = window.setInterval(() => {
            if (!ctx || video.readyState < 2 || video.videoWidth === 0) return;
            canvas.width = video.videoWidth;
            canvas.height = video.videoHeight;
            ctx.drawImage(video, 0, 0);
            const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
            frames++;
            if (frames === 1) {
              setInfo(`Camera: ${track?.label || "default"} · ${video.videoWidth}×${video.videoHeight}`);
            }
            // Average brightness of a sample of pixels: all black = wrong camera
            // or a covered lens.
            let sum = 0;
            let n = 0;
            for (let i = 0; i < img.data.length; i += 4 * 997) {
              sum += img.data[i] + img.data[i + 1] + img.data[i + 2];
              n++;
            }
            const dark = n > 0 && sum / (n * 3) < 8;
            darkFrames = dark ? darkFrames + 1 : 0;
            setBlack(darkFrames >= 15);
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
        .catch((e) => {
          if (!stopped) {
            setError(cameraError(e));
            setInfo("");
            void navigator.mediaDevices
              .enumerateDevices()
              .then((d) => setCameras(d.filter((x) => x.kind === "videoinput")))
              .catch(() => undefined);
          }
        });
    };
    // Start a moment later: in development React mounts this twice in a row,
    // and opening the same webcam twice at once fails on Windows. The first,
    // instantly-unmounted copy never opens the camera.
    startTimer = window.setTimeout(start, 150);
    return stop;
    // Restart when another camera is chosen; parents remount to scan again.
  }, [cameraId, restart]);

  return (
    <div className="scanner">
      {error && <p className="error">{error}</p>}
      {!error && <video ref={videoRef} muted playsInline className="scanner-video" />}
      {cameras.length > 0 && (
        <label>
          Camera{" "}
          <select
            value={cameraId ?? ""}
            onChange={(e) => {
              saveCamera(e.target.value);
              setCameraId(e.target.value);
            }}
          >
            <option value="" disabled>
              Choose…
            </option>
            {cameras.map((c, i) => (
              <option key={c.deviceId || i} value={c.deviceId}>
                {c.label || `Camera ${i + 1}`}
              </option>
            ))}
          </select>
        </label>
      )}
      {black && (
        <p className="warning">
          The camera picture is completely black. Choose another camera above (laptops often also have an infrared
          camera for face login, which looks black), or check that the lens isn't covered.
        </p>
      )}
      {!error &&
        (notice ? (
          <p className="warning">{notice}</p>
        ) : (
          <p className="hint">
            Looking for the QR code… Hold the tablet 20–40 cm from the webcam, straight on, with its screen brightness
            up.
          </p>
        ))}
      {info && <p className="hint">{info}</p>}
      <div className="button-row">
        <button
          className="secondary"
          onClick={() => {
            setCameras([]);
            setRestart((n) => n + 1);
          }}
        >
          Look for cameras again
        </button>
      </div>
      <p className="hint">
        No working webcam? Use your phone as one (Windows 11: Settings → Bluetooth &amp; devices → Mobile devices,
        or DroidCam), then press “Look for cameras again” and choose it above. Or take a photo of the tablet's QR code
        with your phone, copy it to this PC, and load it here:
      </p>
      <label>
        Load a photo of the QR code{" "}
        <input type="file" accept="image/png,image/jpeg,image/webp,image/bmp" onChange={(e) => void loadPhoto(e.target.files?.[0])} />
      </label>
      {photoMsg && <p className="warning">{photoMsg}</p>}
      <button className="secondary" onClick={onCancel}>
        Cancel (turns the camera off)
      </button>
    </div>
  );
}
