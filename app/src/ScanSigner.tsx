// "Add from tablet": read the signer tablet's watch-only export QR with the
// PC webcam (or paste its text), show what it contains for comparison with
// the tablet screen, then add it. Rust checks the export again at each step;
// this file only reads the QR and shows results.
import jsQR from "jsqr";
import { useEffect, useRef, useState } from "react";
import { api, errorText, type SignerWalletPreview, type WalletView } from "./api";
import { ChunkedAddress } from "./Receive";

const PREFIX = "WWX1:";
const SCAN_EVERY_MS = 200;
/** Long enough for a real export (under 500 characters). */
const MAX_TEXT = 2000;

function cameraError(e: unknown): string {
  const name = e instanceof DOMException ? e.name : "";
  switch (name) {
    case "NotAllowedError":
    case "SecurityError":
      return (
        "Camera access was refused. In Windows: Settings → Privacy & security → Camera, turn on " +
        "“Camera access” and “Let desktop apps access your camera”, then try again."
      );
    case "NotFoundError":
    case "OverconstrainedError":
      return "No camera found. Connect a webcam, or paste the export text instead.";
    case "NotReadableError":
      return "The camera is being used by another app. Close that app and try again.";
    default:
      return "The camera couldn't be started. Try again, or paste the export text instead.";
  }
}

type Stage = { kind: "idle" } | { kind: "scanning" } | { kind: "checking" } | { kind: "preview"; text: string; p: SignerWalletPreview };

export function AddFromSigner({ onAdded }: { onAdded: (w: WalletView[]) => void }) {
  const [stage, setStage] = useState<Stage>({ kind: "idle" });
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [pasted, setPasted] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const timerRef = useRef<number | null>(null);

  /** Turn the camera fully off (the light on the webcam goes out). */
  const stopCamera = () => {
    if (timerRef.current !== null) window.clearInterval(timerRef.current);
    timerRef.current = null;
    streamRef.current?.getTracks().forEach((t) => t.stop());
    streamRef.current = null;
    if (videoRef.current) videoRef.current.srcObject = null;
  };

  // Never leave the camera on when this panel goes away (page change, lock).
  useEffect(() => stopCamera, []);

  const check = async (text: string) => {
    setStage({ kind: "checking" });
    setError(null);
    setNotice(null);
    setConfirmed(false);
    try {
      const p = await api.previewSignerWallet(text);
      setStage({ kind: "preview", text, p });
    } catch (e) {
      setError(errorText(e));
      setStage({ kind: "idle" });
    }
  };

  const startCamera = async () => {
    setError(null);
    setNotice(null);
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { width: { ideal: 1280 }, height: { ideal: 720 } },
        audio: false,
      });
      streamRef.current = stream;
      setStage({ kind: "scanning" });
    } catch (e) {
      stopCamera();
      setError(cameraError(e));
    }
  };

  // Once the <video> is on screen, attach the stream and scan frames.
  useEffect(() => {
    if (stage.kind !== "scanning") return;
    const video = videoRef.current;
    const stream = streamRef.current;
    if (!video || !stream) return;
    video.srcObject = stream;
    void video.play().catch(() => undefined);
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    timerRef.current = window.setInterval(() => {
      if (!ctx || video.readyState < 2 || video.videoWidth === 0) return;
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      ctx.drawImage(video, 0, 0);
      const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const found = jsQR(img.data, img.width, img.height, { inversionAttempts: "dontInvert" });
      if (!found || !found.data) return;
      const text = found.data.trim();
      if (!text.startsWith(PREFIX) || text.length > MAX_TEXT) {
        setNotice("That QR code isn't a wallet export from the signer tablet. Show the tablet's export QR.");
        return;
      }
      stopCamera();
      void check(text);
    }, SCAN_EVERY_MS);
    return () => {
      if (timerRef.current !== null) window.clearInterval(timerRef.current);
      timerRef.current = null;
    };
  }, [stage.kind]);

  const cancel = () => {
    stopCamera();
    setStage({ kind: "idle" });
    setNotice(null);
    setConfirmed(false);
  };

  const add = async () => {
    if (stage.kind !== "preview") return;
    setBusy(true);
    setError(null);
    try {
      onAdded(await api.addSignerWallet(stage.text));
      setStage({ kind: "idle" });
      setPasted("");
      setConfirmed(false);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card form">
      <h3>Add a wallet from the signer tablet</h3>
      <p className="hint">
        On the tablet: open the wallet → <strong>Show export QR for the PC</strong>. Hold the tablet in front of this
        PC's webcam. The QR holds public data only.
      </p>
      {error && <p className="error">{error}</p>}

      {stage.kind === "idle" && (
        <>
          <button onClick={() => void startCamera()}>Scan with webcam</button>
          <details>
            <summary className="muted">No webcam? Paste the export text instead</summary>
            <label>
              Export text <span className="muted">(starts with {PREFIX})</span>
              <textarea
                value={pasted}
                onChange={(e) => setPasted(e.target.value.slice(0, MAX_TEXT))}
                rows={4}
                className="mono"
                autoComplete="off"
                spellCheck={false}
              />
            </label>
            <button disabled={pasted.trim() === ""} onClick={() => void check(pasted)}>
              Check export
            </button>
          </details>
        </>
      )}

      {stage.kind === "scanning" && (
        <div className="scanner">
          <video ref={videoRef} muted playsInline className="scanner-video" />
          {notice ? <p className="warning">{notice}</p> : <p className="hint">Looking for the export QR…</p>}
          <button className="secondary" onClick={cancel}>
            Cancel (turns the camera off)
          </button>
        </div>
      )}

      {stage.kind === "checking" && <p className="hint">Checking the export…</p>}

      {stage.kind === "preview" && (
        <div className="signer-preview">
          <p>
            <strong>{stage.p.label}</strong> <span className="muted">· {stage.p.id} · {stage.p.tier_name}</span>
          </p>
          {stage.p.problem && <p className="error">Can't add: {stage.p.problem}</p>}
          <p className="hint">
            Compare each value below with the <strong>tablet screen</strong> (wallet → Verify an address). Every
            character must match. If anything differs, cancel: don't use this wallet.
          </p>
          <dl>
            <dt>Fingerprint</dt>
            <dd className="mono big-address">
              <strong>{stage.p.fingerprint}</strong>
            </dd>
            <dt>Bitcoin receive #0</dt>
            <dd>
              <ChunkedAddress a={stage.p.btc_first_address} />
            </dd>
            <dt>Ethereum</dt>
            <dd>
              <ChunkedAddress a={stage.p.eth} />
            </dd>
            <dt>TRON</dt>
            <dd>
              <ChunkedAddress a={stage.p.tron} />
            </dd>
          </dl>
          <label className="confirm">
            <input
              type="checkbox"
              checked={confirmed}
              disabled={!!stage.p.problem}
              onChange={(e) => setConfirmed(e.target.checked)}
            />
            I compared the fingerprint and all three addresses with the tablet screen, and they match.
          </label>
          <div className="button-row">
            <button disabled={!confirmed || busy || !!stage.p.problem} onClick={() => void add()}>
              Add this wallet
            </button>
            <button className="secondary" onClick={cancel}>
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
