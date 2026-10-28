import jsQR from 'jsqr';

/** Bounded local sampling; never uploads media or opens decoded URLs. */
export function readQr(file: File, signal: AbortSignal, progress: (message: string) => void): Promise<string | null> {
  return new Promise(resolve => {
    if (signal.aborted) { resolve(null); return; }
    const url = URL.createObjectURL(file);
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    let media: HTMLImageElement | HTMLVideoElement;
    let done = false;
    const finish = (value: string | null) => {
      if (done) return; done = true;
      clearTimeout(timer); signal.removeEventListener('abort', abort);
      if (media) { media.onload = null; media.onerror = null; if (media instanceof HTMLVideoElement) { media.onloadeddata = null; media.onseeked = null; media.pause(); media.removeAttribute('src'); media.load(); } else media.src = ''; }
      URL.revokeObjectURL(url); canvas.width = canvas.height = 0; resolve(value);
    };
    const abort = () => finish(null);
    const timer = setTimeout(abort, 20000);
    signal.addEventListener('abort', abort, { once: true });
    if (!ctx) { finish(null); return; }
    const decode = (source: HTMLImageElement | HTMLVideoElement) => {
      const width = source instanceof HTMLVideoElement ? source.videoWidth : source.naturalWidth;
      const height = source instanceof HTMLVideoElement ? source.videoHeight : source.naturalHeight;
      if (!width || !height || width * height > 50_000_000) throw new Error('Dimensões inválidas');
      const scale = Math.min(1, 1400 / Math.max(width, height));
      canvas.width = Math.max(1, Math.round(width * scale)); canvas.height = Math.max(1, Math.round(height * scale));
      ctx.drawImage(source, 0, 0, canvas.width, canvas.height);
      return jsQR(ctx.getImageData(0, 0, canvas.width, canvas.height).data, canvas.width, canvas.height)?.data ?? null;
    };
    if (file.type.startsWith('image/')) {
      const image = new Image(); media = image;
      image.onload = () => { try { finish(decode(image)); } catch { finish(null); } };
      image.onerror = abort; image.src = url;
    } else if (file.type.startsWith('video/')) {
      const video = document.createElement('video'); media = video;
      video.muted = true; video.preload = 'auto'; video.playsInline = true;
      let frame = 0;
      const sample = () => {
        if (done) return;
        try {
          progress(`Lendo QR localmente: amostra ${frame + 1} de até 8.`);
          const code = decode(video);
          if (code || ++frame >= 8 || !Number.isFinite(video.duration) || video.duration <= 0.1) { finish(code); return; }
          const next = (video.duration - 0.05) * frame / 7;
          if (Math.abs(video.currentTime - next) < 0.001) { finish(null); return; }
          video.currentTime = next;
        } catch { finish(null); }
      };
      video.onloadeddata = sample; video.onseeked = sample; video.onerror = abort; video.src = url;
    } else finish(null);
  });
}
