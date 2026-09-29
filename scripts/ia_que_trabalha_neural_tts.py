from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

SEGMENTS = [
    {"id": 1, "start_s": 0.000000, "end_s": 1.931202, "text": "Essa planilha tem três erros. Você consegue achar em dez segundos?"},
    {"id": 2, "start_s": 2.323039, "end_s": 5.046440, "text": "Pare de revisar linha por linha. Use a IA para reduzir o espaço de busca."},
    {"id": 3, "start_s": 5.411519, "end_s": 7.706576, "text": "Selecione os dados e aplique o prompt."},
    {"id": 4, "start_s": 7.909660, "end_s": 11.988753, "text": "Encontre duplicados, datas inválidas e valores muito fora do padrão."},
    {"id": 5, "start_s": 12.184308, "end_s": 15.016735, "text": "Retorne a linha, o problema e o motivo."},
    {"id": 6, "start_s": 15.438458, "end_s": 18.934422, "text": "A análise encontrou três suspeitas. Você continua decidindo."},
    {"id": 7, "start_s": 19.209070, "end_s": 20.349524, "text": "A IA não corrigiu nada."},
    {"id": 8, "start_s": 20.524671, "end_s": 24.102902, "text": "Ela mostrou onde olhar primeiro: duplicidade, data inválida e valor fora do padrão."},
    {"id": 9, "start_s": 24.512562, "end_s": 25.439909, "text": "A IA filtra. Você valida."},
    {"id": 10, "start_s": 25.868073, "end_s": 28.290567, "text": "Confira sempre no arquivo original."},
]

KOKORO_VOICES = ("pf_dora", "pm_alex")
PIPER_VOICES = ("pt_BR-cadu-medium", "pt_BR-faber-medium")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def wav_info(path: Path) -> dict:
    import soundfile as sf
    info = sf.info(str(path))
    data, _ = sf.read(str(path), dtype="float32", always_2d=False)
    import numpy as np
    rms = float(np.sqrt(np.mean(np.square(data)))) if len(data) else 0.0
    return {
        "samplerate": int(info.samplerate),
        "frames": int(info.frames),
        "duration_s": round(float(info.duration), 6),
        "channels": int(info.channels),
        "rms": round(rms, 8),
        "sha256": sha256(path),
    }


def generate_kokoro(out: Path) -> list[dict]:
    import numpy as np
    import soundfile as sf
    try:
        import espeakng_loader
        espeakng_loader.make_library_available()
        os.environ.setdefault("PHONEMIZER_ESPEAK_LIBRARY", str(espeakng_loader.get_library_path()))
        os.environ.setdefault("PHONEMIZER_ESPEAK_PATH", str(espeakng_loader.get_data_path()))
    except Exception:
        pass

    from kokoro import KPipeline
    pipeline = KPipeline(lang_code="p")
    results: list[dict] = []
    for voice in KOKORO_VOICES:
        voice_dir = out / voice
        voice_dir.mkdir(parents=True, exist_ok=True)
        for segment in SEGMENTS:
            pieces = []
            generator = pipeline(segment["text"], voice=voice, speed=1.0)
            for _, _, audio in generator:
                pieces.append(np.asarray(audio, dtype=np.float32))
            if not pieces:
                raise RuntimeError(f"kokoro_empty_audio:{voice}:{segment['id']}")
            audio = np.concatenate(pieces)
            wav = voice_dir / f"segment_{segment['id']:02d}.wav"
            sf.write(str(wav), audio, 24000)
            meta = wav_info(wav)
            if meta["duration_s"] <= 0.2 or meta["rms"] <= 0.001:
                raise RuntimeError(f"kokoro_invalid_audio:{voice}:{segment['id']}")
            results.append({"voice": voice, "segment": segment, "file": str(wav), **meta})
    return results


def generate_piper(out: Path) -> list[dict]:
    results: list[dict] = []
    for voice in PIPER_VOICES:
        voice_dir = out / voice
        voice_dir.mkdir(parents=True, exist_ok=True)
        for segment in SEGMENTS:
            wav = voice_dir / f"segment_{segment['id']:02d}.wav"
            cmd = [
                sys.executable,
                "-m",
                "piper",
                "--model",
                voice,
                "--output_file",
                str(wav),
            ]
            proc = subprocess.run(
                cmd,
                input=segment["text"],
                text=True,
                capture_output=True,
                timeout=180,
                check=False,
            )
            if proc.returncode != 0:
                raise RuntimeError(
                    f"piper_failed:{voice}:{segment['id']}:rc={proc.returncode}:"
                    f"{proc.stderr[-1000:]}"
                )
            if not wav.exists():
                raise RuntimeError(f"piper_missing_audio:{voice}:{segment['id']}")
            meta = wav_info(wav)
            if meta["duration_s"] <= 0.2 or meta["rms"] <= 0.001:
                raise RuntimeError(f"piper_invalid_audio:{voice}:{segment['id']}")
            results.append({"voice": voice, "segment": segment, "file": str(wav), **meta})
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", choices=("kokoro", "piper"), required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    evidence_path = Path(args.evidence)
    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    result = {
        "ok": False,
        "engine": args.engine,
        "host": os.environ.get("COMPUTERNAME", ""),
        "github_sha": os.environ.get("GITHUB_SHA", ""),
        "paid_service": False,
        "production_touched": False,
        "secrets_read": False,
        "segments_expected": len(SEGMENTS),
        "files": [],
    }
    try:
        files = generate_kokoro(out) if args.engine == "kokoro" else generate_piper(out)
        expected = len(SEGMENTS) * (len(KOKORO_VOICES) if args.engine == "kokoro" else len(PIPER_VOICES))
        if len(files) != expected:
            raise RuntimeError(f"file_count_mismatch:{len(files)}:{expected}")
        result["files"] = files
        result["voices"] = sorted({item["voice"] for item in files})
        result["files_generated"] = len(files)
        result["ok"] = True
    except Exception as exc:
        result["error_type"] = type(exc).__name__
        result["error"] = str(exc)[:2000]
    evidence_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: result.get(k) for k in ("ok", "engine", "voices", "files_generated", "error_type", "error")}, ensure_ascii=False))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
