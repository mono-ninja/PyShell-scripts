#!/usr/bin/env python3
"""tts-audio/main.py — text to speech, on your machine.

[Kokoro](https://github.com/thewh1teagle/kokoro-onnx) is a small
neural TTS model that runs offline through ONNX Runtime: no API keys,
no cloud, the text never leaves the machine. This script wraps it the
way the collection handles heavy prerequisites — the playwright
pattern from Tech Stack, sharpened:

- **kokoro-onnx not installed** → exit 1 with the Prepare Env /
  pip line (the lazy import keeps argparse and the introspect guard
  working without it);
- **models not downloaded** → exit 1 with the exact `--download-models`
  instruction — **unless** that flag is set, in which case the chosen
  model (~80–310 MB by variant) and the voices file land in the cache
  dir first, with a progress bar.

A missing prerequisite is a missing result: both failure states are
exit 1, never a warning-plus-exit-0.

The voice's first letter encodes its language (`a`/`b` English,
`e` Spanish, `f` French, `i` Italian, `j` Japanese, `z` Chinese) —
the phonemizer language is derived from it automatically. The WAV
lands as the `speech.wav` artifact.

Exit codes: 0 = the audio was written, 1 = prerequisite missing or
synthesis failed, 2 = bad arguments (empty/oversized text, unknown
voice, bad speed).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

try:  # lazy — the guard and argparse run before the dependency check
    from kokoro_onnx import Kokoro  # noqa: F401
    HAVE_KOKORO = True
except ImportError:  # pragma: no cover — environment-dependent
    HAVE_KOKORO = False

BASE_URL = ("https://github.com/thewh1teagle/kokoro-onnx/releases/"
            "download/model-files-v1.0")
MODEL_FILES = {
    "int8": "kokoro-v1.0.int8.onnx",
    "fp16": "kokoro-v1.0.fp16.onnx",
    "full": "kokoro-v1.0.onnx",
}
VOICES_FILE = "voices-v1.0.bin"

# The voice's first letter → the phonemizer language.
VOICE_LANG = {
    "a": "en-us", "b": "en-gb", "e": "es-es", "f": "fr-fr",
    "h": "hi-in", "i": "it-it", "j": "ja-jp", "p": "pt-br",
    "z": "zh-cn",
}
MAX_TEXT = 5000
DEFAULT_CACHE = Path.home() / ".cache" / "pyshell" / "tts-audio"


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# ---------------------------------------------------------------------------
# Model management (the two failure states live here)
# ---------------------------------------------------------------------------

def model_paths(models_dir: Path, variant: str) -> tuple[Path, Path]:
    return (models_dir / MODEL_FILES[variant],
            models_dir / VOICES_FILE)


def download_with_progress(url: str, dest: Path) -> None:
    """One file, progress events per whole percent (the guide's rate
    limit), to a .part file renamed on success — a killed download
    never leaves a corrupt model behind."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_suffix(dest.suffix + ".part")
    last_pct = -1

    def hook(count, block_size, total_size):
        nonlocal last_pct
        if total_size > 0:
            pct = min(int(count * block_size * 100 / total_size), 100)
            if pct != last_pct:
                last_pct = pct
                emit({"type": "progress", "pct": pct,
                      "message": f"downloading {dest.name} · {pct}%"})

    log(f"  downloading {dest.name} from {url}")
    urllib.request.urlretrieve(url, str(part), reporthook=hook)
    part.rename(dest)


def ensure_models(models_dir: Path, variant: str,
                  allow_download: bool) -> tuple[Path, Path] | None:
    """(model, voices) when both exist — downloading first when
    allowed. None means "missing and not allowed to fetch": the exit-1
    prerequisite state."""
    model, voices = model_paths(models_dir, variant)
    if model.exists() and voices.exists():
        return model, voices
    if not allow_download:
        return None
    if not model.exists():
        download_with_progress(f"{BASE_URL}/{MODEL_FILES[variant]}",
                               model)
    if not voices.exists():
        download_with_progress(f"{BASE_URL}/{VOICES_FILE}", voices)
    return model, voices


# ---------------------------------------------------------------------------
# Language derivation (pure)
# ---------------------------------------------------------------------------

def lang_for_voice(voice: str) -> str | None:
    """The phonemizer language from the voice's first letter; None for
    an unknown prefix."""
    return VOICE_LANG.get((voice or "")[:1].lower())


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="TTS Audio — text to speech on your machine via "
                    "Kokoro ONNX (offline, no keys)")
    parser.add_argument("--text", required=True,
                        help="the text to speak")
    parser.add_argument("--voice", default="af_heart",
                        help="Kokoro voice, e.g. af_heart (default), "
                             "am_michael, bf_emma, ef_dora, zf_xiaobei")
    parser.add_argument("--speed", type=float, default=1.0,
                        help="speech rate 0.5–2.0 (default 1.0)")
    parser.add_argument("--model-variant",
                        choices=["int8", "fp16", "full"], default="int8",
                        help="model size/quality tradeoff (default int8)")
    parser.add_argument("--download-models", action="store_true",
                        help="fetch the model and voices into the cache "
                             "dir when missing (tens to ~310 MB)")
    parser.add_argument("--models-dir", default="",
                        help="where the models live (default "
                             "~/.cache/pyshell/tts-audio)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no synthesis, no downloads",
              flush=True)
        return 0

    text = (args.text or "").strip()
    if not text:
        print("✗ the text is empty", file=sys.stderr, flush=True)
        return 2
    if len(text) > MAX_TEXT:
        print(f"✗ the text is {len(text)} characters; the cap is "
              f"{MAX_TEXT} (CPU synthesis is roughly real-time)",
              file=sys.stderr, flush=True)
        return 2
    lang = lang_for_voice(args.voice)
    if lang is None:
        print(f"✗ unknown voice {args.voice!r} — the first letter "
              f"must be one of {', '.join(sorted(VOICE_LANG))} "
              f"(af_heart, am_michael, bf_emma, ef_dora, …)",
              file=sys.stderr, flush=True)
        return 2
    if not (0.5 <= args.speed <= 2.0):
        print("✗ --speed must be 0.5–2.0", file=sys.stderr, flush=True)
        return 2

    # Failure state 1: the package.
    if not HAVE_KOKORO:
        print("✗ kokoro-onnx is not installed — press Prepare Env in "
              "PyShell (or `python3 -m pip install -r "
              "requirements.txt`) and re-run", file=sys.stderr,
              flush=True)
        return 1

    models_dir = Path(args.models_dir) if args.models_dir \
        else DEFAULT_CACHE
    status(f"Loading the {args.model_variant} model from {models_dir}")
    paths = ensure_models(models_dir, args.model_variant,
                          args.download_models)

    # Failure state 2: the models.
    if paths is None:
        need = MODEL_FILES[args.model_variant]
        print(f"✗ the model files are missing in {models_dir}:\n"
              f"    {need} + {VOICES_FILE}\n"
              f"  re-run with --download-models to fetch them "
              f"(~80–310 MB, one time), or place the files there "
              f"yourself", file=sys.stderr, flush=True)
        emit({"type": "markdown", "content":
              "## Prerequisite missing\n\nThe Kokoro model files "
              f"aren't in `{models_dir}`. Tick **Download the models "
              "if missing** and re-run — a one-time fetch "
              "(~80–310 MB by variant) into that cache dir."})
        return 1

    model_path, voices_path = paths
    log(f"  voice {args.voice} ({lang}) · speed {args.speed} · "
        f"{model_path.name}")
    emit({"type": "progress", "pct": 5,
          "message": "loading the model (10–30 s on first load)"})

    from kokoro_onnx import Kokoro  # re-import for the type checker
    try:
        kokoro = Kokoro(str(model_path), str(voices_path))
    except Exception as exc:
        print(f"✗ the model failed to load ({type(exc).__name__}: "
              f"{exc}) — a corrupt download? Delete {model_path} and "
              f"re-run with --download-models", file=sys.stderr,
              flush=True)
        return 1

    status("Synthesizing (roughly real-time on CPU)")
    emit({"type": "progress", "pct": 40, "message": "synthesizing"})
    started = time.monotonic()
    try:
        samples, sample_rate = kokoro.create(
            text, voice=args.voice, speed=args.speed, lang=lang)
    except Exception as exc:
        print(f"✗ synthesis failed ({type(exc).__name__}: {exc})",
              file=sys.stderr, flush=True)
        return 1
    synth_s = time.monotonic() - started

    output_dir = os.environ.get("PYSHELL_OUTPUT_DIR") or os.getcwd()
    os.makedirs(output_dir, exist_ok=True)
    out_path = Path(output_dir) / "speech.wav"
    try:
        import soundfile as sf
        sf.write(str(out_path), samples, sample_rate)
    except Exception as exc:
        print(f"✗ could not write the WAV ({type(exc).__name__})",
              file=sys.stderr, flush=True)
        return 1

    size_mb = out_path.stat().st_size / 1_000_000
    duration_s = len(samples) / sample_rate if hasattr(samples,
                                                       "__len__") else 0
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit({"type": "markdown", "content":
          f"## 🎙️ speech.wav written\n\n"
          f"- Voice: **{args.voice}** ({lang}) · speed {args.speed}\n"
          f"- Text: {len(text)} character(s)\n"
          f"- Audio: {duration_s:.1f} s · {size_mb:.1f} MB · "
          f"{sample_rate} Hz\n"
          f"- Synthesis took {synth_s:.1f} s on this machine\n\n"
          f"_Offline: the text never left the machine; the model ran "
          f"through ONNX Runtime._"})
    status(f"speech.wav · {duration_s:.1f} s of audio")
    log(f"← speech.wav ({duration_s:.1f} s, {size_mb:.1f} MB) in "
        f"{synth_s:.1f} s of synthesis")
    return 0


if __name__ == "__main__":
    sys.exit(main())
