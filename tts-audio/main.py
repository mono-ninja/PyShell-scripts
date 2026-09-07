#!/usr/bin/env python3
"""tts-audio/main.py — text to speech, on your machine.

[Kokoro](https://github.com/thewh1teagle/kokoro-onnx) is a small
neural TTS model that runs offline through ONNX Runtime: no API keys,
no cloud, the text never leaves the machine. This script wraps it the
way the collection handles heavy prerequisites — the playwright
pattern from Tech Stack, sharpened:

- **kokoro-onnx or soundfile not installed** → exit 1 naming the one
  that is missing, with the Prepare Env / pip line (the lazy imports
  keep argparse and the introspect guard working without them);
- **models not downloaded** → exit 1 with the exact `--download-models`
  instruction — **unless** that flag is set, in which case the chosen
  model (~80–310 MB by variant) and the voices file land in the cache
  dir first, with a progress bar;
- **the download itself fails** → exit 1 with one `✗` line rather than
  a traceback, and the `.part` file removed.

A missing prerequisite is a missing result: every one of these is
exit 1, never a warning-plus-exit-0.

`--list-voices` prints every name the voices file carries (dozens;
the manifest curates a dozen) grouped by language, and needs only the
~27 MB voices file — never the model.

The voice's first letter encodes its language (`a`/`b` English,
`e` Spanish, `f` French, `h` Hindi, `i` Italian, `j` Japanese,
`p` Portuguese, `z` Mandarin) — the phonemizer language is derived
from it automatically. The WAV lands as the `speech.wav` artifact.

Exit codes: 0 = the audio was written, 1 = prerequisite missing (the
packages, the models, a download that failed) or synthesis failed,
2 = bad arguments (empty/oversized text, unknown voice, bad speed).
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

# Lazy — the guard and argparse run before the dependency check. Both
# wheels are checked here, by name: soundfile is needed only at the very
# end, and discovering it missing after minutes of synthesis would throw
# the audio away.
MISSING: list[str] = []
try:
    from kokoro_onnx import Kokoro  # noqa: F401
except ImportError:  # pragma: no cover — environment-dependent
    MISSING.append("kokoro-onnx")
try:
    import soundfile  # noqa: F401
except ImportError:  # pragma: no cover — environment-dependent
    MISSING.append("soundfile")
HAVE_KOKORO = not MISSING

BASE_URL = ("https://github.com/thewh1teagle/kokoro-onnx/releases/"
            "download/model-files-v1.0")
MODEL_FILES = {
    "int8": "kokoro-v1.0.int8.onnx",
    "fp16": "kokoro-v1.0.fp16.onnx",
    "full": "kokoro-v1.0.onnx",
}
VOICES_FILE = "voices-v1.0.bin"

# The voice's first letter → the phonemizer language. These are
# espeak-ng's own codes, not BCP-47: it knows "es", "it", "ja", "hi" and
# "cmn" (Mandarin), and rejects "es-es"/"it-it"/"ja-jp"/"zh-cn" outright
# — `EspeakBackend.supported_languages()` is the list that counts.
VOICE_LANG = {
    "a": "en-us", "b": "en-gb", "e": "es", "f": "fr-fr",
    "h": "hi", "i": "it", "j": "ja", "p": "pt-br",
    "z": "cmn",
}
MAX_TEXT = 5000
# urlretrieve takes no timeout: without a socket default a stalled
# connection would hang until PyShell's job timeout (30 min).
DOWNLOAD_TIMEOUT = 60
DEFAULT_CACHE = Path.home() / ".cache" / "pyshell" / "tts-audio"


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


def missing_packages() -> int:
    """The exit-1 package state, naming the wheel that is actually
    absent. Shared by the synthesis run and `--list-voices`."""
    print(f"✗ {', '.join(MISSING) or 'kokoro-onnx'} is not "
          "installed — press Prepare Env in PyShell (or `python3 "
          "-m pip install -r requirements.txt`) and re-run",
          file=sys.stderr, flush=True)
    return 1


# ---------------------------------------------------------------------------
# Model management (the model prerequisite states live here)
# ---------------------------------------------------------------------------

def model_paths(models_dir: Path, variant: str) -> tuple[Path, Path]:
    return (models_dir / MODEL_FILES[variant],
            models_dir / VOICES_FILE)


def download_with_progress(url: str, dest: Path) -> None:
    """One file, progress events per whole percent (the guide's rate
    limit), to a .part file renamed on success — a killed download
    never leaves a corrupt model behind."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    socket.setdefaulttimeout(DOWNLOAD_TIMEOUT)
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
    try:
        urllib.request.urlretrieve(url, str(part), reporthook=hook)
    except BaseException:
        part.unlink(missing_ok=True)  # no half a model left to retry into
        raise
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


def list_voices(models_dir: Path, allow_download: bool) -> int:
    """Every name in the voices file, grouped by the language its first
    letter encodes. Only the voices file is read — listing what you can
    say it with must not cost the 80–310 MB model."""
    voices_path = models_dir / VOICES_FILE
    if not voices_path.exists():
        if not allow_download:
            print(f"✗ {VOICES_FILE} is not in {models_dir} — re-run "
                  f"with --download-models to fetch it (~27 MB, one "
                  f"time); the model itself is not needed to list "
                  f"voices", file=sys.stderr, flush=True)
            return 1
        try:
            download_with_progress(f"{BASE_URL}/{VOICES_FILE}",
                                   voices_path)
        except Exception as exc:
            print(f"✗ the download failed ({type(exc).__name__}: "
                  f"{exc}) — check the connection and re-run; nothing "
                  f"partial was kept", file=sys.stderr, flush=True)
            return 1

    import numpy as np  # a kokoro-onnx dependency, guarded by MISSING
    names = sorted(np.load(voices_path).files)
    by_lang: dict[str, list[str]] = {}
    for name in names:
        by_lang.setdefault(lang_for_voice(name) or "?", []).append(name)

    log(f"{len(names)} voices in {voices_path}")
    for lang in sorted(by_lang):
        log(f"  {lang:6s} {', '.join(by_lang[lang])}")
    rows = "\n".join(
        f"| `{lang}` | {', '.join(f'`{n}`' for n in group)} |"
        for lang, group in sorted(by_lang.items()))
    emit({"type": "markdown", "content":
          f"## Voices in `{VOICES_FILE}`\n\n{len(names)} names, and "
          f"the first letter of each is what picks the phonemizer "
          f"language.\n\n| Language | Voices |\n|---|---|\n{rows}"})
    emit({"type": "progress", "pct": 100, "message": "Done"})
    return 0


# ---------------------------------------------------------------------------
# The espeak-ng data path (a 160-byte trap)
# ---------------------------------------------------------------------------

# espeak-ng keeps its data directory in a fixed 160-byte buffer
# (N_PATH_HOME). A longer path is dropped without a word and the library
# falls back to the one baked in when the wheel was built —
# /Users/runner/work/espeakng-loader/... — which exists on no machine but
# the CI runner's. The first phonemization then prints "Error processing
# file '.../phontab': No such file or directory." and calls exit() from
# C: no Python exception to catch, no report, no artifact. PyShell venvs
# live under "Application Support/.../<64-char hash>/", 213 characters
# before the filename, so this is the normal case there, not an edge.
ESPEAK_PATH_MAX = 158


def mirror_espeak_data(src: Path, dest: Path) -> Path:
    """A short-path stand-in for espeak's data dir: a real directory of
    symlinks into `src`, so the 19 MB stays where it is. It has to be
    links one level down — phonemizer resolves the directory it is
    handed, so a symlink to the directory itself would expand straight
    back into the long path."""
    dest.mkdir(parents=True, exist_ok=True)
    wanted = {entry.name: str(entry) for entry in src.iterdir()}
    # A rebuilt env changes the hash in the source path: drop the links
    # that now point somewhere else (or nowhere) before adding.
    for link in dest.iterdir():
        if link.is_symlink() and os.readlink(link) != wanted.get(link.name):
            link.unlink()
    for name, target in wanted.items():
        link = dest / name
        if not link.is_symlink():
            try:
                os.symlink(target, link)
            except FileExistsError:  # a concurrent run got there first
                pass
    return dest


def espeak_data_path() -> str | None:
    """The data dir to hand Kokoro — short enough for espeak to keep
    it: the loader's own path when that already fits, a mirror of it
    otherwise. None means "nothing to override", either because
    espeakng-loader isn't installed (a system-wide espeak-ng then finds
    its own data) or because no short mirror could be made."""
    try:
        import espeakng_loader
    except ImportError:  # pragma: no cover — environment-dependent
        return None
    src = Path(espeakng_loader.get_data_path())
    if len(str(src)) <= ESPEAK_PATH_MAX:
        return str(src)
    for dest in (DEFAULT_CACHE / "espeak-ng-data",
                 Path(tempfile.gettempdir()) / "pyshell-espeak-ng-data"):
        if len(str(dest)) > ESPEAK_PATH_MAX:
            continue
        try:
            return str(mirror_espeak_data(src, dest))
        except OSError:  # pragma: no cover — read-only cache dir
            continue
    return None


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
    parser.add_argument("--text",
                        help="the text to speak (not needed with "
                             "--list-voices)")
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
    parser.add_argument("--list-voices", action="store_true",
                        help="print every voice the voices file "
                             "carries, grouped by language, and exit "
                             "(reads the ~27 MB voices file only)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no synthesis, no downloads",
              flush=True)
        return 0

    models_dir = Path(args.models_dir) if args.models_dir \
        else DEFAULT_CACHE

    if args.list_voices:
        if not HAVE_KOKORO:
            return missing_packages()
        return list_voices(models_dir, args.download_models)

    if args.text is None:  # argparse's own usage line, still exit 2
        parser.error("--text is required (or --list-voices)")

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

    # Failure state 1: the packages.
    if not HAVE_KOKORO:
        return missing_packages()

    status(f"Loading the {args.model_variant} model from {models_dir}")
    try:
        paths = ensure_models(models_dir, args.model_variant,
                              args.download_models)
    except Exception as exc:
        print(f"✗ the download failed ({type(exc).__name__}: {exc}) — "
              f"check the connection and re-run with "
              f"--download-models; nothing partial was kept",
              file=sys.stderr, flush=True)
        return 1

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
    from kokoro_onnx.config import EspeakConfig
    data_path = espeak_data_path()
    espeak_config = EspeakConfig(data_path=data_path) if data_path else None
    try:
        kokoro = Kokoro(str(model_path), str(voices_path),
                        espeak_config=espeak_config)
    except Exception as exc:
        print(f"✗ the model failed to load ({type(exc).__name__}: "
              f"{exc}) — a corrupt download? Delete {model_path} and "
              f"re-run with --download-models", file=sys.stderr,
              flush=True)
        return 1

    # The prefix decides the language, but only the voices file knows
    # which names exist — and it is loaded, so say so before spending
    # the synthesis rather than after (exit 2, the bad-argument state).
    available = getattr(kokoro, "voices", None)
    if available is not None and args.voice not in available:
        names = sorted(getattr(available, "files", available))
        print(f"✗ {args.voice!r} is not in {voices_path.name}, which "
              f"carries {len(names)} voices: {', '.join(names[:8])}, …",
              file=sys.stderr, flush=True)
        return 2

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
