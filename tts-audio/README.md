# TTS Audio

A [PyShell](https://github.com/mono-ninja/PyShell) script that turns
**text into speech on your machine** —
[Kokoro](https://github.com/thewh1teagle/kokoro-onnx), a small neural
TTS model running offline through ONNX Runtime. No API keys, no
cloud: the text never leaves the machine.

- **A dozen curated voices** across languages — American/British
  English, Spanish, French, Italian, Japanese, Mandarin — with the
  language derived automatically from the voice's first letter.
- **Speed control** (0.5–2.0×), up to 5000 characters per run (CPU
  synthesis is roughly real-time).
- The result lands as the **`speech.wav`** artifact.

**Heavy prerequisites, handled honestly** (the two failure states are
both exit 1 with exact instructions — never a warning and an empty
result):

- `kokoro-onnx` missing → Prepare Env / the pip line;
- model files missing → re-run with **Download the models** — a
  one-time fetch of the chosen variant (~80 MB `int8`, larger `fp16`
  / `full`) plus the ~27 MB voices file, into
  `~/.cache/pyshell/tts-audio` (shared across runs, overridable),
  with a progress bar. Interrupted downloads never leave corrupt
  files (`.part` files are renamed on completion).

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `kokoro-onnx` (a heavy wheel set:
   ONNX Runtime, numpy, soundfile).
3. **Text**, a **Voice**, and — the first time — tick **Download the
   models**; press **Run** (⌘↩).

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

python3 main.py --text "Hello from PyShell." --download-models
python3 main.py --text "Hello from PyShell."                       # models cached
python3 main.py --text "Bon día" --voice ef_dora --speed 0.9
python3 main.py --text "你好" --voice zf_xiaobei
python3 main.py --text "Long text…" --model-variant fp16 --download-models
```

## Result

- **Results tab** — the summary (voice, language, audio duration,
  synthesis time) and the `speech.wav` artifact card.
- **Artifacts** — `speech.wav`.

## Exit codes

- `0` — the audio was written.
- `1` — a prerequisite is missing (the package, or the model files —
  with the exact instruction), or synthesis failed.
- `2` — bad arguments (empty/oversized text, unknown voice, speed out
  of range).

## Layout

```
tts-audio/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # lazy import, model management, synthesis
├── requirements.txt     # kokoro-onnx, soundfile
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
