# TTS Audio

Text to speech **on your machine** — Kokoro, a small neural TTS model
running offline through ONNX Runtime. No API keys, no cloud: the text
never leaves the machine. The result is the `speech.wav` artifact.

---

## Before running

1. **Text** — what to speak (up to 5000 characters; CPU synthesis is
   roughly real-time, so a full page is a couple of minutes).
2. Press **Prepare Env** — installs `kokoro-onnx` and its wheels
   (ONNX Runtime, numpy, soundfile). Heavy, one time.
3. **The first run needs the models too**: tick **Download the models
   if missing** — the chosen variant (~80 MB `int8`; `fp16`/`full`
   larger) plus the ~27 MB voices file land in
   `~/.cache/pyshell/tts-audio`, shared across runs. Unticked and
   missing → exit 1 with this exact instruction; a missing
   prerequisite is a missing result, never a silent warning.

## Fields

### Voice

- **Text** — the text to speak.
- **Voice** — the curated list (Heart/Bella/Nicole, Adam/Michael/Puck,
  Emma, George, Dora (Spanish), Siwis (French), Sara (Italian), Alpha
  (Japanese), Xiaobei (Mandarin)). The first letter encodes the
  language (`a`/`b` English, `e` Spanish, `f` French, `i` Italian,
  `j` Japanese, `z` Chinese) — the phonemizer language is derived
  from it automatically.
- **Speed** — 0.5–2.0×, default 1.0.

### Models

- **Model variant** — `int8` (small, fast, default), `fp16`, `full`
  (~310 MB): the size/quality tradeoff.
- **Download the models if missing** — the opt-in fetch, with a
  progress bar. Interrupted downloads leave no corrupt files
  (`.part` renamed on completion).
- **Models dir** — where the models live; the default
  `~/.cache/pyshell/tts-audio` is shared across runs.

---

## Result

- **Results tab** — the summary: voice and language, audio duration,
  file size, synthesis time (your machine's real number, useful for
  sizing longer texts), and the `speech.wav` card.
- **Artifacts** — `speech.wav` (WAV, the model's native 24 kHz).

## Exit codes

- `0` — the audio was written.
- `1` — prerequisite missing (a package, the models — with the exact
  instruction — or a download that failed), or synthesis failed.
- `2` — bad arguments (empty/oversized text, a voice the model doesn't
  carry, speed out of range).
