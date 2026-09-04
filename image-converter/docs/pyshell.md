# Image Converter

Converts images to **AVIF**, **WebP**, **JPEG**, **PNG**, **TIFF**, **BMP** with
adjustable quality. Works with a single file, a group of files, or a whole
folder (optionally recursive). The script sends nothing over the network and
never modifies the originals — it only writes new files to the chosen folder.

## Fields

### Input

- **Source** — how to pick the images:
  - *Single image* — one file.
  - *Multiple images* — an arbitrary set of files.
  - *Folder* — all images in a directory.
- **Image folder** is only available in *Folder* mode. The **Recursive** option
  walks subfolders and reproduces their structure in the output.

### Conversion

- **Format** — the target. AVIF gives the smallest size, WebP a small size with
  broad browser support, JPEG/PNG are universal, TIFF/BMP are for compatibility.
- **Quality** — 1–100. For AVIF/WebP/JPEG this is the lossy compression quality;
  for PNG (a lossless format) the value is treated as the compression level: the
  higher it is, the smaller the file and the slower the save. TIFF and BMP are
  written uncompressed, so the value has no effect on them.
- **Max size (px)** — proportionally shrink the image to the given longest side.
  `0` = no change. Shrinking happens only when the original is larger than the
  given value (it never upscales).

### Output

- **Output folder** — where to put the results. Subfolders are created
  automatically (for recursive mode).
- **Overwrite existing** — when off, files that already exist in the output from
  previous runs are skipped (marked "skipped" in the table).

If two input files claim the same output name (`photo.png` and `photo.jpg` both
become `photo.webp`), the second one gets a suffix: `photo-1.webp`. The real
name is shown in the **Status** column — `OK → photo-1.webp`. This way no image
is lost regardless of whether overwrite is on or off.

## Animation

Animated GIF/WebP/AVIF keep all their frames, duration and loop count when
converted to **WebP** or **AVIF**. When converted to JPEG/PNG/TIFF/BMP only the
first frame is kept (these formats do not support animation).

## Result

The **Results** tab shows a per-file table: status, original and new size, the
percentage size change, plus a summary markdown report. Progress is shown by the
native PyShell progress bar.

## Exit code

- `0` — at least one image was converted or skipped as already existing
  (skipping is a normal outcome, not an error).
- `1` — no images were found, or every file errored.
- `2` — invalid arguments, or the environment cannot write the chosen format
  (AVIF needs Pillow ≥ 11.3 or `pillow-avif-plugin`).

Individual corrupt files do not stop the batch — their status is visible in the
table.
