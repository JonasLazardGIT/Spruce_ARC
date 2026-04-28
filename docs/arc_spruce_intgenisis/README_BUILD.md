# ARC-SPRUCE revised source

This source directory contains the edited ARC-SPRUCE LaTeX files for the IntGenISIS-style committed-message construction with computational MLWE commitment hiding.

Build command used in this environment:

```bash
pdflatex -interaction=nonstopmode -halt-on-error main.tex
bibtex main   # or use the included main.bbl if BibTeX is unavailable
pdflatex -interaction=nonstopmode -halt-on-error main.tex
pdflatex -interaction=nonstopmode -halt-on-error main.tex
```

In this container, the standard `bibtex` symlink was broken, so `/usr/bin/bibtex.original main` was used. The generated `main.bbl` is included for reproducibility.
