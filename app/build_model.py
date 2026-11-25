"""Build the demo app's model once: refit 03's final model on Nov 2021-2023 with its frozen settings (as
03_model_test.ipynb did), check that it reproduces 03's saved 2024 scores, and save it to app/model/.

Run from the project folder:   python app/build_model.py      (about a minute)
The app can also build it itself (a button on its home page)."""
import sys

import cve_model

if __name__ == "__main__":
    try:
        cve_model.build_final_model()
    except (RuntimeError, FileNotFoundError) as exc:
        print(f"could not build the app's model: {exc}")
        sys.exit(1)
