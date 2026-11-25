@echo off
rem Start the DSCI 510 demo app. Double-click this file; keep the window open while you use the app.
rem Close the window (or press Ctrl+C in it) to stop the app.
cd /d "%~dp0"
call "%USERPROFILE%\anaconda3\Scripts\activate.bat"
if not exist "app\model\final_model.joblib" (
  echo Building the model once - about a minute...
  python app\build_model.py
)
streamlit run app\Home.py
pause
