@echo off
echo Installing requirements...
pip install -r requirements.txt
pip install pyinstaller

echo Building executable...
pyinstaller --noconfirm --onefile --windowed --icon="assets/Zoro.png" --add-data "assets;assets" --hidden-import PyQt5 --hidden-import PyQt5.QtCore --hidden-import PyQt5.QtGui --hidden-import PyQt5.QtWidgets gui.py

echo Build complete! Executable can be found in the dist folder.
pause
