@echo off
rem Double-click this file. Windows asks once for permission, then garrett is installed and running.
rem To join a fleet instead of protecting only this machine, put a garrett.conf beside this file first:
rem   SERVER=https://your-service
rem   ENROLL_KEY=your enrolment key
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File','\"%~dp0deploy\install-windows.ps1\"'"
