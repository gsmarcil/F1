@echo off
rem Double-click this file to remove garrett from this machine.
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File','\"%~dp0deploy\uninstall-windows.ps1\"'"
