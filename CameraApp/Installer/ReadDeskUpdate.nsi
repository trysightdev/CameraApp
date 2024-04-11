;NSIS Modern User Interface
;Basic Example Script
;Written by Joost Verburg

;--------------------------------
;Include Modern UI

	!include nsDialogs.nsh
	!include LogicLib.nsh
	!include "MUI2.nsh"

;--------------------------------
;General

  ;Name and file

  Name "CameraApp"
  OutFile "CameraAppSetup.exe"
  InstallDir "$TEMP\CameraApp"
  RequestExecutionLevel admin

;--------------------------------
;Interface Settings

  !define MUI_ABORTWARNING

;--------------------------------
;Pages
  
;--------------------------------
;Languages
 
  !insertmacro MUI_LANGUAGE "English"

Function .onInit
	${If} ${FileExists} "$TEMP\CameraApp"
		RMDir 	/r	"$TEMP\CameraApp"
	${EndIf}

FunctionEnd


;--------------------------------
;Installer Sections
Var G_MYPICTURES
Var G_REG1
Var G_REG2
Var G_HDID

Section "Dummy Section" SecDummy

	SetOutPath $TEMP\CameraApp
	File /r "InstallFiles\*"
  
	;ADD YOUR OWN FILES HERE...
  
	SetRegView 64
	WriteRegStr		HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "SmartScreenEnabled" "Off"
	WriteRegDWORD 	HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" "AllowDevelopmentWithoutDevLicense" 1
	


	
	ExecWait 'powershell -ExecutionPolicy bypass Get-AppxPackage *CameraApp* | Remove-AppxPackage'
	ExecWait 'powershell -ExecutionPolicy bypass -File "$TEMP\CameraApp\CameraApp\Add-AppDevPackage.ps1"'
	ExecWait 'explorer.exe shell:appsFolder\CameraApp_g9avtacrxzk8t!App'

SectionEnd

