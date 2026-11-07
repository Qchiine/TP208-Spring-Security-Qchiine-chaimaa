@echo off
title TP-208-Spring-Security
chcp 65001 >nul
mode con: cols=120 lines=55
set "JAVA_HOME=C:\Program Files\Java\jdk-17"
set "MAVEN_OPTS=-Dfile.encoding=UTF-8"
set "PATH=%JAVA_HOME%\bin;%PATH%"
cd /d "%~dp0"

:menu
cls
echo ==============================================================================
echo   TP 9 - Authentification en memoire avec Spring Security
echo   Users en memoire, BCrypt, formulaire personnalise, controle par role
echo   Spring Boot 3.3.1  /  Spring Security 6  /  Thymeleaf  /  JDK 17
echo ==============================================================================
echo.
echo   [1] Lancer l'application   (http://localhost:8080)
echo   [2] Suite de tests (mvn test)
echo   [3] Recompiler proprement le projet
echo   [4] Afficher les URLs et les comptes
echo   [0] Quitter
echo.
set "choix="
set /p "choix=Votre choix : "
if "%choix%"=="1" goto :lancer
if "%choix%"=="2" goto :tests
if "%choix%"=="3" goto :compile
if "%choix%"=="4" goto :urls
if "%choix%"=="0" goto :fin
goto :menu

:lancer
cls
echo ==============================================================================
echo   L'application demarre sur le port 8080.
echo   Appuyez sur Ctrl+C dans cette fenetre pour l'arreter.
echo ==============================================================================
echo.
echo   Accueil : http://localhost:8080/
echo   Comptes : user/1111  admin/1234  invite/0000
echo.
call mvn -B -q spring-boot:run
goto :suspension

:tests
cls
echo Execution de la suite de tests...
echo.
call mvn -B test
if errorlevel 1 goto :echec
goto :suspension

:compile
cls
call mvn -B -q clean compile
if errorlevel 1 goto :echec
echo.
echo Compilation terminee sans erreur.
goto :suspension

:urls
cls
echo ==============================================================================
echo   URLS ET COMPTES  (application lancee via le choix 1)
echo ==============================================================================
echo.
echo   Pages publiques
echo     http://localhost:8080/
echo     http://localhost:8080/login
echo.
echo   Espace utilisateur (role USER)
echo     http://localhost:8080/user/dashboard
echo.
echo   Espace administrateur (role ADMIN)
echo     http://localhost:8080/admin/dashboard
echo     http://localhost:8080/admin/journal
echo.
echo   Comptes declares en memoire
echo     user   / 1111   -^> USER
echo     admin  / 1234   -^> ADMIN + USER
echo     invite / 0000   -^> INVITE (aucun acces)
echo.
echo   Scenario de verification
echo     1. ouvrir / sans etre connecte  -^> redirection vers /login
echo     2. se connecter avec user       -^> arrivee sur /user/dashboard
echo     3. ouvrir /admin/dashboard      -^> 403 acces refuse
echo     4. se deconnecter               -^> retour sur /login?logout
echo     5. se connecter avec admin      -^> acces aux deux espaces
echo.
goto :suspension

:echec
echo.
echo *** Echec de la compilation ou de l'execution. ***
:suspension
echo.
echo ==============================================================================
echo   Fin de l'operation. Appuyez sur une touche pour revenir au menu.
echo ==============================================================================
pause >nul
goto :menu

:fin
exit /b 0
