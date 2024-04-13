在源码根目录下执行 gradle17 进行编译

gradle17 在与指定了Java17 JDK 进行编译
如下:

if "%OS%"=="Windows_NT" setlocal

set JAVA_HOME="D:\Program Files\jdk-17.0.3-full"
set DIRNAME=%~dp0