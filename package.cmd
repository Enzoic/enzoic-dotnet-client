%windir%\Microsoft.NET\Framework\v4.0.30319\msbuild.exe passwordping-dotnet-client.sln /t:Clean,Rebuild /p:Configuration=Release /fileLogger

tools\nuget.exe update -self
tools\nuget.exe pack PasswordPingClient\PasswordPingClient.csproj -IncludeReferencedProjects -Prop Configuration=Release