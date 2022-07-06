# Building ApproovHttpClient nuget package

The solution file requires Visual Studio and Windows. Open the solution and select the `ApproovHttpClient.csproj` file. The settings will allow you to increase the version number to desired one. Select `Build` and `Pack ApproovHttpClient` and it will genrate a nuget file.
You need to codesign the nuget package (see `ApproovSDK` README) and upload it to nuget.org.