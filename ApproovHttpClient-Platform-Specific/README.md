# Building ApproovHttpClient-Platform-Specific nuget package

Using Visual Studio and Windows, open the solution and select the `nuspec` file. Increase the version number to desired one and modify the dependencies in each platform setting (ApproovHttpClient and ApproovSDK versions) to point to the latest versions. Select `Build` and `Build Solution` making sure you are building `Release` versions. Once the build is complete, using the command line, build the nuget package:

```code
C:\Users\ivo\Desktop\ApproovHttpClient-Platform-Specific>nuget pack ApproovHttpClient-Platform-Specific.NuGet.nuspec
Attempting to build package from 'ApproovHttpClient-Platform-Specific.NuGet.nuspec'.
Successfully created package 'C:\Users\ivo\Desktop\ApproovHttpClient-Platform-Specific\ApproovHttpClient-Platform-Specific.1.0.6.nupkg'.
```
You need to codesign the nuget package and upload it to nuget.org.

```code
C:\Users\ivo\Desktop\ApproovHttpClient-Platform-Specific>nuget sign C:\Users\ivo\Desktop\ApproovHttpClient-Platform-Specific\ApproovHttpClient-Platform-Specific.1.0.6.nupkg -CertificatePath ..\CB_CodeSigningCert_2020.p12 -Timestamper http://timestamp.digicert.com
Please provide password for: ..\CB_CodeSigningCert_2020.p12
Password: ********************


Signing package(s) with certificate:
  Subject Name: CN=Critical Blue Ltd, O=Critical Blue Ltd, STREET=181 The Pleasance, L=Edinburgh, S=Midlothian, PostalCode=EH8 9RU, C=GB
  SHA1 hash: 6174D4950EAE371AFC66969B37AAB90D896E3682
  SHA256 hash: 87EC0413676751FD2801A0DAEDF0EA121FFE15E5CA472D1631A1AA4F316B8C04
  Issued by: CN=Sectigo RSA Code Signing CA, O=Sectigo Limited, L=Salford, S=Greater Manchester, C=GB
  Valid from: 11/08/2020 01:00:00 to 12/08/2021 00:59:59

Timestamping package(s) with:
http://timestamp.digicert.com
Package(s) signed successfully.
```