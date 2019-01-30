# webrootpowershellwrapper
A powershell wrapper to facilitate token renewal

Copy Webroot and its content to %username%\Documents\WindowsPowerShell\Modules.

|Function name|Purpose|
|-|-|
|`Set-WebrootCredentials`|Store all information needed to access  the API|
|`New-WebrootRefreshToken`|Renew refresh token|
|`New-WebrootAccessToken`|Renew access token. Will call `New-WebrootRefreshToken` if expired|
|`Show-WebrootRefreshToken`|Reveals refresh token|
|`Show-WebrootAccessToken`|Reveals acccess token|