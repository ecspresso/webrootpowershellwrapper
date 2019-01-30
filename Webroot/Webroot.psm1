function Set-WebrootCredentials {
    param(
        # Webroot credentials
        [Parameter(Mandatory = $true)]
        [string]$username,
        [Parameter(Mandatory = $true)]
        [string]$password,
        [Parameter(Mandatory = $true)]
        [string]$cliend_id,
        [Parameter(Mandatory = $true)]
        [string]$client_secret,
        [Parameter(Mandatory = $true)]
        [string]$gsm_key
    )

    # Config and token folders
    $config_path = "$($env:USERPROFILE)\Webroot"

    # Config and token files
    $config_file = 'webrootconfig.psd1'

    # Removing trailing backslash
    if($config_path.EndsWith('\')) {
        $config_path = $config_path.Remove($config_path.Length -1, 1)
    }

    # Create directory if not existing
    if(-not (test-path -Path $config_path)) {
        New-Item -ItemType Directory -Force -Path $config_path  | Foreach-Object {$_.Attributes = 'hidden'}
    }

# Export settings
@"
@{
    username = "$username"
    password = "$($password | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString)"
    cliend_id = "$cliend_id"
    client_secret = "$($client_secret | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString)"
    accountid = "$($gsm_key| ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString)"
}
"@ | Out-File -FilePath "$config_path\$config_file" -Force
}


function New-WebrootRefreshToken {
    [CmdletBinding()]
    param(
        # Config and token folders
        [string]$config_path = "$($env:USERPROFILE)\Webroot",
        [string]$token_path = "$($env:USERPROFILE)\Webroot",

        # Config and token files
        [string]$config_file = 'webrootconfig.psd1',
        [string]$tokens_file = 'webroottoken.psd1'
    )

    # Removing trailing backslash
    if($config_path.EndsWith("\")) {
        $config_path = $config_path.Remove($config_path.Length -1, 1)
    }
    if($token_path.EndsWith("\")) {
        $token_path = $token_path.Remove($token_path.Length -1, 1)
    }

    # Import credentials data from file
    $config = Import-PowerShellDataFile -Path "$config_path\$config_file"

    # Parse config file for credentials
    $username = $config.username
    $password = [PSCredential]::New('null', $($config.password | ConvertTo-SecureString)).GetNetworkCredential().Password
    $cliend_id = $config.cliend_id
    $client_secret = [PSCredential]::New('null', $($config.client_secret | ConvertTo-SecureString)).GetNetworkCredential().Password

    # API Parameters
    $params = @{
        Headers = @{
            'Accept' = 'application/json'
            'Content-Type' = 'application/x-www-form-urlencoded'
            'Authorization' = 'Basic {0}' -f [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($cliend_id + ':' +$client_secret))
        }
        body = @{
            'username' = $username
            'password' = $password
            'grant_type' = 'password'
            'scope' = '*'
        }
        URI = 'https://unityapi.webrootcloudav.com/auth/token'
        Method = 'POST'
    }

    # Call Webroot API for a new token
    $token_data = Invoke-RestMethod @params

@"
@{
    access_token = @{
        token = "$($token_data.access_token | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString)"
        expire = "$(((Get-Date).AddSeconds($token_data.expires_in)).Ticks)"
        token_type = "$($token_data.token_type)"
    }
    refresh_token = @{
        token = "$($token_data.refresh_token | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString)"
        expire = "$(((Get-Date).AddDays(14)).Ticks)"
    }
    scope = `"$($token_data.scope.Trim("[").Trim("]").Trim("`""))`"
}
"@  | Out-File -FilePath "$token_path\$tokens_file" -Force
}

function New-WebrootAccessToken {
    [CmdletBinding()]
    param(
        # Config and token folders
        [string]$config_path = "$($env:USERPROFILE)\Webroot",
        [string]$token_path = "$($env:USERPROFILE)\Webroot",

        # Config and token files
        [string]$config_file = 'webrootconfig.psd1',
        [string]$tokens_file = 'webroottoken.psd1',

        # Scope
        [string]$scope = '*'
    )

    # Removing trailing backslash
    if($config_path.EndsWith("\")) {
        $config_path = $config_path.Remove($config_path.Length -1, 1)
    }
    if($token_path.EndsWith("\")) {
        $token_path = $token_path.Remove($token_path.Length -1, 1)
    }

    # Import config data
    $config = Import-PowerShellDataFile -Path "$config_path\$config_file"

    # Import token data
    $tokens = Import-PowerShellDataFile -Path "$token_path\$tokens_file"

    if([DateTime][int64]$tokens.refresh_token.expire -lt (Get-Date)) {
        # Get new refresh token and access token
        New-WebrootRefreshToken

        # Reimport token data
        $tokens = Import-PowerShellDataFile -Path "$token_path\$tokens_file"

    }

    # Parse config data for client id and secret
    $cliend_id = $config.cliend_id
    $client_secret = [PSCredential]::New('null', $($config.client_secret | ConvertTo-SecureString)).GetNetworkCredential().Password

    # Parse token data for refresh token
    $refresh_token = [PSCredential]::New('null', $($tokens.refresh_token.token | ConvertTo-SecureString)).GetNetworkCredential().Password

    # Check if refresh token has expired


    # API Parameters
    $params = @{
        Headers = @{
            "Accept" = "application/json"
            "Content-Type" = "application/x-www-form-urlencoded"
            "Authorization" = "Basic $([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($cliend_id + ":" +$client_secret)))"
        }
        body = @{
            "refresh_token"  = $refresh_token
            "grant_type" = "refresh_token"
            "scope" = $scope
        }
        URI = 'https://unityapi.webrootcloudav.com/auth/token'
        Method = "POST"
    }


    # Call Webroot API for a new token
    $token_data = Invoke-RestMethod @params

@"
@{
    access_token = @{
        token = "$($token_data.access_token | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString)"
        expire = "$(((Get-Date).AddSeconds($token_data.expires_in)).Ticks)"
        token_type = "$($token_data.token_type)"
    }
    refresh_token = @{
        token = "$($token_data.refresh_token | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString)"
        expire = "$(((Get-Date).AddDays(14)).Ticks)"
    }
    scope = `"$($token_data.scope.Trim("[").Trim("]").Trim("`""))`"
}
"@  | Out-File -FilePath "$token_path\$tokens_file" -Force
}

function Show-WebrootRefreshToken {
    param(
        [string]$token_path = "$($env:USERPROFILE)\Webroot",
        [string]$tokens_file = 'webroottoken.psd1'
        [switch]$renew
    )

    if($token_path.EndsWith("\")) {
        $token_path = $token_path.Remove($token_path.Length -1, 1)
    }

    $tokens = Import-PowerShellDataFile -Path "$token_path\$tokens_file"

    if($renew -and [DateTime][int64]$tokens.refresh_token.expire -lt (Get-Date)) {
        # Get new refresh token and access token
        New-WebrootRefreshToken

        # Reimport token data
        $tokens = Import-PowerShellDataFile -Path "$token_path\$tokens_file"
    }

    return [PSCredential]::New('null', $($tokens.refresh_token.token | ConvertTo-SecureString)).GetNetworkCredential().Password
}

function Show-WebrootAccessToken {
    param(
        [string]$token_path = "$($env:USERPROFILE)\Webroot",
        [string]$tokens_file = 'webroottoken.psd1'
        [switch]$renew
    )

    if($token_path.EndsWith("\")) {
        $token_path = $token_path.Remove($token_path.Length -1, 1)
    }

    $tokens = Import-PowerShellDataFile -Path "$token_path\$tokens_file"

    if($renew -and [DateTime][int64]$tokens.access_token.expire -lt (Get-Date)) {
        # Get new refresh token and access token
        New-WebrootAccessToken

        # Reimport token data
        $tokens = Import-PowerShellDataFile -Path "$token_path\$tokens_file"
    }

    return [PSCredential]::New('null', $($tokens.access_token.token | ConvertTo-SecureString)).GetNetworkCredential().Password
}