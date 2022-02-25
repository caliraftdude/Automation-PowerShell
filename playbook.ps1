# ================================================================================
# F5 Automation Playbook with PowerShell
# There are a lot of resources regarding automation with F5 tools AS3 and DO, but
# none of them really address doing this from PowerShell which is typically not
# used as much as alternatives.  This playbook is meant to be a set of examples
# on taking an F5 from "just a mgmt IP" to a configured endpoint using these
# tools with PowerShell.
#
# The code is NOT optimized and there is a lot of redundant code here, this is
# purposeful.  The idea is that you could copy and paste any of these steps and
# easily integrate it into an existing code base/workflow.  This CAN be run
# with the requisite resources as well, but some refactoring and cleanup would
# yield much more maintainable code.
#
# This code is presented AS-IS with no warranty or support implied or otherwise 
# and provided entirely free.
# 
# Requires PS 7.x or >
# Elements borrowed from here:  https://github.com/mjmenger/terraform-bigip-postbuild-config/blob/main/atcscript.tmpl
# ================================================================================

# Uncomment out the next section if you want to provide credentials on the cmd line
# and use that throughout the script.  You will need to adjust appropriate lines
# in the "Get Auth Token" routine to make use of this
<# Write-Output "==================================================================="
Write-Output "Get Credentials"
Write-Output "==================================================================="

$credential = Get-Credential

# access credentials?
Write-Host $credential.UserName
Write-Host $(ConvertFrom-SecureString -SecureString $credential.Password -AsPlainText)
#>

$big_ip = "https://10.1.1.151"

# ================================================================================
# Get auth token
# ================================================================================
Write-Output "==================================================================="
Write-Output "Get auth token"
Write-Output "==================================================================="
$url = "{0}{1}" -f $big_ip, '/mgmt/shared/authn/login'
$body = @{
	username = "admin"
	password = "admin"
	loginProviderName = "tmos"
} | ConvertTo-Json

$result = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri $url -ContentType 'application/json' -Body $body
$token = $($result.token.token)
Write-Output ""

# ================================================================================
# Verify token
# ================================================================================
Write-Output "==================================================================="
Write-Output "Verify Token"
Write-Output "==================================================================="
$url = "{0}{1}{2}" -f $big_ip, "/mgmt/shared/authz/tokens/", $token
$headers = @{
	'X-F5-Auth-Token' = $token
}

try {
    $result = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri $url -Headers $headers -ContentType 'application/json'

} catch {
    # Can't capture the response code with Invoke-RestMethod, but can catch the exception and assume failure.
    Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
	Write-Host "Authentication token / attempt failed.  Exiting..."
	exit
}
Write-Output "`nAuth succeeded!`n"

<# # ================================================================================
# Change Password policy
# ================================================================================
Write-Output "==================================================================="
Write-Output "Change Password Policy"
Write-Output "==================================================================="
$url = "{0}{1}" -f $big_ip, "/mgmt/tm/auth/password-policy"
$headers = @{
	'X-F5-Auth-Token' = $token
	'Content-Type' = 'application/json'
}
$body = @{
	policyEnforcement = "disabled"
	expirationWarning = 14
	minimumLength = 5
	requiredLowercase = 1
	requiredUppercase = 0
	requiredNumeric = 0
	requiredSpecial = 0
	passwordMemory = 0
	maxDuration = 30
	maxLoginFailures = 5
	minDuration = 0
} | ConvertTo-Json


$result = Invoke-RestMethod -SkipCertificateCheck -Method 'PATCH' -Uri $url -Headers $headers -Body $body
Write-Output $result #>


# ================================================================================
# Change Passwords
# Note:  you CANNOT do root over the REST interface.
# ================================================================================
Write-Output "==================================================================="
Write-Output "Change Passwords"
Write-Output "==================================================================="
$url = "{0}{1}" -f $big_ip, "/mgmt/tm/auth/user/admin"
$headers = @{
	'X-F5-Auth-Token' = $token
	'Content-Type' = 'application/json'
}
$body = @{
	password = "admin"
} | ConvertTo-Json


$result = Invoke-RestMethod -SkipCertificateCheck -Method 'PATCH' -Uri $url -Headers $headers -Body $body
Write-Output $result


# ================================================================================
# Testing Get Version with token
# ================================================================================
Write-Output "==================================================================="
Write-Output "Testing Get Version with token"
Write-Output "==================================================================="
$url = "{0}{1}" -f $big_ip, "/mgmt/tm/sys/version"
$headers = @{
	'X-F5-Auth-Token' = $token
}

$result = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri $url -Headers $headers -ContentType 'application/json'
Write-Output $result


# ================================================================================
# Upload DO RPM
# ================================================================================
Write-Output "==================================================================="
Write-Output "Uploading DO package"
Write-Output "==================================================================="
$file = "f5-declarative-onboarding-1.27.0-6.noarch.rpm"
$url = "{0}{1}{2}" -f $big_ip, "/mgmt/shared/file-transfer/uploads/", $file
$filelength = (Get-Item $file).length
$headers = @{
	'Content-Type' = 'application/octet-stream'
	'X-F5-Auth-Token' = $token
	'Content-Range' = "0-$($filelength-1)/$filelength"
}
# Sha256: 2aee4a29ac64b38ac5af7d41607a966cac063c99a339b228225ffa38f8f9a4cf  f5-declarative-onboarding-1.27.0-6.noarch.rpm

try {
    $result = Invoke-RestMethod -SkipCertificateCheck -SkipHeaderValidation -Method Post -Uri $url -Headers $headers -InFile $file

} catch [Exception] {
    # Can't capture the response code with Invoke-RestMethod, but can catch the exception and assume failure.
    Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__
	Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription 
	
	Write-Host $_.Exception
	exit
}

Write-Output $result

# ================================================================================
# Upload AS3 RPM
# ================================================================================
Write-Output "==================================================================="
Write-Output "Uploading AS3 RPM package"
Write-Output "==================================================================="
$file = "f5-appsvcs-3.34.0-4.noarch.rpm"
$url = "{0}{1}{2}" -f $big_ip, "/mgmt/shared/file-transfer/uploads/", $file
$filelength = (Get-Item $file).length
$headers = @{
	'Content-Type' = 'application/octet-stream'
	'X-F5-Auth-Token' = $token
	'Content-Range' = "0-$($filelength-1)/$filelength"
}
# Sha256: 05a80ec0848dc5b8876b78a8fbee2980d5a1671d635655b3af604dc830d5fed4  f5-appsvcs-3.34.0-4.noarch.rpm

try {
    $result = Invoke-RestMethod -SkipCertificateCheck -SkipHeaderValidation -Method Post -Uri $url -Headers $headers -InFile $file

} catch [Exception] {
    # Can't capture the response code with Invoke-RestMethod, but can catch the expection and assume failure.
    Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__
	Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription 
	
	Write-Host $_.Exception
	exit
}

Write-Output $result

# ================================================================================
# Install DO 
# ================================================================================
Write-Output "==================================================================="
Write-Output "Install DO package"
Write-Output "==================================================================="
$file = "f5-declarative-onboarding-1.27.0-6.noarch.rpm"							# X diff from AS3 install
$install_url = "{0}{1}" -f $big_ip, "/mgmt/shared/iapp/package-management-tasks"
$info_url = "{0}{1}" -f $big_ip, "/mgmt/shared/declarative-onboarding/info"		# X diff from AS3 install
$retries = 0			# Number of times the system has been polled
$retry_limit = 	5		# max number of times the system will be polled
$poll_interval = 10		# interval, in seconds, between polls

$headers = @{
	'X-F5-Auth-Token' = $token
	'Origin' =  'https://10.1.1.151' #  change to $big_ip?
	'Content-Type' = 'application/json;charset=UTF-8'
}
$body = @{
    operation = 'INSTALL'
    packageFilePath = '/var/config/rest/downloads/' +$file
} | ConvertTo-Json

# Initiate the installation request and capture the result id (task uuid) which we can poll for installation progress
try {
	$result = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri $install_url -Headers $headers -Body $body
	$poll_url = "{0}{1}{2}" -f $big_ip, "/mgmt/shared/iapp/package-management-tasks/", $($result.id)

} catch {
	$code = $_.Exception.Response.StatusCode.value__
	Write-Host "Error at install DO request: " $code 
}



# Enter a polling loop checking for completion or failure
do {
	# Wait for poll_interval seconds
	Start-Sleep -s $poll_interval
	
	# Poll the system to see what the status of the installation is
	$tmp = try {
		Invoke-WebRequest -SkipCertificateCheck -SkipHeaderValidation -Method 'GET' -Uri $poll_url -Headers $headers -ErrorAction Stop
	} catch [System.Net.WebException] { 
		$_.Exception.Response
	}
	
	# Pull out the status code from the response and increment the retries
	$response = $tmp.StatusCode
	$retries++

	# Handle the various responses, and adjust the logic for exiting the loop
	switch ( $response )
	{
		200 {
			Write-Host $response "- ATC service available for use"
			break
		}
		202 {
			Write-Host $response "- ATC service in use"
			break
		}
		204 {
			Write-Host $response "- No content returned - assuming ATC service available for use"
			$response = 200
			break
		}
		422 {
			Write-Host $response "- ATC service in failed state - likely from a previous run."
			$response = 200
		}
		4* {
			Write-Host $response "- ATC service in failed state - this may be transient"
			break
		}
		5* {
			Write-Host $response "- ATC service in failed state - this may be transient"
			break}
	
		default {
			Write-Host $response "- Unexpected ATC service availability"
			break
		}
	}

} while ( ($response -ne 200 ) -and ( $retries -lt $retry_limit ) )

# Installation should have concluded/succeeded, make a request to appsvcs/info to complete, remove origin from headers
$headers = @{
	'X-F5-Auth-Token' = $token
	'Content-Type' = 'application/json'
}

# Give the system a few more seconds to settle..
Start-Sleep -s $poll_interval

# Send out request to the info to get version, etc.. which validates installation and service availability
$result = try {
	Invoke-RestMethod -SkipCertificateCheck -SkipHeaderValidation -Method 'GET' -Uri $info_url -Headers $headers
} catch [System.Net.WebException] { 
	$_.Exception.Response
}

# Announce success and print out the versioning info
Write-Host "DO Installation succeded"
Write-Host $($result | ConvertTo-Json)


# ================================================================================
# Install AS3 
# ================================================================================
Write-Output "==================================================================="
Write-Output "Install AS3 package"
Write-Output "==================================================================="
$file = "f5-appsvcs-3.34.0-4.noarch.rpm"
$install_url = "{0}{1}" -f $big_ip, "/mgmt/shared/iapp/package-management-tasks"
$info_url = "{0}{1}" -f $big_ip, "/mgmt/shared/appsvcs/info"
$retries = 0			# Number of times the system has been polled
$retry_limit = 	5		# max number of times the system will be polled
$poll_interval = 10		# interval, in seconds, between polls

$headers = @{
	'X-F5-Auth-Token' = $token
	'Origin' =  'https://10.1.1.151' #  change to $big_ip?
	'Content-Type' = 'application/json;charset=UTF-8'
}
$body = @{
    operation = 'INSTALL'
    packageFilePath = '/var/config/rest/downloads/' +$file
} | ConvertTo-Json

# Initiate the installation request and capture the result id (task uuid) which we can poll for installation progress
try {
	$result = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri $install_url -Headers $headers -Body $body
	$poll_url = "{0}{1}{2}" -f $big_ip, "/mgmt/shared/iapp/package-management-tasks/", $($result.id)

} catch {
	$code = $_.Exception.Response.StatusCode.value__
	Write-Host "Error at install AS3 request: " $code 
}


# Enter a polling loop checking for completion or failure
do {
	# Wait for poll_interval seconds
	Start-Sleep -s $poll_interval
	
	# Poll the system to see what the status of the installation is
	$tmp = try {
		Invoke-WebRequest -SkipCertificateCheck -SkipHeaderValidation -Method 'GET' -Uri $poll_url -Headers $headers -ErrorAction Stop
	} catch [System.Net.WebException] { 
		$_.Exception.Response
	}
	
	# Pull out the status code from the response and increment the retries
	$response = $tmp.StatusCode
	$retries++

	# Handle the various responses, and adjust the logic for exiting the loop
	switch ( $response )
	{
		200 {
			Write-Host $response "- ATC service available for use"
			break
		}
		202 {
			Write-Host $response "- ATC service in use"
			break
		}
		204 {
			Write-Host $response "- No content returned - assuming ATC service available for use"
			$response = 200
			break
		}
		422 {
			Write-Host $response "- ATC service in failed state - likely from a previous run."
			$response = 200
			break
		}
		4* {
			Write-Host $response "- ATC service in failed state - this may be transient"
			break
		}
		5* {
			Write-Host $response "- ATC service in failed state - this may be transient"
			break}
	
		default {
			Write-Host $response "- Unexpected ATC service availability"
			break
		}
	}

} while ( ($response -ne 200 ) -and ( $retries -lt $retry_limit ) )

# Installation should have concluded/succeeded, make a request to appsvcs/info to complete, remove origin from headers
$headers = @{
	'X-F5-Auth-Token' = $token
	'Content-Type' = 'application/json'
}

# Give the system a few more seconds to settle..
Start-Sleep -s $poll_interval

# Send out request to the info to get version, etc.. which validates installation and service availability
$result = try {
	Invoke-RestMethod -SkipCertificateCheck -SkipHeaderValidation -Method 'GET' -Uri $info_url -Headers $headers
} catch [System.Net.WebException] { 
	$_.Exception.Response
}

# Announce success and print out the versioning info
Write-Host "AS3 Installed.."
Write-Host $($result | ConvertTo-Json)


# ================================================================================
# Upload DO configuration
# ================================================================================
Write-Output "==================================================================="
Write-Output "Upload DO configuration"
Write-Output "==================================================================="
$file = 'do.json'
$url = "{0}{1}" -f $big_ip, "/mgmt/shared/declarative-onboarding/"
$poll_url = "{0}{1}" -f $big_ip, "/mgmt/shared/declarative-onboarding/task/"
$headers = @{
	'X-F5-Auth-Token' = $token
	'Content-Type' = 'application/json'
}

try {
    $result = Invoke-RestMethod -SkipCertificateCheck -SkipHeaderValidation -Method 'POST' -Uri $url -Headers $headers -InFile $file
	
	# Extract the job id from the response, so we can poll this for completion later
	$poll_url = $poll_url + $result.id
	$retries = 0			# Number of times the system has been polled
	$retry_limit = 7		# max number of times the system will be polled
	$poll_interval = 10		# interval, in seconds, between polls

	# Enter a polling loop checking for completion or failure
	do {
		# Wait for poll_interval seconds
		Start-Sleep -s $poll_interval
		
		# Poll the system and retain / extract the response
		# Invoke-RestMethod doesn't return the entire payload, and you cannot get the return code from its return value
		$tmp = Invoke-WebRequest -SkipCertificateCheck -SkipHeaderValidation -Method 'GET' -Uri $poll_url -Headers $headers
		$response = $tmp | ConvertFrom-Json
		$response = $($response.result.code)

		# Increment the retries
		$retries++

		# Handle the various responses, and adjust the logic for exiting the loop
		switch ( $response )
		{
			200 {
				Write-Host $response "- payload applied"
				break
			}
			202 {
				Write-Host $response "- payload in process"
				break
			}
			204 {
				Write-Host $response "- no content returned - success assumed"
				$response = 200
				break
			}
			422 {
				Write-Host $response "- detected, failed to upload DO policy"
				throw [System.Exception] "Exiting the script.."
			}
			4* {
				Write-Host $response "- 4* considered possible transient error, ignoring."
				break
			}
			5* {
				Write-Host $response "- 5* considered possible transient error, ignoring."
				break}
		
			default {
				Write-Host $response"- default handler.  Unexpected response to payload, assuming success"
				break
			}
		}

	} while ( ($response -ne 200 ) -and ( $retries -lt $retry_limit ) )

	Write-Host "Successfully Applied DO Policy...	"

} 
catch [System.Net.WebException] {
    # If things really go wrong, capture here and exit.
	Write-Host "DO Deployment failure: $($_.Exception.Message)" 
    Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__
	Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription 
	
	Write-Host $_.Exception
	exit
}
catch [System.Exception] {
	Write-Host "DO Deployment failure: "$($_.Exception.Message)
	Write-Host "Error: " $_.Exception.Message
	exit
}

# Announce Victory
Write-Host "DO policy deployed"

# ================================================================================
# Upload AS3 configuration
# ================================================================================
Write-Output "==================================================================="
Write-Output "Upload AS3 configuration"
Write-Output "==================================================================="
$file = 'as3.json'
$url = "{0}{1}" -f $big_ip, "/mgmt/shared/appsvcs/declare?async=true"
$headers = @{
	'X-F5-Auth-Token' = $token
	'Content-Type' = 'application/json'
}

try {
    $result = Invoke-RestMethod -SkipCertificateCheck -SkipHeaderValidation -Method 'POST' -Uri $url -Headers $headers -InFile $file
	$poll_url = "{0}{1}{2}" -f $big_ip, "/mgmt/shared/appsvcs/task/", $($result.id)

	# Extract the job id from the response, so we can poll this for completion later
	$retries = 0			# Number of times the system has been polled
	$retry_limit = 7		# max number of times the system will be polled
	$poll_interval = 10		# interval, in seconds, between polls

	# Enter a polling loop checking for completion or failure
	do {
		# Wait for poll_interval seconds
		Start-Sleep -s $poll_interval
		
		# Poll the system and retain / extract the response
		# Invoke-RestMethod doesn't return the entire payload, and you cannot get the return code from its return value
		$tmp = Invoke-WebRequest -SkipCertificateCheck -SkipHeaderValidation -Method 'GET' -Uri $poll_url -Headers $headers
		$response = $tmp | ConvertFrom-Json
		$response = $($response.results.code)

		# Increment the retries
		$retries++

		# Handle the various responses, and adjust the logic for exiting the loop
		switch ( $response )
		{
			200 {
				Write-Host $response "- payload applied"
				break
			}
			202 {
				Write-Host $response "- payload in process"
				break
			}
			204 {
				Write-Host $response "- no content returned - success assumed"
				$response = 200
				break
			}
			422 {
				Write-Host $response "- detected"
				throw [System.Exception] "Exiting the script.."
			}
			4* {
				Write-Host $response "- 4* considered possible transient error, ignoring."
				break
			}
			5* {
				Write-Host $response "- 5* considered possible transient error, ignoring."
				break}
		
			default {
				Write-Host $response"- default handler.  Unexpected response to payload, assuming success"
				break
			}
		}

	} while ( ($response -ne 200 ) -and ( $retries -lt $retry_limit ) )

	Write-Host "Successfully Applied AS3 Policy...	"

} 
catch [System.Net.WebException] {
    # If things really go wrong, capture here and exit.
	Write-Host "AS3 Deployment failure: $($_.Exception.Message)" 
    Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__
	Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription 
	
	Write-Host $_.Exception
	exit
}
catch [System.Exception] {
	Write-Host "AS3 Deployment failure: "$($_.Exception.Message)
	Write-Host "Error: " $_.Exception.Message
	exit
}


# fini~
Write-Host "Script complete.  Exiting..."

