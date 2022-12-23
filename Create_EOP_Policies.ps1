#Checks for correct version of Exchange Powershell. If it is not found, it installs it and then connects. 
try 
{
    import-module -name ExchangeOnlinemanagement -MinimumVersion "3.0.0" -ErrorAction Stop
}
catch 
{
    install-module ExchangeOnlineManagement -RequiredVersion "3.0.0" -Force
    import-module ExchangeOnlinemanagement -MinimumVerison "3.0.0"    
}
connect-exchangeonline
#Sets region blocklist into an array
$RegionBlockList=@('BR', 'CN', 'CU', 'DO', 'HK', 'IN', 'IR', 'JP', 'NG', 'KP', 'RU', 'RO', 'SA', 'SD', 'SY', 'TH', 'TR', 'UA', 'AE', 'UY', 'VN')
#Sets anti-malware filetypes into Array
$AntiMalwareFileTypes=@('aci', 'ani', 'app', 'cab', 'docm', 'exe', 'iso', 'jar', 'jnlp', 'reg', 'scr', 'vbe', 'vbs')
#Gets list of user mailboxes, then sets into an array 
#Creates New Quarantine Policy
New-QuarantinePolicy `
    -Name "Quarantine with Notifications" `
    -AdminDisplayName "Quarantine with Notifications" `
    -EndUserQuarantinePermissionsvalue 23 `
    -EndUserSpamNotificationFrequencyInDays 1 `
    -ESNEnabled $True
#Creates new Anti-Spam policy
New-HostedContentFilterPolicy `
    -Name "Anchor Anti-Spam" `
    -AdminDisplayName "Anchor Anti-Spam" `
    -QuarantineRetentionPeriod 30 `
    -SpamAction "Quarantine" `
    -SpamQuarantineTag "Quarantine with Notifications" `
    -BulkSpamAction "Quarantine" `
    -BulkQuarantineTag "Quarantine with Notifications" `
    -PhishSpamAction "Quarantine" `
    -PhishQuarantineTag "Quarantine with Notifications" `
    -HighConfidenceSpamAction "Quarantine" `
    -HighConfidenceSpamQuarantineTag "Quarantine with Notifications" `
    -HighConfidencePhishAction "Quarantine" `
    -HighConfidencePhishQuarantineTag "Quarantine with Notifications" `
    -EnableRegionBlockList $True `
    -RegionBlockList $RegionBlockList
New-HostedContentFilterRule `
    -Name "Anchor Anti-Spam" `
    -HostedContentFilterPolicy "Anchor Anti-Spam" `
    -RecipientDomainIs (Get-AcceptedDomain).Name
#Creates Anti-Malware Policy
New-MalwareFilterPolicy `
    -Name "Anchor Anti-Malware" `
    -AdminDisplayName "Anchor Anti-Malware" `
    -EnableFileFilter $True `
    -FileTypes $AntiMalwareFileTypes `
    -FileTypeAction "Quarantine" `
    -QuarantineTag "Quarantine with Notifications" `
    -ZapEnabled $True
New-MalwareFilterRule `
    -Name "Anchor Anti-Malware" `
    -MalwareFilterPolicy "Anchor Anti-Malware" `
    -RecipientDomainIs (Get-AcceptedDomain).Name
#Creates New Anti-Phishing Policy
New-AntiPhishPolicy `
    -Name "Anchor Anti-Phishing" `
    -AdminDisplayName "Anchor Anti-Phishing" `
    -Enabled $True `
    -EnableMailboxIntelligenceProtection $True `
    -EnableOrganizationDomainsProtection $True `
    -AuthenticationFailAction "Quarantine" `
    -SpoofQuarantineTag "Quarantine with Notifications" `
    -MailboxIntelligenceProtectionAction "Quarantine" `
    -MailboxIntelligenceQuarantineTag "Quarantine with Notifications" `
    -EnableFirstContactSafetyTips $True `
    -EnableUnusualCharactersSafetyTips $True 
New-AntiPhishRule `
    -Name "Anchor Anti-Phishing" `
    -AntiPhishPolicy "Anchor Anti-Phishing" `
    -RecipientDomainIs (Get-AcceptedDomain).Name