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
Connect-ExchangeOnline
#Creates New Quarantine Policy
New-QuarantinePolicy `
    -Name "Quarantine with Notifications" `
    -AdminDisplayName "Quarantine with Notifications" `
    -EndUserQuarantinePermissionsvalue 23 `
    -EndUserSpamNotificationFrequencyInDays 1 `
    -ESNEnabled $True
#Sets Regionblocklist variable
$RegionBlockList=@('BR', 'CN', 'CU', 'DO', 'HK', 'IN', 'IR', 'JP', 'NG', 'KP', 'RU', 'RO', 'SA', 'SD', 'SY', 'TH', 'TR', 'UA', 'AE', 'UY', 'VN') 
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
#Sets Antimalwarefilytypes Variable
$AntiMalwareFileTypes=@('aci', 'ani', 'app', 'cab', 'docm', 'exe', 'iso', 'jar', 'jnlp', 'reg', 'scr', 'vbe', 'vbs')    
#Creates new Anti-Malware Policy
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
#Pulls list of active users and creates array of email addresses
$ImpPro = (get-mailbox -recipienttypedetails "UserMailBox")
$impPro = ($imppro | select-object -property DisplayName,PrimarySMTPAddress)
foreach ($imp in $imppro)
{
$addme =@($imp.displayname + ';' + $imp.primarysmtpaddress)
$Targetedusers += $addme
}
#Creates new Antiphishing policy and rule
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
    -EnableTargetedDomainsProtection $True `
    -EnableTargetedUserProtection $True `
    -TargetedDomainsToProtect (Get-AcceptedDomain).Name `
    -TargetedDomainProtectionAction "Quarantine" `
    -TargetedDomainQuarantineTag "Quarantine with Notifications" `
    -TargetedUserProtectionAction "Quarantine" `
    -TargetedUserQuarantineTag "Quarantine with Notifications" `
    -EnableFirstContactSafetyTips $True `
    -EnableSimilarUsersSafetyTips $True `
    -EnableSimilarDomainsSafetyTips $True `
    -EnableUnusualCharactersSafetyTips $True `
    -TargetedUserstoProtect $targetedusers
New-AntiPhishRule `
    -Name "Anchor Anti-Phishing" `
    -AntiPhishPolicy "Anchor Anti-Phishing" `
    -RecipientDomainIs (Get-AcceptedDomain).Name
#Creates new SafeLinks Policy
New-SafeLinksPolicy `
    -Name "Anchor Safe Links" `
    -AdminDisplayName "Anchor Safe Links" `
    -EnableOrganizationBranding $True `
    -EnableSafeLinksForOffice $True `
    -EnableSafeLinksForTeams $True `
    -EnableSafeLinksForEmail $True `
    -TrackClicks $True `
    -AllowClickThrough $True `
    -ScanUrls $True `
    -EnableForInternalSenders $True `
    -DeliverMessageAfterScan $True
New-SafeLinksRule `
    -Name "Anchor Safe Links" `
    -SafeLinksPolicy "Anchor Safe Links" `
    -RecipientDomainIs (Get-AcceptedDomain).Name
#Creates new Safe Attachments Policy
New-SafeAttachmentPolicy `
    -Name "Anchor Safe Attachments" `
    -AdminDisplayName "Anchor Safe Attachments" `
    -QuarantineTag "Quarantine with Notifications" `
    -Enable $True `
    -Redirect $False `
    -Action "Replace" `
    -ActionOnError $False 
New-SafeAttachmentRule `
    -Name "Anchor Safe Attachments" `
    -SafeAttachmentPolicy "Anchor Safe Attachments" `
    -RecipientDomainIs (Get-AcceptedDomain).Name