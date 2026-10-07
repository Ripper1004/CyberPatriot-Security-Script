# =============================================================================
#  Example config for Harden.ps1 - copy it, fill it in from the README, then run:
#     copy config.example.psd1 my-readme.psd1
#     notepad my-readme.psd1
#     powershell -ExecutionPolicy Bypass -File .\Harden.ps1 -Mode Audit -Config .\my-readme.psd1
#     powershell -ExecutionPolicy Bypass -File .\Harden.ps1 -Mode Apply -Config .\my-readme.psd1
#
#  Put each name in 'single quotes', separated by commas.
# =============================================================================
@{
    # Administrators listed in the README (they keep / get admin rights)
    AuthorizedAdmins = @('alice', 'bob')

    # Other authorized users listed in the README (normal users)
    AuthorizedUsers  = @('carol', 'dave', 'erin')

    # Services the README says must keep working. Keywords the script understands:
    #   rdp iis web ftp smb fileshare dns dhcp ad winrm ssh print sql mysql apache snmp telnet vnc
    # Leave empty - @() - if the README lists none.
    CriticalServices = @('rdp')

    # Strong password given to every authorized user EXCEPT the one running the
    # script. 12+ characters with upper, lower, number and symbol.
    # 'skip' = leave passwords alone. '' = ask.
    NewPassword      = ''

    # Account lockout after 5 wrong passwords: 'yes' or 'no'
    EnableLockout    = 'yes'

    # Install all Windows updates during the run (slow!): 'yes', 'no' or 'ask'
    InstallUpdates   = 'ask'
}
