


DEFAULT_CONFIG = "Windows10SystemLog.txt"

class Windows10SystemLogger:
    """Windows10SystemLogger writes error messages to the Windows 10 System log file
    for every rule in the JRE STIG that is violated.
    """

    def __init__(self, filename=DEFAULT_CONFIG):
        self.filename = filename
        self.log = open(filename, 'w')
        self.log.write("#########################\n\n")
        self.log.write("JRE Audit Findings\n\n")
    
    def __del__(self):
        print("Write out")
        self.log.write("#########################\n\n")
        self.log.close()

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")
    
    def remote_assistance_disabled(self, success):
        if not success:
           self.log.write("Check SV-78141r1_rule: ")
           self.log.write("Solicited Remote Assistance must not be allowed.\n\n")

    def windows_installer_elevated_prviliges_disabled(self, success):
        if not success:
           self.log.write("Check SV-77815r1_rule: ")
           self.log.write("The Windows Installer Always install with elevated privileges must be disabled.\n\n")


    def non_volume_autoplay_disabled(self, success):
        if not success:
           self.log.write("Check SV-78157r1_rule: ")
           self.log.write("Autoplay must be turned off for non-volume devices.\n\n")

    def annonymous_pipe_access_restricted(self, success):
        if not success:
           self.log.write("Check SV-78249r1_rule: ")
           self.log.write("Anonymous access to Named Pipes and Shares must be restricted.\n\n")

    def drive_autorun_disabled(self, success):
        if not success:
           self.log.write("Check SV-78163r1_rule: ")
           self.log.write("Autoplay must be disabled for all drives.\n\n")

    def autorun_commands_disabled(self, success):
        if not success:
           self.log.write("Check SV-78163r1_rule: ")
           self.log.write("The default autorun behavior must be configured to prevent autorun commands.\n\n")

    def sam_anonymous_enumeration_disabled(self, success):
        if not success:
           self.log.write("Check SV-78235r1_rule: ")
           self.log.write("Anonymous enumeration of SAM accounts must not be allowed.\n\n")

    def sehop_disabled(self, success):
        if not success:
           self.log.write("Check SV-83445r1_rule: ")
           self.log.write("Structured Exception Handling Overwrite Protection (SEHOP) must be turned on.\n\n")

    def recovery_console_enabled(self, success):
        if not success:
           self.log.write("Check SV-78299r1_rule: ")
           self.log.write("The Recovery Console option must be set to prevent automatic logon to the system.\n\n")

    def lanman_auth_level_set(self, success):
        if not success:
           self.log.write("Check SV-78291r1_rule: ")
           self.log.write("The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM.\n\n")

    def winrm_service_basic_auth_disabled(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The Windows Remote Management (WinRM) service must not use Basic authentication.\n\n")

    def annonymous_share_enumeration_disabled(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("Anonymous enumeration of shares must be restricted..\n\n")

    def winrm_client_basic_auth_disabled(self, success):
        if not success:
           self.log.write("Check SV-77825r1_rule: ")
           self.log.write("The Windows Remote Management (WinRM) client must not use Basic authentication.\n\n")

    def emet_sehop_optout_set(self, success):
        if not success:
           self.log.write("Check SV-77901r2_rule: ")
           self.log.write("The Enhanced Mitigation Experience Toolkit (EMET) system-wide Structured Exception Handler Overwrite Protection (SEHOP) must be configured to Application Opt Out.\n\n")

    def emet_deephooks_set(self, success):
        if not success:
           self.log.write("Check SV-77901r2_rule: ")
           self.log.write("The Enhanced Mitigation Experience Toolkit (EMET) system-wide Structured Exception Handler Overwrite Protection (SEHOP) must be configured to Application Opt Out.\n\n")

    def unencrypted_passwd_smb_disabled(self, success):
        if not success:
           self.log.write("Check SV-78201r1_rule: ")
           self.log.write("Unencrypted passwords must not be sent to third-party SMB Servers.\n\n")

    def smartscreen_filter_enabled(self, success):
        if not success:
           self.log.write("Check SV-78203r1_rule: ")
           self.log.write("The SmartScreen filter for Microsoft Edge must be enabled.\n\n")

    def hardware_device_pfw_enabled(self, success):
        if not success:
           self.log.write("Check SV-78207r2_rule: ")
           self.log.write("The SmartScreen filter for Microsoft Edge must be enabled.\n\n")

    def smb_packet_signing_set(self, success):
        if not success:
           self.log.write("Check SV-78209r1_rule: ")
           self.log.write("The Windows SMB server must be configured to always perform SMB packet signing.\n\n")





    def client_rpc_authentication_set(self, success):
        if not success:
           self.log.write("Check SV-78145r1_rule: ")
           self.log.write(" Client computers must be required to authenticate for RPC communication.\n\n")

    def unauthenticated_rpc_elient_restricted(self, success):
        if not success:
           self.log.write("Check SV-78147r1_rule: ")
           self.log.write("Unauthenticated RPC clients must be restricted from connecting to the RPC server.\n\n")

    def application_event_log_size_set(self, success):
        if not success:
           self.log.write("Check SV-78009r1_rule: ")
           self.log.write("The Application event log size must be configured to 32768 KB or greater.\n\n")


    def user_installation_option_disabled(self, success):
        if not success:
           self.log.write("Check SV-77811r1_rule: ")
           self.log.write("Users must be prevented from changing installation options.\n\n")

    def powershell_script_block_logging_enabled(self, success):
        if not success:
           self.log.write("Check SV-83411r1_rule: ")
           self.log.write("PowerShell script block logging must be enabled.\n\n")

    def tcp_port_set(self, success):
        if not success:
           self.log.write("Check SV-78019r1_rule: ")
           self.log.write("The system must be configured to send error reports on TCP port 1232.\n\n")

    def strong_session_key_required(self, success):
        if not success:
           self.log.write("Check SV-78155r1_rule: ")
           self.log.write("The system must be configured to require a strong session key.\n\n")

    def tcp_port_set(self, success):
        if not success:
           self.log.write("Check SV-78019r1_rule: ")
           self.log.write("The system must be configured to send error reports on TCP port 1232.\n\n")

    def screen_saver_set(self, success):
        if not success:
           self.log.write("Check SV-78159r1_rule: ")
           self.log.write("The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver.\n\n")

    def error_reports_generated(self, success):
        if not success:
           self.log.write("Check SV-77949r1_rule: ")
           self.log.write("The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver.\n\n")

    def smb_packet_signing(self, success):
        if not success:
           self.log.write("Check SV-78197r1_rule: ")
           self.log.write("The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver.\n\n")

    def inprivate_browsing_disabled(self, success):
        if not success:
           self.log.write("Check SV-78195r1_rule: ")
           self.log.write("The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver.\n\n")


    def smb_packet_signing_required(self, success):
        if not success:
           self.log.write("Check SV-78193r1_rule: ")
           self.log.write(" The Windows SMB client must be configured to always perform SMB packet signing.\n\n")

    def app_override_disabled(self, success):
        if not success:
           self.log.write("Check SV-78191r1_rule: ")
           self.log.write("Users must not be allowed to ignore SmartScreen filter warnings for unverified files in Microsoft Edge.\n\n")

    def automatic_logon_disabled(self, success):
        if not success:
           self.log.write("Check SV-78041r2_rule: ")
           self.log.write("Automatic logons must be disabled.\n\n")

    def ipv6_routing_protection_configured(self, success):
        if not success:
           self.log.write("Check SV-78045r1_rule: ")
           self.log.write("IPv6 source routing must be configured to highest protection.\n\n")

    def screen_saver_enabled(self, success):
        if not success:
           self.log.write("Check SV-78325r1_rule: ")
           self.log.write("A screen saver must be enabled on the system.\n\n")

    def ip_source_routing_disabled(self, success):
        if not success:
           self.log.write("Check SV-78049r1_rule: ")
           self.log.write("The system must be configured to prevent IP source routing.\n\n")

    def multiple_error_reports_set(self, success):
        if not success:
           self.log.write("Check SV-77987r1_rule: ")
           self.log.write("The system must be configured to collect multiple error reports of the same event type.\n\n")

    def enhanced_antispoofing_set(self, success):
        if not success:
           self.log.write("Check SV-78167r1_rule: ")
           self.log.write("Enhanced anti-spoofing when available must be enabled for facial recognition.\n\n")

    def winrm_runas_disabled(self, success):
        if not success:
           self.log.write("Check SV-77865r1_rule: ")
           self.log.write("Enhanced anti-spoofing when available must be enabled for facial recognition.\n\n")

    def zone_info_saved(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("Zone information must be preserved when saving attachments.\n\n")

    def num_error_reports_configured(self, success):
        if not success:
           self.log.write("Check SV-78033r1_rule: ")
           self.log.write("The maximum number of error reports to archive on a system must be configured to 100 or greater.\n\n")

    def lock_screen_camera_access_disabled(self, success):
        if not success:
           self.log.write("Check SV-78035r1_rule: ")
           self.log.write(" Camera access from the lock screen must be disabled.\n\n")

    def queue_error_reports_disabled(self, success):
        if not success:
           self.log.write("Check SV-78037r1_rule: ")
           self.log.write("The system must be configured to queue error reports until a local or DOD-wide collector is available.\n\n")

    def lock_screen_slide_shows_disabled(self, success):
        if not success:
           self.log.write("Check SV-78039r1_rule: ")
           self.log.write("The system must be configured to queue error reports until a local or DOD-wide collector is available.\n\n")

    def winrm_unencrypted_traffic_disabled(self, success):
        if not success:
           self.log.write("Check SV-77859r1_rule: ")
           self.log.write("The system must be configured to queue error reports until a local or DOD-wide collector is available.\n\n")

    def smartscreen_admin_aproval_required(self, success):
        if not success:
           self.log.write("Check SV-78175r1_rule: ")
           self.log.write("The Windows SmartScreen must be configured to require approval from an administrator before running downloaded \n\n")

    def windows_telemetry_data_set(self, success):
        if not success:
           self.log.write("Check SV-78173r1_rule: ")
           self.log.write("The Windows SmartScreen must be configured to require approval from an administrator before running downloaded unknown software.\n\n")

    def classic_security_model_set(self, success):
        if not success:
           self.log.write("Check SV-78251r1_rule: ")
           self.log.write("The system must be configured to use the Classic security model.\n\n")


    def computer_identity_negotiation_set(self, success):
        if not success:
           self.log.write("Check SV-78253r1_rule: ")
           self.log.write("Services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity vs. authenticating anonymously.\n\n")

    def ntml_null_session_disabled(self, success):
        if not success:
           self.log.write("Check SV-78253r1_rule: ")
           self.log.write("NTLM must be prevented from falling back to a Null session.\n\n")

    def group_policy_objects_reprocess_set(self, success):
        if not success:
           self.log.write("Check SV-78099r1_rule: ")
           self.log.write("Group Policy objects must be reprocessed even if they have not changed.\n\n")

    def pku2u_authentication_disabled(self, success):
        if not success:
           self.log.write("Check SV-78099r1_rule: ")
           self.log.write("Group Policy objects must be reprocessed even if they have not changed.\n\n")

    def powershell_script_block_invocation_logging(self, success):
        if not success:
           self.log.write("Check SV-83413r1_rule: ")
           self.log.write("PowerShell script block invocation logging must be enabled.\n\n")

    def all_error_ports_added_to_queue(self, success):
        if not success:
           self.log.write("Check SV-78047r1_rule: ")
           self.log.write("The system must be configured to add all error reports to the queue.\n\n")

    def consent_override_behavior_set(self, success):
        if not success:
           self.log.write("Check SV-78065r1_rule: ")
           self.log.write("The system must be configured to add all error reports to the queue.\n\n")

    def data_transmission_consent_set(self, success):
        if not success:
           self.log.write("Check SV-78061r1_rule: ")
           self.log.write("The system must be configured to automatically consent to send all data requested by a local or DOD-wide error collection site.\n\n")

    def pin_length_configuered(self, success):
        if not success:
           self.log.write("Check SV-78211r1_rule: ")
           self.log.write("The minimum pin length for Microsoft Passport for Work must be 6 characters or greater.\n\n")

    def encrypted_indexing_disabled(self, success):
        if not success:
           self.log.write("Check SV-78241r1_rule: ")
           self.log.write("Indexing of encrypted files must be turned off.\n\n")

    def password_storage_disabled(self, success):
        if not success:
           self.log.write("Check SV-78243r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of passwords and credentials.\n\n")

    def elevated_network_domain_privlidge_disabled(self, success):
        if not success:
           self.log.write("Check SV-78087r1_rule: ")
           self.log.write("Local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain systems.\n\n")

    def http_printer_driver_dl_disabled(self, success):
        if not success:
           self.log.write("Check SV-78105r1_rule: ")
           self.log.write("Downloading print driver packages over HTTP must be prevented.\n\n")

    def blank_passwd_accounts_disabled(self, success):
        if not success:
           self.log.write("Check SV-78107r1_rule: ")
           self.log.write("Local accounts with blank passwords must be restricted to prevent access from the network.\n\n")

    def wifi_sense_disabled(self, success):
        if not success:
           self.log.write("Check SV-78081r1_rule: ")
           self.log.write("Wi-Fi Sense must be disabled.\n\n")

    def emet_antidetours_set(self, success):
        if not success:
           self.log.write("Check SV-77915r2_rule: ")
           self.log.write("The Enhanced Mitigation Experience Toolkit (EMET) Default Actions and Mitigations Settings must enable Anti Detours.\n\n")

    def uac_admin_mode_enabled(self, success):
        if not success:
           self.log.write("Check SV-78319r1_rule: ")
           self.log.write("User Account Control must run all administrators in Admin Approval Mode, enabling UAC.\n\n")

    def sys_event_log_size_configuered(self, success):
        if not success:
           self.log.write("Check SV-78017r1_rule: ")
           self.log.write("The System event log size must be configured to 32768 KB or greater.\n\n")

    def uac_elevate_restricted(self, success):
        if not success:
           self.log.write("User Account Control must only elevate UIAccess applications that are installed in secure locations.\n\n")

    def uac_installer_detection_enabled(self, success):
        if not success:
           self.log.write("Check SV-78315r1_rule: ")
           self.log.write("User Account Control must be configured to detect application installations and prompt for elevation.\n\n")

    def kerberos_encrypt_configuered(self, success):
        if not success:
           self.log.write("Check SV-78315r1_rule: ")
           self.log.write("User Account Control must be configured to detect application installations and prompt for elevation.\n\n")

    def smb_packet_signing_required(self, success):
        if not success:
           self.log.write("Check SV-78213r1_rule: ")
           self.log.write("The Windows SMB server must perform SMB packet signing when possible.\n\n")

    def error_report_ssl_required(self, success):
        if not success:
           self.log.write("Check SV-78015r1_rule: ")
           self.log.write("The system must be configured to use SSL to forward error reports.\n\n")

    def domain_joined_computers_unenumerated(self, success):
        if not success:
           self.log.write("Check SV-78015r1_rule: ")
           self.log.write("The system must be configured to use SSL to forward error reports.\n\n")

    def max_error_queue_reports_set(self, success):
        if not success:
           self.log.write("Check SV-78051r1_rule: ")
           self.log.write("The system must be configured to use SSL to forward error reports.\n\n")

    def security_event_log_size_configuered(self, success):
        if not success:
           self.log.write("Check SV-78051r1_rule: ")
           self.log.write("The system must be configured to use SSL to forward error reports.\n\n")

    def rss_feed_attachements_disabled(self, success):
        if not success:
           self.log.write("Check SV-78233r1_rule: ")
           self.log.write("Attachments must be prevented from being downloaded from RSS feeds.\n\n")

    def admin_account_elevation_enumeration_disabled(self, success):
        if not success:
           self.log.write("Check SV-78169r1_rule: ")
           self.log.write("Administrator accounts must not be enumerated during elevation.\n\n")

    def user_errmsg_disabled(self, success):
        if not success:
           self.log.write("Check SV-77995r1_rule: ")
           self.log.write("Administrator accounts must not be enumerated during elevation.\n\n")

    def ignore_edge_warnings_disabled(self, success):
        if not success:
           self.log.write("Check SV-78189r1_rule: ")
           self.log.write(" Users must not be allowed to ignore SmartScreen filter warnings for malicious websites in Microsoft Edge.\n\n")

    def wizard_provider_dl_disabled(self, success):
        if not success:
           self.log.write("Check SV-78189r1_rule: ")
           self.log.write("Users must not be allowed to ignore SmartScreen filter warnings for malicious websites in Microsoft Edge.\n\n")

    def nondomain_domain_network_blocked(self, success):
        if not success:
           self.log.write("Check SV-78075r1_rule: ")
           self.log.write("Connections to non-domain networks when connected to a domain authenticated network must be blocked.\n\n")
    def nui_disabled(self, success):
        if not success:
           self.log.write("Check SV-78119r1_rule: ")
           self.log.write("The network selection user interface (UI) must not be displayed on the logon screen.\n\n")

    def rds_encryption_level_set(self, success):
        if not success:
           self.log.write("Check SV-78231r1_rule: ")
           self.log.write("Remote Desktop Services must be configured with the client connection encryption set to the required level.\n\n")

    def screen_saver_passwd_required(self, success):
        if not success:
           self.log.write("Check SV-78231r1_rule: ")
           self.log.write("Remote Desktop Services must be configured with the client connection encryption set to the required level.\n\n")

    def uac_virtalilzation_set(self, success):
        if not success:
           self.log.write("Check SV-78321r1_rule: ")
           self.log.write("User Account Control must virtualize file and registry write failures to per-user locations.\n\n")

    def daily_error_reports_required(self, success):
        if not success:
           self.log.write("Check SV-78055r1_rule: ")
           self.log.write("The system must be configured to attempt to forward queued error reports once a day.\n\n")

    def annonymous_users_excluded(self, success):
        if not success:
           self.log.write("Check SV-78055r1_rule: ")
           self.log.write("The system must be configured to attempt to forward queued error reports once a day.\n\n")

    def error_report_archive_configuered(self, success):
        if not success:
           self.log.write("Check SV-78029r1_rule: ")
           self.log.write("The system must be configured to store all data in the error report archive.\n\n")

    def uac_elevation_requests_disabled(self, success):
        if not success:
           self.log.write("Check SV-78029r1_rule: ")
           self.log.write("The system must be configured to store all data in the error report archive.\n\n")

    def smb_insecure_login_disabled(self, success):
        if not success:
           self.log.write("Check SV-78059r1_rule: ")
           self.log.write("Insecure logons to an SMB server must be disabled.\n\n")





    def error_reports_archived(self, success):
        if not success:
           self.log.write("Check SV-78059r1_rule: ")
           self.log.write("Insecure logons to an SMB server must be disabled.\n\n")

    def remote_desktop_host_secure_rpc_required(self, success):
        if not success:
           self.log.write("Check SV-78227r1_rule: ")
           self.log.write("The Remote Desktop Session Host must require secure RPC communications.\n\n")

    def spn_client_accept_configuered(self, success):
        if not success:
           self.log.write("Check SV-78225r1_rule: ")
           self.log.write(" The service principal name (SPN) target name validation level must be configured to Accept if provided by client.\n\n")

    def rsd_passwd_prompt_required(self, success):
        if not success:
           self.log.write("Check SV-78223r1_rule: ")
           self.log.write("Remote Desktop Services must always prompt a client for passwords upon connection.\n\n")

    def remote_desktop_session_hosts_local_drive_disabled(self, success):
        if not success:
           self.log.write("Check SV-78221r1_rule: ")
           self.log.write("Local drives must be prevented from sharing with Remote Desktop Session Hosts.\n\n")

    def outgoing_traffic_secured(self, success):
        if not success:
           self.log.write("Check SV-78129r1_rule: ")
           self.log.write("Outgoing secure channel traffic must be encrypted or signed.\n\n")

    def pin_signin_disabled(self, success):
        if not success:
           self.log.write("Check SV-78127r1_rule: ")
           self.log.write("Signing in using a PIN must be turned off.\n\n")

    def local_user_enumeration_disabled(self, success):
        if not success:
           self.log.write("Check SV-78123r1_rule: ")
           self.log.write("Local users on domain-joined computers must not be enumerated.\n\n")

    def emet_banned_functions_disabled(self, success):
        if not success:
           self.log.write("Check SV-77923r2_rule: ")
           self.log.write("The Enhanced Mitigation Experience Toolkit (EMET) Default Actions and Mitigations Settings must enable Banned Functions.\n\n")





    def onedrive_storage_disabled(self, success):
        if not success:
           self.log.write("Check SV-78215r1_rule: ")
           self.log.write("The use of OneDrive for storage must be disabled.\n\n")

    def audit_policy_subcategories_enabled(self, success):
        if not success:
           self.log.write("Check SV-78125r1_rule: ")
           self.log.write("The use of OneDrive for storage must be disabled.\n\n")

    def ldap_client_signing_level_set(self, success):
        if not success:
           self.log.write("Check SV-78293r1_rule: ")
           self.log.write("The use of OneDrive for storage must be disabled.\n\n")

    def ntlm_ssp_client_session_security_configuered(self, success):
        if not success:
           self.log.write("Check SV-78295r1_rule: ")
           self.log.write("The system must be configured to meet the minimum session security requirement for NTLM SSP based clients.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def ntlm_ssp_server_session_security_configuered(self, success):
        if not success:
           self.log.write("Check SV-78297r1_rule: ")
           self.log.write("The system must be configured to meet the minimum session security requirement for NTLM SSP based clients.\n\n")

    def winrm_digest_authentication_disabled(self, success):
        if not success:
           self.log.write("Check SV-77831r1_rule: ")
           self.log.write("The system must be configured to meet the minimum session security requirement for NTLM SSP based clients.\n\n")

    def command_line_creation_event_logged(self, success):
        if not success:
           self.log.write("Check SV-83409r1_rule: ")
           self.log.write("Command line data must be included in process creation events.\n\n")

    def uac_approval_mode_enabled(self, success):
        if not success:
           self.log.write("Check SV-78307r1_rule: ")
           self.log.write("User Account Control approval mode for the built-in Administrator must be enabled.\n\n")

    def ac_sleep_wakeup_password_required(self, success):
        if not success:
           self.log.write("Check SV-78139r1_rule: ")
           self.log.write("The user must be prompted for a password on resume from sleep (plugged in).n\n")

    def case_insensitivity_required(self, success):
        if not success:
           self.log.write("Check SV-78303r1_rule: ")
           self.log.write("The system must be configured to require case insensitivity for non-Windows subsystems.\n\n")

    def fips_compliant_algorithims_set(self, success):
        if not success:
           self.log.write("Check SV-78301r1_rule: ")
           self.log.write("The system must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing.\n\n")









    def untrusted_fonts_blocked(self, success):
        if not success:
           self.log.write("Check SV-78131r1_rule: ")
           self.log.write("The system must be configured to block untrusted fonts from loading.\n\n")

    def outgoing_traffic_signed(self, success):
        if not success:
           self.log.write("Check SV-78137r1_rule: ")
           self.log.write("Outgoing secure channel traffic must be signed when possible.\n\n")

    def remote_desktop_client_password_unsaved(self, success):
        if not success:
           self.log.write("Check SV-78219r1_rule: ")
           self.log.write("Passwords must not be saved in the Remote Desktop Client.\n\n")









    def dc_sleep_wakeup_password_required(self, success):
        if not success:
           self.log.write("Check SV-78135r1_rule: ")
           self.log.write("Users must be prompted for a password on resume from sleep (on battery).\n\n")

    def admin_consent_prompt_enabled(self, success):
        if not success:
           self.log.write("Check SV-78309r1_rule: ")
           self.log.write("Users must be prompted for a password on resume from sleep (on battery).\n\n")

    def machine_lockout_enabled(self, success):
        if not success:
           self.log.write("Check SV-78447r1_rule: ")
           self.log.write("Users must be prompted for a password on resume from sleep (on battery).\n\n")

    def http_printing_disabled(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("Printing over HTTP must be prevented.\n\n")


    def winrm_client_unencrypted_traffic_disabled(self, success):
        if not success:
           self.log.write("Check SV-77829r1_rule: ")
           self.log.write("The Windows Remote Management (WinRM) client must not allow unencrypted traffic.\n\n")

    def optional_accounts_enabled(self, success):
        if not success:
           self.log.write("Check SV-78149r1_rule: ")
           self.log.write("he setting to allow Microsoft accounts to be optional for modern style apps must be enabled.\n\n")









    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")









    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")









    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")









    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")









    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")









    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")









    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")









    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")









    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")









    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")









    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")









    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")









    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")

    def lan_manager_hash_disabled_errmsg(self, success):
        if not success:
           self.log.write("Check SV-78287r1_rule: ")
           self.log.write("The system must be configured to prevent the storage of the LAN Manager hash of passwords.\n\n")



















