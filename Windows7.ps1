Configuration CIS_Windows7_V310{
    #base on V3.10 03-30-2018 L1 to setup 
    
    #implement Section 1,2, 5 L1 
    
    #missing 2.3.10.7 2.3.10.7 2.3.10.7
    param(
        [string[]]$NodeName = 'localhost'
    )

    Import-DscResource -ModuleName PSDscResources
    Import-DscResource -ModuleName SecurityPolicyDsc
    Import-DscResource -ModuleName AuditPolicyDsc
    

    Node $NodeName{


   
   AccountPolicy CIS11{

        name='CIS11_AccountPolicy'
        Enforce_password_history ='24'
        Maximum_Password_Age ='60'
        Minimum_Password_Age =  '1'
        Minimum_Password_Length ='14'
        Password_must_meet_complexity_requirements ='Enabled'
        Store_passwords_using_reversible_encryption ='Disabled'

        Account_lockout_duration ='15'
        Account_lockout_threshold ='10'
        Reset_account_lockout_counter_after = '15'

        }

     # 2.2.1
    UserRightsAssignment Access_Credential_Manager_as_a_trusted_caller{
        policy = 'Access_Credential_Manager_as_a_trusted_caller'
        Identity= ''
        Force=$True
        Ensure='Present'

    }


    # 2.2.2
    UserRightsAssignment AccessthisComputerFromTheNetwork{
        policy = 'Access_this_Computer_From_The_Network'
        Identity= 'Administrators'
        Force=$True
        Ensure='Present'

    }
    
    # 2.2.3
    UserRightsAssignment Act_as_part_of_the_operating_system{
        policy = 'Act_as_part_of_the_operating_system'
        Identity= ''
        Force=$True
        Ensure='Present'

    }

     # 2.2.4
    UserRightsAssignment Adjust_memory_quotas_for_a_process{
        policy = 'Adjust_memory_quotas_for_a_process'
        Identity= @('Administrators', 'LOCAL SERVICE', 'NETWORK SERVICE')
        Force=$True
        Ensure='Present'
    }

    
     # 2.2.5
    UserRightsAssignment Allow_log_on_locally{
        policy = 'Allow_log_on_locally'
        Identity= @('Administrators', 'Users')
        Force=$True
        Ensure='Present'
    }

     # 2.2.6
    UserRightsAssignment Allow_log_on_through_Remote_Desktop_Services{
        policy = 'Allow_log_on_through_Remote_Desktop_Services'
        Identity= @('Administrators', 'Remote Desktop Users')
        Force=$True
        Ensure='Present'
    }

    # 2.2.7
    UserRightsAssignment Back_up_files_and_directories{
        policy = 'Back_up_files_and_directories'
        Identity= 'Administrators'
        Force=$True
        Ensure='Present'
    }

    # 2.2.8
    UserRightsAssignment Change_the_system_time{
        policy = 'Change_the_system_time'
        Identity= @('Administrators', 'LOCAL SERVICE')
        Force=$True
        Ensure='Present'
    }

    # 2.2.9
    UserRightsAssignment Change_the_time_zone{
        policy = 'Change_the_time_zone'
        Identity= @('Administrators', 'LOCAL SERVICE', 'USERS')
        Force=$True
        Ensure='Present'
    }


    # 2.2.10
    UserRightsAssignment Create_a_pagefile{
        policy = 'Create_a_pagefile'
        Identity= 'Administrators'
        Force=$True
        Ensure='Present'
    }

     # 2.2.11
    UserRightsAssignment Create_a_token_object{
        policy = 'Create_a_token_object'
        Identity= ''
        Force=$True
        Ensure='Present'
    }


    # 2.2.12
      UserRightsAssignment Create_global_objects{
        policy = 'Create_global_objects'
        Identity= @('Administrators', 'Local Service', 'Network Service')
        Force=$True
        Ensure='Present'
    }


     # 2.2.13
      UserRightsAssignment Create_permanent_shared_objects{
        policy = 'Create_permanent_shared_objects'
        Identity= ''
        Force=$True
        Ensure='Present'
    }


     # 2.2.14
      UserRightsAssignment Create_symbolic_links{
        policy = 'Create_symbolic_links'
        Identity= 'Administrators'
        Force=$True
        Ensure='Present'
    }

     # 2.2.15
      UserRightsAssignment Debug_programs{
        policy = 'Debug_programs'
        Identity= 'Administrators'
        Force=$True
        Ensure='Present'
    }


    # 2.2.16
      UserRightsAssignment Deny_access_to_this_computer_from_the_network{
        policy = 'Deny_access_to_this_computer_from_the_network'
        Identity= @('Guests', 'Local account')
        Force=$True
        Ensure='Present'
    }

    # 2.2.17
      UserRightsAssignment Deny_log_on_as_a_batch_job{
        policy = 'Deny_log_on_as_a_batch_job'
        Identity= 'Guests'
        Force=$True
        Ensure='Present'
    }

    # 2.2.18
      UserRightsAssignment Deny_log_on_as_a_service{
        policy = 'Deny_log_on_as_a_service'
        Identity= 'Guests'
        Force=$True
        Ensure='Present'
    }


    # 2.2.19
      UserRightsAssignment Deny_log_on_locally{
        policy = 'Deny_log_on_locally'
        Identity= 'Guests'
        Force=$True
        Ensure='Present'
    }

    # 2.2.20
      UserRightsAssignment Deny_log_on_through_Remote_Desktop_Services{
        policy = 'Deny_log_on_through_Remote_Desktop_Services'
        Identity= @('Guests', 'Local Account')
        Force=$True
        Ensure='Present'
    }

    # 2.2.21
      UserRightsAssignment Enable_computer_and_user_accounts_to_be_trusted_for_delegation{
        policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
        Identity= ''
        Force=$True
        Ensure='Present'
    }

    # 2.2.22
      UserRightsAssignment Force_shutdown_from_a_remote_system{
        policy = 'Force_shutdown_from_a_remote_system'
        Identity= 'Administrators'
        Force=$True
        Ensure='Present'
    }



    # 2.2.23
      UserRightsAssignment Generate_security_audits{
        policy = 'Generate_security_audits'
        Identity= @('Local Service', 'Network Service')
        Force=$True
        Ensure='Present'
    }

    # 2.2.24
      UserRightsAssignment Impersonate_a_client_after_authentication{
        policy = 'Impersonate_a_client_after_authentication'
        Identity= @('Administrators', 'Local Service', 'Network Service')
        Force=$True
        Ensure='Present'
    }

    # 2.2.25
      UserRightsAssignment Increase_scheduling_priority{
        policy = 'Increase_scheduling_priority'
        Identity= @('Administrators')
        Force=$True
        Ensure='Present'
    }

    # 2.2.26
      UserRightsAssignment Load_and_unload_device_drivers{
        policy = 'Load_and_unload_device_drivers'
        Identity= @('Administrators')
        Force=$True
        Ensure='Present'
    }

    # 2.2.27
      UserRightsAssignment Lock_pages_in_memory{
        policy = 'Lock_pages_in_memory'
        Identity= ''
        Force=$True
        Ensure='Present'
    }

    # 2.2.28
      UserRightsAssignment Log_on_as_a_batch_job{
        policy = 'Log_on_as_a_batch_job'
        Identity= @('Administrators')
        Force=$True
        Ensure='Present'
    }

    # 2.2.29
      UserRightsAssignment Log_on_as_a_service{
        policy = 'Log_on_as_a_service'
        Identity= ''
        Force=$True
        Ensure='Present'
    }

     # 2.2.30
      UserRightsAssignment Manage_auditing_and_security_log{
        policy = 'Manage_auditing_and_security_log'
        Identity= @('Administrators')
        Force=$True
        Ensure='Present'
    }

    # 2.2.31
      UserRightsAssignment Modify_an_object_label{
        policy = 'Modify_an_object_label'
        Identity= ''
        Force=$True
        Ensure='Present'
    }

     # 2.2.32
      UserRightsAssignment Modify_firmware_environment_values{
        policy = 'Modify_firmware_environment_values'
        Identity= @('Administrators')
        Force=$True
        Ensure='Present'
    }

     # 2.2.33
      UserRightsAssignment Perform_volume_maintenance_tasks{
        policy = 'Perform_volume_maintenance_tasks'
        Identity= @('Administrators')
        Force=$True
        Ensure='Present'
    }



    
   

     # 2.2.34
      UserRightsAssignment Profile_single_process{
        policy = 'Profile_single_process'
        Identity= @('Administrators')
        Force=$True
        Ensure='Present'
    }

     # 2.2.35
      UserRightsAssignment Profile_system_performance{
        policy = 'Profile_system_performance'
        Identity= @('Administrators', 'NT SERVICE\WDIServiceHOST')
        Force=$True
        Ensure='Present'
    }


    # 2.2.36
      UserRightsAssignment Replace_a_process_level_token{
        policy = 'Replace_a_process_level_token'
        Identity= @('LOCAL SERVICE','NETWORK SERVICE')
        Force=$True
        Ensure='Present'
    }



     # 2.2.37
      UserRightsAssignment Restore_files_and_directories{
        policy = 'Restore_files_and_directories'
        Identity= @('Administrators')
        Force=$True
        Ensure='Present'
    }

    # 2.2.378
      UserRightsAssignment Shut_down_the_system{
        policy = 'Shut_down_the_system'
        Identity= @('Administrators','Users')
        Force=$True
        Ensure='Present'
    }

     # 2.2.39
      UserRightsAssignment Take_ownership_of_files_or_other_objects{
        policy = 'Take_ownership_of_files_or_other_objects'
        Identity= @('Administrators')
        Force=$True
        Ensure='Present'
    }




    
    # 2.3 Security Options

    SecurityOption CIS2_3{
    
        Name='SecurityOption'

        Accounts_administrator_account_status ='Disabled' #2.3.1.1
        
        
        Accounts_Guest_account_status ='Disabled' #2.3.1.2 

        Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only =  'Disabled' #2.3.1.3

        Accounts_Rename_administrator_account ='RenamedAdmin' #2.3.1.4

        Accounts_Rename_guest_account ='RenamedGuest' #2.3.1.5


        Devices_Allowed_to_format_and_eject_removable_media = 'Administrators and Interactive Users' # 2.3.4.1


        

        Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled' #2.3.6.1

        Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled' #2.3.6.2

        Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'  #2.3.6.3

        Domain_controller_Refuse_machine_account_password_changes = 'Enabled' #2.3.6.4

        Domain_member_Maximum_machine_account_password_age ='14' #2.3.6.5

        Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'  #2.3.6.6


               

        Interactive_logon_Do_not_display_last_user_name = 'Enabled'  #2.3.7.1
        Interactive_logon_Do_not_require_CTRL_ALT_DEL ='Disabled' #2.3.7.2
        Interactive_logon_Message_text_for_users_attempting_to_log_on ='logon_Message_tex' #2.3.7.3
        Interactive_logon_Message_title_for_users_attempting_to_log_on='logon_Message_tex' #2.3.7.4
        Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available= '4' #2.3.7.5
        Interactive_logon_Prompt_user_to_change_password_before_expiration = '14' #2.3.7.6
        Interactive_logon_Smart_card_removal_behavior ='Lock workstation'  #2.3.7.7



        Microsoft_network_client_Digitally_sign_communications_always = 'Enabled' #2.3.8.1
        Microsoft_network_client_Digitally_sign_communications_if_server_agrees ='Enabled' #2.3.8.2
        Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers ='Disabled' #2.3.8.3



        Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = '15' #2.3.9.1
        Microsoft_network_server_Digitally_sign_communications_always = 'Enabled' #2.3.9.2
        Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled' #2.3.9.3
        Microsoft_network_server_Disconnect_clients_when_logon_hours_expire = 'Enabled' #2.3.9.4
        Microsoft_network_server_Server_SPN_target_name_validation_level= 'Accept if provided by client' #2.3.9.5




        Network_access_Allow_anonymous_SID_Name_translation = 'Disabled' #2.3.10.1
        Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled' #2.3.10.2
        Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares ='Enabled' #2.3.10.3
        Network_access_Do_not_allow_storage_of_passwords_and_credentials_for_network_authentication='Enabled' #2.3.10.4
        Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled' #2.3.10.5
        Network_access_Named_Pipes_that_can_be_accessed_anonymously = '' #2.3.10.6
        Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares ='Enabled' #2.3.10.9

        Network_access_Sharing_and_security_model_for_local_accounts ='Classic - Local users authenticate as themselves' #2.3.10.11
        #Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM = '' #2.3.10.10
        #
        #Network_access_Remotely_accessible_registry_paths = @('System\CurrentControlSet\Control\ProductOptions','System\CurrentControlSet\Control\Server Applications','Software\Microsoft\Windows NT\CurrentVersion')
        
       Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled' #2.3.11.1
        Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled' #2.3.11.2

        Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities ='Disabled' #2.3.11.3
        Network_security_Configure_encryption_types_allowed_for_Kerberos =@('AES128_HMAC_SHA1', 'AES256_HMAC_SHA1', 'FUTURE') #2.3.11.4
        Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change ='Enabled' #2.3.11.5
        Network_security_Force_logoff_when_logon_hours_expire = 'Enabled' #2.3.11.6
        Network_security_LAN_Manager_authentication_level ='Send NTLMv2 responses only. Refuse LM & NTLM' #2.3.11.7
        Network_security_LDAP_client_signing_requirements ='Negotiate Signing' #2.3.11.8
        Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'  #2.3.11.9
        Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_Servers = 'Both options checked'  #2.3.11.10


        System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer ='User is prompted when the key is first used' #2.3.14.1
        System_objects_Require_case_insensitivity_for_non_Windows_subsystems ='Enabled' #2.3.15.1
 
        System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links ='Enabled' #2.3.15.2

        System_settings_Optional_subsystems= '' #2.3.16.1

        User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account ='Enabled' #2.3.17.1
        User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop	 ='Disabled' #2.3.17.2
        User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode ='Prompt for consent on the secure desktop' #2.3.17.3
        User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users ='Automatically deny elevation request' #2.3.17.4
        User_Account_Control_Detect_application_installations_and_prompt_for_elevation ='Enabled' #2.3.17.5
        User_Account_Control_Only_elevate_executables_that_are_signed_and_validated ='Enabled' #2.3.17.6
        User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode ='Enabled' #2.3.17.7
        User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation ='Enabled' #2.3.17.8
        User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations ='Enabled' #2.3.17.9
        
    }













     # 5.2
     Service Computer_Browser{
        Name  = 'Browser'
        StartupType = 'Disabled'
        State ='Stopped'
    }

    # 5.3
     Service HomeGroup_Listener{
        Name  = 'HomeGroupListener'
        StartupType = 'Disabled'
        State ='Stopped'
        
    }

    # 5.4
     Service HomeGroup_Provider{
        Name  = 'HomeGroupProvider'
        StartupType = 'Disabled'
        State ='Stopped'
        
    }

    
    # 5.5
     Service IIS_Admin_Service{
        Name= 'IISADMIN'
        Ensure='Absent'
        
    }



    # 5.6
     Service Internet_Connection_Sharing{
        Name  = 'SharedAccess'
        StartupType = 'Disabled'
        State ='Stopped'
        
    }

    
    # 5.8
     Service Media_Center_Extender_Service{
        Name= 'Mcx2Svc'
        Ensure='Absent'
        
    }

     # 5.9
     Service Microsoft_FTP_Service{
        Name= 'FTPSVC'
        Ensure='Absent'
        
    }



     # 5.20
     Service Remote_Procedure_Call_RPC_Locator{
        Name  = 'RpcLocator'
        StartupType = 'Disabled'
        State ='Stopped'
        
    }

     # 5.22
     Service Routing_and_Remote_Access{
        Name  = 'RemoteAccess'
        StartupType = 'Disabled'
        State ='Stopped'
        
    }
    
    
    # 5.24
     Service Simple_TCPIP_Service{
        Name= 'simptc'
        Ensure='Absent'
        
    }

     # 5.26
     Service SSDP_Discovery{
        Name  = 'SSDPSRV'
        StartupType = 'Disabled'
        State ='Stopped'

        
    }

    # 5.27
     Service Telnet_Service{
        Name= 'TlntSv'
        Ensure='Absent'
        
    }

     # 5.28
     Service UPnP_Device_Host{
        Name  = 'upnphost'
        StartupType = 'Disabled'
        State ='Stopped'
        
    }

    # 5.29
     Service Web_Management_Service{
        Name= 'WMSvc'
        Ensure='Absent'
        
    }

    # 5.30
     Service Windows_CardSpace{
        Name= 'idsv'
        Ensure='Absent'
        
    }

     # 5.33
     Service Windows_Media_Center_Receiver_Service{
        Name  = 'ehRecvr'
       Ensure='Absent'
        
    }


    
     # 5.34
     Service Windows_Media_Center_Scheduler_Service{
        Name  = 'ehSched'
       StartupType = 'Disabled'
        State ='Stopped'
        
        
    }

    # 5.35
     Service Windows_Media_Player_Network_Sharing_Service{
        Name  = 'WMPNetworkSvc'
        Ensure='Absent'
        
    }
    
     # 5.37
     Service WinHTTP_Web_Proxy_Auto_Discovery_Service{
        Name  = 'WinHttpAutoProxySvc'
        StartupType = 'Disabled'
        State ='Stopped'
        
    }
    # 5.38
     Service World_Wide_Web_Publishing_Service{
        Name= 'W3SVC'
        Ensure='Absent'
        
    }

    }
}

CIS_Windows7_V310
