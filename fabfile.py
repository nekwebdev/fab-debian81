# 1) Deploy the distro as small as possible. 
# 2) Create all the other disk images the sizes you want. 
# 3) Boot into rescue mode (note which image is on which device node) 
# 4) Mount all the images into unique locations (/media/xvda, /media/xvdb, etc) 
# 5) For each of the folders you want to move: cp -au /media/xvda/var/* /media/xvde/ ... then blow away the source 'rm -rf /media/xvda/var/*' 
# 6) Edit /media/xvda/etc/fstab to reflect the mounts [when not in rescue mode]. 
# 7) Modify your configuration profile to reflect the new disk mappings 
# 8) Reboot. 
# 9) Profit? 

from fabric.api import *
from fabric.contrib.files import exists, append, upload_template, sed, uncomment
from fabric.colors import red, green
from fabric.contrib.console import confirm
import json
import random
import string

def err(string):
    print(red('Error: ' + string))
def success(string):
    print(green(string))

try:
    CONFIG = json.load(open('./config.json'))
except:
    err('Please create a config.json, see config_example.json for format')

# server vars
env.hosts = [CONFIG['server']['ip']]
env.user = CONFIG['server']['admin_user']
env.hostname = CONFIG['server']['hostname']
env.timezone = CONFIG['server']['timezone']
env.ssh_pubkey = CONFIG['server']['ssh_pubkey']

# flask app vars
env.flask_user = CONFIG['flask_app']['username']
env.flask_name = CONFIG['flask_app']['name']
env.flask_domain = CONFIG['flask_app']['domain']
env.flask_local_dir = CONFIG['flask_app']['local_app_dir']

# server config files locations
ssh_config = '/etc/ssh/sshd_config'
sysctl_config = '/etc/sysctl.conf'
host_config = '/etc/host.conf'
rkhunter_config = '/etc/rkhunter.conf'
rkhunter_config2 = '/etc/default/rkhunter'
nginx_config = '/etc/nginx/nginx.conf'
supervisor_config = '/etc/supervisor/supervisord.conf'
php_config = '/etc/php5/fpm/php.ini'
mysql_config = '/etc/mysql/my.cnf'


def backup_file(path, use_sudo = False):
    if use_sudo:
        sudo('cp %s %s.$(date +%%Y-%%m-%%d)' % (path, path))
    else:
        run('cp %s %s.$(date +%%Y-%%m-%%d)' % (path, path))


def basic_setup():
    success('Setting the hostname to %s...' % env.hostname)
    opts = {
        'server_ip': env.hosts[0],
        'hostname': env.hostname,
        'timezone': env.timezone
    }
    sudo('echo "\n%(server_ip)s %(hostname)s" >> /etc/hosts' % opts)
    append('/etc/hosts', '%(server_ip)s  %(hostname)s' % opts, use_sudo = True)
    sudo('hostname %(hostname)s' % opts)

    success('Setting the timezone to %s...' % env.timezone)
    sudo('echo "%(timezone)s" > /etc/timezone' % opts)
    sudo ('dpkg-reconfigure -f noninteractive tzdata')
    
    success('Update and upgrade')
    sudo('apt-get -yq update && apt-get -yq upgrade')
    sudo('apt-get -yq install build-essential')

    success('Add user groups')
    sudo('groupadd admin')
    sudo('groupadd sshlogin')
    sudo('groupadd web')

    success('Set a 10 minutes timeout to sudo password')
    sudo('echo "Defaults        timestamp_timeout=10" | (EDITOR="tee -a" visudo)')

    success('Setup new users skel folder')
    with cd('/etc/skel'):
        sudo('touch ./.bash_history')
        sudo('mkdir ./errors')
        sudo('mkdir ./logs')
        sudo('mkdir ./uploads')
        sudo('mkdir ./git')
        sudo('mkdir ./www')
        sudo('mkdir ./www/public')
        sudo('find . -type f -exec chmod 600 {} \;')
        sudo('find . -type d -exec chmod 700 {} \;')

    success('Set default user umask to 0027')
    umask = 'session optional        pam_umask.so umask=0027'
    append('/etc/pam.d/common-session', umask, use_sudo = True)
    append('/etc/pam.d/common-session-noninteractive', umask, use_sudo = True)

    success('Harden file permissions')
    sudo('chmod o-r /home')
    sudo('chmod 600 /etc/rsyslog.conf')
    sudo('chmod 600 /etc/sysctl.conf')
    sudo('chmod 640 /etc/security/access.conf')


def ssh_hardening():
    # Harden shh
    # Prevent root login, no password login, only sshlogin group allowed
    backup_file(ssh_config, use_sudo = True)
    put('./files/sshd_config', ssh_config, use_sudo = True)
    put('./files/issue.net', '/etc', use_sudo = True)
    sudo('service ssh restart')


def secure_network():
    # Harden sysctl
    backup_file(sysctl_config, use_sudo = True)

    put('./files/sysctl.conf', sysctl_config, use_sudo = True)
    sudo('sysctl -p')

    # Prevent IP Spoofing
    backup_file(host_config, use_sudo = True)
    put('./files/host.conf', host_config, use_sudo = True)

    # Setup new persistant firewall rules
    put('./files/iptables.firewall.rules', '/etc', use_sudo = True)   
    sudo('iptables-restore < /etc/iptables.firewall.rules')
    put('./files/firewall', '/etc/network/if-pre-up.d', use_sudo = True)
    sudo('chmod +x /etc/network/if-pre-up.d/firewall')


def install_git():
    opts = {
        'username': env.user
    }
    sudo('apt-get -y install libcurl4-gnutls-dev libexpat1-dev gettext libzen-dev libssl-dev')
    with cd('/home/%(username)s/git' % opts):
        run('wget https://github.com/git/git/archive/v1.8.3.2.tar.gz')
        run('tar -zxf v1.8.3.2.tar.gz')
        run('rm v1.8.3.2.tar.gz')
    with cd('/home/%(username)s/git/git-1.8.3.2' % opts):
        run('make --silent prefix=/usr/local all')
        sudo('make --silent prefix=/usr/local install')
    with cd('/home/%(username)s/git' % opts):
        run('rm -rf git-1.8.3.2')
        run('git clone https://github.com/git/git.git')


def better_motd():
    sudo('rm /etc/motd')
    sudo('touch /etc/motd')
    with cd('/home/%s' % env.user):
        run('cp .profile .profile.back')
        run('chmod 600 .profile.back')
    put('./files/profile', '.profile')


def install_unattended_upgrades():
    sudo('apt-get -yq install unattended-upgrades')
    put('./files/02periodic', '/etc/apt/apt.conf.d', use_sudo = True)


def install_rkhunter():
    # install RKHunter
    sudo('apt-get -yq install rkhunter')

    # ignore some Ubuntu specific files
    backup_file(rkhunter_config, use_sudo = True)
    uncomment(rkhunter_config, '#ALLOWHIDDENDIR=\/dev\/.udev', use_sudo = True)
    uncomment(rkhunter_config, '#ALLOWHIDDENDIR=\/dev\/.static', use_sudo = True)
    uncomment(rkhunter_config, '#ALLOWHIDDENDIR=\/dev\/.initramfs', use_sudo = True)

    # update files properties DB every time you run apt-get install, this
    # prevents warnings every time a new version of some package is installed
    backup_file(rkhunter_config2, use_sudo = True)
    append(rkhunter_config2, '# Update file properties database after running apt-get install', use_sudo = True)
    append(rkhunter_config2, 'APT_AUTOGEN="yes"', use_sudo = True)


def install_nginx():
    sudo('apt-get update')
    sudo('apt-get install -yq nginx')
    if exists('/etc/nginx/sites-enabled/default'):
        sudo('rm /etc/nginx/sites-enabled/default')
    # Set nginx tokens off
    backup_file(nginx_config, use_sudo = True)
    sed(nginx_config,
        '# server_tokens off;',
        'server_tokens off;',
        use_sudo = True)


def install_flask_requirements():
    sudo('apt-get update')
    sudo('apt-get install -yq python')
    sudo('apt-get install -yq python-pip')
    sudo('apt-get install -yq python-dev')
    sudo('apt-get install -yq python-virtualenv')
    sudo('apt-get install -yq gunicorn')
    sudo('apt-get install -yq supervisor')

    backup_file(supervisor_config, use_sudo = True)
    put('./files/supervisord.conf', supervisor_config, use_sudo = True)
    sudo('chown root:web %s' % supervisor_config)
    sudo('service supervisor restart')


def add_nginx_virtualhost(template, opts):
    if exists('/etc/nginx/sites-available/%(app_name)s' % opts) is False:        
        upload_template(template,
                        '/etc/nginx/sites-available/%(app_name)s' % opts,
                        context = opts,
                        use_sudo = True)
        sudo('ln -s /etc/nginx/sites-available/%(app_name)s' % opts +
             ' /etc/nginx/sites-enabled/%(app_name)s' % opts)
        append('/etc/hosts', '%(server_ip)s %(app_domain)s' % opts, use_sudo = True)
        sudo('service nginx restart')


def add_supervisor_app(template, opts):
    if exists('/etc/supervisor/conf.d/%(app_name)s.conf' % opts) is False:
        with cd('/etc/supervisor/conf.d'):
            upload_template(template,
                            './%(app_name)s.conf' % opts,
                            context = opts,
                            use_sudo = True)
        sudo('chown root:web /etc/supervisor/conf.d/%(app_name)s.conf' % opts)
        sudo('service supervisor restart')


def create_git_repository(template, opts):
    run('mkdir /home/%(app_user)s/www/%(app_name)s' % opts)
    with cd('/home/%(app_user)s/git' % opts):
        run('mkdir %(app_name)s.git' % opts)
        with cd('%(app_name)s.git' % opts):
            run('git init --bare')
            with cd('hooks'):
                upload_template(template, './post-receive', context = opts)
                run('chmod +x post-receive')


def install_flask_app(opts):
    remote_app_dir = '/home/%(app_user)s/www/%(app_name)s' % opts

    with cd(remote_app_dir):
        if exists('venv'):
            run('rm -rf venv')
        run('virtualenv venv')
        with prefix('source venv/bin/activate'):
            run('pip install -r requirements.txt')


def install_php5_fpm():
    sudo('apt-get -yq install php5-fpm php5-mysql')
    backup_file(php_config, use_sudo = True)
    sed(php_config,
        ';cgi.fix_pathinfo=1',
        'cgi.fix_pathinfo=0',
        use_sudo = True)
    sed(php_config,
        'error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT',
        'error_reporting = E_COMPILE_ERROR|E_RECOVERABLE_ERROR|E_ERROR|E_CORE_ERROR',
        use_sudo = True)
    sed(php_config,
        ';error_log = syslog',
        'error_log = /var/log/php.log',
        use_sudo = True)
    sed(php_config,
        ',pcntl_setpriority,',
        ',pcntl_setpriority,exec,system,shell_exec,passthru,',
        use_sudo = True)
    sed(php_config,
        'html_errors = On',
        'html_errors = Off',
        use_sudo = True)
    
    sudo('service php5-fpm restart')
    sudo('service nginx restart')


def install_mysql():
    default_password = ''.join([random.choice(string.ascii_letters \
               + string.digits) for n in xrange(12)])
    # first set root password in advance so we don't get the package
    # configuration dialog
    sudo('echo "mysql-server-5.0 mysql-server/root_password password %s" | debconf-set-selections' % default_password)
    sudo('echo "mysql-server-5.0 mysql-server/root_password_again password %s" | debconf-set-selections' % default_password)

    # install MySQL along with php drivers for it
    sudo('sudo apt-get -yq install mysql-server mysql-client')

    # Secure MySQL installation
    confirm(red("You will now start with interactive MySQL secure installation."
            " Current root password is '%s'. Change it "
            "and save the new one to your password managere. Then answer "
            "with default answers to all other questions. Ready?" % default_password))

    sudo('/usr/bin/mysql_secure_installation')

    backup_file(mysql_config, use_sudo = True)
    sed(mysql_config,
        '#max_connections        = 100',
        'max_connections        = 75',
        use_sudo = True)
    sed(mysql_config,
        'key_buffer              = 16M',
        'key_buffer              = 32M',
        use_sudo = True)
    sed(mysql_config,
        'max_allowed_packet      = 16M',
        'max_allowed_packet      = 1M',
        use_sudo = True)
    sed(mysql_config,
        'thread_stack            = 192K',
        'thread_stack            = 128K',
        use_sudo = True)
    sed(mysql_config,
        '#table_cache            = 64',
        'table_cache            = 32',
        use_sudo = True)

    # restart mysql and php-fastcgi
    sudo('service mysql restart')

    password = prompt(red('Please enter your mysql root password so I can configure weekly checks:'))
    sudo('echo "#!/bin/sh\nmysqlcheck -o --user=root --password=%s -A" > /etc/cron.weekly/mysqlcheck' % password)
    sudo('chmod +x /etc/cron.weekly/mysqlcheck')

    # Setup backup in /var/lib/automysqlbackup
    sudo('apt-get -yq install automysqlbackup')


@task
def create_user(username, admin = False, ssh_key = True):
    if not username:
        err("username must be set")
        return False

    # Check if user already exists
    if sudo('finger -ms %s 2>&1 1>/dev/null | wc -l' % username) == 0:
        err("username already in use")
        return False

    password = ''.join([random.choice(string.ascii_letters \
               + string.digits) for n in xrange(12)])
    
    opts = {
        'username': username,
        'password': password
    }

    success('Creating %(username)s...' % opts)

    sudo('groupadd %(username)s' % opts)
    sudo('useradd -s /bin/bash -m -g %(username)s -d /home/%(username)s %(username)s' % opts)
    sudo('echo "%(username)s:%(password)s" | chpasswd' % opts)
    
    # Only sshlogin group can log through ssh
    sudo('usermod -a -G sshlogin %(username)s' % opts)

    # Only web group can control certain processes such as supervisor
    sudo('usermod -a -G web %(username)s' % opts)

    if admin:
        success('Setting admin groups...')
        # Set admin groups
        sudo('usermod -a -G sudo %(username)s' % opts)
        sudo('usermod -a -G admin %(username)s' % opts)
        sudo('dpkg-statoverride --update --add root admin 4750 /bin/su')
        # Set admin umask
        append('/home/%(username)s/.profile' % opts, 'umask 077')

    
    success('Fix permissions and ownerships...')
    with cd('/home/%(username)s' % opts):
        sudo('chmod 711 .')
        sudo('chown -R %(username)s:www-data ./logs' % opts)
        sudo('chmod 770 ./logs')
        sudo('chmod g+rwxs ./logs')
        sudo('chown -R %(username)s:www-data ./errors' % opts)
        sudo('chmod 770 ./errors')
        sudo('chmod g+rwxs ./errors')
        sudo('chown -R %(username)s:www-data ./www' % opts)
        sudo('chmod -R 750 ./www')
        sudo('chmod g+rxs ./www')
        sudo('chmod g+rxs ./www/public')

        success('Setup SSH public key...')
        if not exists('./.ssh'):
            sudo('mkdir ./.ssh')
        if not ssh_key:  
            opts['pub'] = prompt("Paste %(username)s's public key: " % opts)
            sudo("echo '%(pub)s' > ./.ssh/authorized_keys" % opts)
        else:
            put(env.ssh_pubkey, './.ssh/authorized_keys', use_sudo = True)
        sudo('chown -R %(username)s:%(username)s ./.ssh' % opts)
        sudo('chmod 700 ./.ssh')
        sudo('chmod 600 ./.ssh/authorized_keys')

    confirm(red("User %(username)s was successfully created. Notify "
                "him that he must login and change his default password "
                "(%(password)s) with the ``passwd`` command."
                " Proceed?" % opts))

    return opts['password']


@task
def update_git(version = None):
    if version is None:
        err("Git version tag must be specified, vx.x.x")
        return

    success('Updating git to %s...' % version)

    with cd('/home/%s/git/git' % env.user):
        run('git fetch')
        run('git tag')
        run('git checkout %s' % version)
        run('make prefix=/usr/local all')
        sudo('make prefix=/usr/local install')
        run('git --version')


@task
def setup_server():
    admin_user = env.user
    # Basic setup to be done under root
    with settings(user = 'root'):
        success('Basic server setup...')
        basic_setup()

        # Create our admin user
        env.password = create_user(admin_user, admin = True)

    success('ssh hardening...')
    ssh_hardening()

    success('Network hardening...')
    secure_network()

    success('Compile and install git from latest source...')
    install_git()
    
    success('Install unattended upgrades...')
    install_unattended_upgrades()

    success('Installing nginx...')
    install_nginx()

    success('Installing MySQL...')
    install_mysql()

    success('Installing php5...')
    install_php5_fpm()

    success('Install rkunter toolkit')
    install_rkhunter()

    success('Clean up...')
    better_motd()


@task
def app_setup_flask(ssh_key = True):
    success('Installing flask requirements: python, gunicorn and supervisor...')
    install_flask_requirements()

    # Create our flask app user
    create_user(env.flask_user, admin = False, ssh_key = ssh_key)

    opts = {
        'app_name': env.flask_name,
        'app_user': env.flask_user,
        'server_ip': env.hosts[0],
        'app_domain': env.flask_domain,
        'app_local_dir': env.flask_local_dir
    }

    success('Configuring git repository for %s...' % env.flask_name)
    with settings(user = env.flask_user):
        create_git_repository(template = './templates/flaskapp_post-receive',
                              opts = opts)      

    # Add our newly created remote repository to our local app git
    with lcd(env.flask_local_dir):
        local('git remote add production %(app_user)s@%(server_ip)s:/home/%(app_user)s/git/%(app_name)s.git' % opts)
        local('git push production master')

    success('Installing %s...' % env.flask_name)
    with settings(user = env.flask_user):
        install_flask_app(opts = opts)

    success('Add new nginx virtualhost for %s...' % env.flask_name)
    add_nginx_virtualhost(template = './templates/flaskapp_virtualhost',
                          opts = opts)

    success('Configuring supervisor for %s...' % env.flask_name)
    add_supervisor_app(template = './templates/flaskapp_supervisor.conf',
                         opts = opts)
