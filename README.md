# **Fabric script to provision Debian 8.1 Linode**

This fabric script has a main task to setup a Debian 8.1 webserver running nginx, MySQL and php5.

The secondary tasks will be to prepare for deployment of various types of apps. The first one being a Flask app using gunicorn and supervisor to manage it.

#Configuration

Use the `config_example.json` file and rename it to `config.json`

Each further deployable type of app will have it's own section.

#Tasks

##1. `fab setup_server`

Takes no arguments and will run the main server setup. Once it has been ran the root user will not longer have remote access so that task can only be run once.

This task will first do a basic setup of the server as the **root** user:

* Sets the hostname
* Sets the timezone
* Run apt-get update and upgrade
* Adds some user groups
* Sets a timeout to the sudo password of 10 minutes
* Prepares a better /etc/skel folder for future users
* Sets the default user umask to 0027
* Hardens some files permissions

It will then create the admin user and print the random password it used so you can change it once the script is done running. This admin user will also have your public ssh key set and be added to the sshlogin group.

The script will then harden the system with these steps:

* Modify sshd_config to prevent root ssh login and password authentification. Only members of the sshlogin group will be able to log remotely with ssh and the server IP has to be used, no DNS.
* Harden sysctl settings
* Prevent IP spoofing
* Set proper and persistant iptables

The next steps wil install and configure the various services needed to run a basic web server:

* Install Git from source
* Install and configure nginx
* Install and configure MySQL (change some of the values according to your system specs)
* Install and configure php5-fpm
* Install and configure unattended upgrades
* Install and configure rkhunter toolkit

##2. `fab app_setup_flask`

This task can take one argument, defaults to `fab app_setup_flask:ssh_key=True`

Set it to `False` if you want a prompt to paste the flask app user's public key instead of using the key from your config file.

These are the steps taken:

* Install and configure all the requirements to run a Flask app with Gunicorn and Supervisor
* Create a new user for this app
* Create a remote git repository to push our app to and adds it to the flask app remotes
* Pushes the code to the git repository, installs and starts the flask app
* Sets up a new nginx virtualhost
* Sets up a new supervisor app. supervisorctl is set to not require sudo so it can be ran by a fabfile in your flask app.

See this [skeleton flask app](https://github.com/nekwebdev/fab-flaskapp) for an example on how the flask app needs to be setup and the fabfile it uses to automatically deploy and restart the remote app.

##3. `fab create_user:username, admin=False, ssh_key=True`

Creates a new user, can be admin if set to True, and will ask for the ssh public key in a prompt if ssh_key is set to False.

##4. `fab update_git:version=vx.x.x`

Will update git to the specified version tag.