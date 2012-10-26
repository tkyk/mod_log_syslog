Mod log syslog
================

`mod_log_syslog` is an Apache module to send access logs to syslog.

Usage
------------

    CustomLog  syslog:<facility>.<priority>  <format>

Examples:

    CustomLog syslog:local1.info combined

    <VirtualHost *:80>
    CustomLog syslog:local2.debug common
    </VirtualHost>

Possible facilities: `local[0-7]` and `user`

Possible priorities: `debug`, `info`, `notice`, `warning`, `err`, `crit`, `alert`, and `emerg`


Requirements
------------

* Apache >= 2.2

Install
------------

    make install

    # If your apxs is not in the PATH
    make PATH=/usr/sbin:$PATH install

