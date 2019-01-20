Installation
=====

### Configure the Big-IP
Answering of challenges from the CA is done through an iRule and a datagroup on the Big-IP. You must create the datagroup (type "String") and add the iRule (iRule.tcl). Normally these will be located in the Common partition, so that they can be used from several partitions. You can call them what you want, but you must update the iRule with the correct name of the datagroup.

Then you must create a user for bigacme. It must be have the iRule Manager role on the partition where the datagroup is (usually Common) and the Certificate Manager role on the partitions where certificates will be installed.

### Installation of bigacme

Bigacme must be installed on a server which is able to connect to the Big-IP and the CA. It is only tested on GNU/Linux, but should work on Windows as well. The easiest way is just to install it with the setup.py:

```python setup.py install```

This wil install it and all the prerequisites. Now the bigacme command is avaiable from the command line.

### Configure bigacme

Bigacme uses configuration folders to store the configuration and the certificates. You can create several configuration folders, if you have several Big-IPs. Create a folder, run the `bigacme config` command and follow the instructions. This wil generate the needed configuration folders and config files.

Then you must adapt the config.ini file in the config folder to your environment. Most of the options should be self explanatory, but here are the details:

```
[Common]
renewal days = This adjust how many days before the expiry date certificates will be renewed.
delayed installation days = This adjust how long to wait before installing a renewed certificate. A certificate issued seconds ago can cause troubles with some clients with bad clocks. Set to 0 for immediately installation.
account config = This is the path to the config file containing your account info (key and kid). This will be generated for you.

[Load Balancer]
cluster = This specifies whether you have several Big-IP instances in a failover cluster. If True, bigacme will connect to both and choose the active one.
host 1 = hostname for the first big-ip
host 2 = hostname for the second big-ip. You can delete this if you only have one Big-IP.
username = Username for the account on the Big-IP bigacme should use.
password = Password for the account on the Big-IP
datagroup = The name of the datagroup used by the iRule to answer challenges.
datagroup partition = The partition where the datagroup resides.

[Certificate Authority]
directory url = The directory URL to the ACME CA
use proxy = Whether bigacme should use a proxy to reach the CA. True or False
proxy = The proxy to use for communcation with the CA. If you specified False above, you can delete this line.

```

When you are finished with the config.ini file, you can register with the CA with the ```bigacme register``` command. This will create an account key and register it. Follow the instructions.

Try the ```bigacme test``` command to see if everything is in order.

Now we are almost finished. But you need to add a cron job for the renewing of certificates. Add the following command to cronjob: ```bigacme --config-dir /path/to/your/config renew```. The frequency is up to you, but be aware that certs will only be renewed and installed when the cron job runs. So if you run the cron job once a week, certificates will be installed after a week, even if you specify only 2 days for "delayed installation days".

Now you are ready to get a certificate!

If you have several Big-IP installations, you can just set up a configuration folders and cron jobs for each one..
