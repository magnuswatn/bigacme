Usage
===

To get a certificate:

1) Configure the virtual server
 The iRule must be added to the virtual server(s) that is accepting trafikk on port 80 for the domains. The iRule should be placed first, before any other rules.

2) Generate a CSR
 System -> File Management -> SSL Certificate List  -> New. Fill inn a name and subject alternate names, in form "DNS: domain1.example.com, DNS: domain2.example.com"

3) Run bigacme
 While in the configuration folder, run ```bigacme new partition csrname```. So if you called the csr "example.com_LetsEncrypt" and it is located in the app01 partition, run ```bigacme new app01 example.com_LetsEncrypt```.

Now you're done. The certificate will be installed on the Big-IP and renewed before it expires. Do not remove the iRule from the virtual server, as it will break the validation process.
