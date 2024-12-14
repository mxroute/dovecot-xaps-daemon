[![YourActionName Actions Status](https://github.com/freswa/dovecot-xaps-daemon/workflows/Test/badge.svg)](https://github.com/freswa/dovecot-xaps-daemon/actions)

iOS Push Email for Dovecot
==========================

What is this?
-------------

This project, together with the [dovecot-xaps-plugin](https://github.com/freswa/dovecot-xaps-plugin) project, will 
enable push email for iOS devices that talk to your Dovecot 2.x IMAP server. This is specially useful for people who 
are migrating away from running email services on OS X Server and want to keep the Push Email ability.

> Please note that it is not possible to use this project without legally owning a copy of OS X Server. You can purchase 
> OS X Server on the [Mac App Store](https://itunes.apple.com/ca/app/os-x-server/id714547929?mt=12) or download it for 
> free if you are a registered Mac or iOS developer.

What is the advantage of push?
------------------------------

Without Push, your iPhone will Fetch email periodically. This means that mail is delayed and that your device will use 
precious power to connect to a remote IMAP server.

Using native Push messages means that your phone will receive new email notifications over a highly optimized connection 
to iCloud that it already has for other purposes.

High Level Overview
-------------------

There are two parts to enabling iOS Push Email. You will need both parts for this to work.

First you need to install the Dovecot plugins from the [dovecot-xaps-plugin](https://github.com/freswa/dovecot-xaps-plugin) 
project. How do to that is documented in the README file in that project. The Dovecot plugin adds support for the `XAPPLEPUSHSERVICE` 
IMAP extension that will let iOS devices register themselves to receive native push notifications for new email arrival.

(Apple did not document this feature, but it did publish the source code for all their Dovecot patches on the 
[Apple Open Source project site](http://www.opensource.apple.com/source/dovecot/dovecot-293/), which include this feature. 
Although I was not able to follow a specification, I was able to read their open source project and do a clean implementation 
with all original code.)

Second, you need to install a daemon process (contained in this project) that will be responsible for receiving new email 
notifications from the Dovecot Local Delivery Agent and transforming those into native Apple Push Notifications.

Installation
============

Prerequisites
-------------

You are going to need the following things to get this going:

* Some patience and willingness to experiment - Although I run this project in production, it may contain bugs.
* Apple ID you’ve purchased macOS Server with
* Dovecot > 2.2.19 (which introduced the push-notification plugin)
* Go version 1.19.7 (see [issue #24](https://github.com/freswa/dovecot-xaps-daemon/issues/24))

Compiling and Installing the Daemon
-----------------------------------

The daemon is written in Go. The easiest way to build it is with go itself.

```
git clone https://github.com/freswa/dovecot-xaps-daemon.git
cd dovecot-xaps-daemon
wget https://go.dev/dl/go1.22.1.linux-amd64.tar.gz
tar zxvf go1.22.1.linux-amd64.tar.gz
go/bin/go build ./cmd/xapsd/xapsd.go
```

Running the Daemon
------------------

We assume that the daemon is installed in `/usr/bin/xapsd`.

* Create a system user `xapsd` in group `xapsd`.
* Create `/var/lib/xapsd` owned by user `xapsd`, group `xapsd`.
* Use the systemd file from `configs/systemd/xapsd.service` to run the daemon.
  On Debian-like distributions, place it in `/etc/systemd/system`.
* The config file from `configs/xapsd/xapsd.yaml` has to go into the directory `/etc/xapsd`.
  Change config to fit your needs.
  Especially fill in the details of the Apple ID. 
  The parameter `appleId` must be set to the login email address of the account.
  Please do _NOT_ fill in your password into `appleIdHashedPassword`, but instead run
  `xapsd -pass`. Then copy the printed hash to the config file.
* Start the xapsd service using `systemctl start xapsd`, and restart dovecot.
* Watch the system logs for errors.
* If everything is working, enable the xapsd service to start automatically on reboot (`systemctl enable xapsd`).

You don't have to care about certificate generation and renewal, as this is handled by the daemon.

On first run, the system log should contain information similar to the following:

```
xapsd[33391]: time="2023-04-29T12:11:02-05:00" level=info msg="Certificate valid until 2024-04-28 17:01:00 +0000 UTC"
```


Setting up Devices
------------------

Your iOS devices will discover that the server supports Push automatically the first time they connect. 
To force them to reconnect you can reboot the iOS device or turn Airport Mode on and off with a little delay in between.

If you go to your Email settings, you should see that the account has switched to Push.

The mail log will contain information such as

```
dovecot[4931]: imap(user)<276831><rbKKoY/700MKMgo3>: Debug: Sending registration: {"ApsAccountId":"...","ApsDeviceToken":"...","ApsSubtopic":"com.apple.mobilemail","Username":"user","Mailboxes": ["Open Orders","INBOX","Sent Messages"]}
dovecot[4931]: imap(user)<276831><rbKKoY/700MKMgo3>: Debug: Notification sent successfully: 200 OK
```

## Troubleshooting

* `Error: net_connect_unix(/run/dovecot/xapsd.sock) failed: Connection refused`
  Ensure the [dovecot-xaps-plugin](https://github.com/freswa/dovecot-xaps-plugin) is installed correctly.
  This version of the xapsd daemon does not work with older versions of the plugin, or plugins from other repositories.
* Multiple devices with same user name, same account, and only a difference in device token – only one device will get notifications
  This can happen when an iOS device is “cloned” (such as old iPhone to new iPhone).
  You must delete and re-create the mail account on one device.
  Watch the contents of `/var/lib/xapsd/database.json ` to see which devices are registered and will receive notifications.
  The `xapsd` service may require a restart to flush out an unwanted device.
* `Post "https://identity.apple.com/pushcert/caservice/new": net/http: HTTP/1.x transport connection broken: malformed MIME header line: 1;: mode=block`
  This can happen when go 1.20 is used to build the daemon.
  This error can cause the daemon to keep registering with Apple, creating lots of new certificates.

Privacy
-------

Each time a message is received, dovecot-xaps-daemon sends Apple a TLS-secured HTTP/2 request, which Apple uses to 
send a notification over a persistent connection maintained to between the user's device and Apple's push notification 
servers.

The request contains the following information: a device token (used by Apple to identify which device should be sent 
a push notification), an account ID (used by the user's device to identify which account it should poll for new messages), 
and a certificate topic. The certificate topic identifies the server to Apple and is hardcoded in the certificate issued 
by Apple and setup in the configuration for dovecot-xaps-daemon. `device token` and `account ID` are terms special to
the native Mail.app of iOS and not available by any other app.

By virtue of having made the request, Apple also learns the IP address of the server sending the push notification, and 
the time at which the push notification is sent by the server to Apple.

While no information typically thought of as private is directly exposed to Apple, some difficult to avoid leaks still occur. 
For example, Apple could correlate that two or more users frequently receive a push notification at almost the exact same time. 
From this, Apple could potentially infer that these users are receiving the same message. For most users this may not be a significant new loss of privacy.
