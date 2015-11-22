#
# Copyright (C) 2011-2012 Entware, 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# It can be done with simple shell script, not sure it can be handy

include $(TOPDIR)/rules.mk

PKG_NAME:=logtrigger
PKG_VERSION:=1.04
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://logtrigger.googlecode.com/files/
PKG_MD5SUM:=e224c96a0e6c5d29af1ab3b2440ad15b

include $(INCLUDE_DIR)/package.mk

define Package/logtrigger
	SECTION:=utils
	CATEGORY:=Utilities
#	DEPENDS:=+libncursesw
	TITLE:=log monitoring tool
	URL:=https://code.google.com/p/logtrigger/
	MAINTAINER:=Entware team, wl500g-repo.googlecode.com
endef

define Package/logtrigger/description
 The logtrigger helps you to monitor syslog and run some script for all
 or specific log events.
endef

define Package/logtrigger/conffiles
/opt/etc/logtrigger/logtrigger.conf
endef

define Package/logtrigger/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/logtrigger $(1)/opt/bin
	$(INSTALL_DIR) $(1)/opt/etc/init.d
	$(INSTALL_BIN) ./files/S04logtrigger $(1)/opt/etc/init.d
	$(INSTALL_DIR) $(1)/opt/etc/logtrigger
endef

$(eval $(call BuildPackage,logtrigger))
