#
# Copyright (C) 2011-2019 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# I don't know how to make it work, I suspect it's was just misconfigured by me

include $(TOPDIR)/rules.mk

PKG_NAME:=upnpproxy
PKG_VERSION:=0.3
PKG_REV:=8fc373f26e8d261bef4f9ebea9c51f082aeb3987
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/Efreak/upnpproxy.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

PKG_INSTALL:=1
PKG_FIXUP:=autoreconf

include $(INCLUDE_DIR)/package.mk

define Package/upnpproxy
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=Web Servers/Proxies
	DEPENDS:=+libuuid
	TITLE:=An UPnP proxy
	URL:=http://www.nongnu.org/upnpproxy/
	MAINTAINER:=Entware team, https://entware.net
endef

define Package/upnpproxy/description
 Start on daemon on each network, connect them together and suddenly
 all the UPnP services available on network A will be visible on
 network B and vice versa. All communication between clients on
 network A to UPnP services on network B will go through the daemon process.
endef

define Package/upnpproxy/conffiles
/opt/etc/upnpproxy.conf
endef

define Package/upnpproxy/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/* $(1)/opt/bin
	$(INSTALL_DIR) $(1)/opt/etc/init.d
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/doc/upnpproxy.conf $(1)/opt/etc
#	$(INSTALL_BIN) files/S91upnpproxy $(1)/opt/etc/init.d
endef

$(eval $(call BuildPackage,upnpproxy))
